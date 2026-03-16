//! Backend for handling PowerPC HLE.
//!
//! NOTE: The socket is blocking right now, but I guess ultimately we don't
//! want that. 

use ironic_core::bus::*;
use ironic_core::dev::hlwd::irq::*;
use crate::back::*;

use log::{info, error, debug};
use parking_lot::RwLock;
use std::env::temp_dir;
use std::path::PathBuf;
use std::thread;
use std::sync::Arc;
use std::net::Shutdown;
use std::io::{Read, Write};


#[cfg(target_family = "unix")]
use std::os::unix::net::{UnixStream, UnixListener};
use std::time::Duration;
#[cfg(target_family = "windows")]
use uds_windows::{UnixStream, UnixListener};

/// A type of command sent over the socket.
#[derive(Debug)]
#[repr(u32)]
pub enum Command { 
    HostWrite, 
    HostRead, 
    Message, 
    Ack, 
    MessageNoReturn,
    PPCRead8,
    PPCRead16,
    PPCRead32,
    PPCWrite8,
    PPCWrite16,
    PPCWrite32,
    EnableFlipperIrqForwarding,
    /// Sent server->client when a Flipper IRQ fires.
    FlipperIrq,
    PatchRange,
    DisableProtections,
    Shutdown,
    Unimpl,
}
impl Command {
    fn from_u32(x: u32) -> Self {
        match x {
            1 => Self::HostRead,
            2 => Self::HostWrite,
            3 => Self::Message,
            4 => Self::Ack,
            5 => Self::MessageNoReturn,
            6 => Self::PPCRead8,
            7 => Self::PPCRead16,
            8 => Self::PPCRead32,
            9 => Self::PPCWrite8,
            10 => Self::PPCWrite16,
            11 => Self::PPCWrite32,
            12 => Self::EnableFlipperIrqForwarding,
            13 => Self::FlipperIrq,
            14 => Self::PatchRange,
            15 => Self::DisableProtections,
            255 => Self::Shutdown,
            _ => Self::Unimpl,
        }
    }
}

/// A request packet from the socket.
#[repr(C)]
pub struct SocketReq {
    pub cmd: Command,
    pub addr: u32,
    pub len: u32,
}
impl SocketReq {
    pub fn from_buf(s: &[u8; 0xc]) -> Self {
        let cmd = Command::from_u32(
            u32::from_le_bytes(s[0..4].try_into().unwrap())
        );
        let addr = u32::from_le_bytes(s[0x4..0x8].try_into().unwrap());
        let len = u32::from_le_bytes(s[0x8..0xc].try_into().unwrap());
        SocketReq { cmd, addr, len }
    }
}

#[derive(Debug)]
pub struct PatchRange<'a> {
    start: u32,
    end: u32,
    old: &'a [u8],
    new: &'a [u8],
    offset: u32,
}

impl<'a> From<&'a [u8]> for PatchRange<'a> {
    fn from(value: &'a [u8]) -> Self {
        fn copy_u32(from: &[u8]) -> u32 {
            u32::from_be_bytes(from[..4].try_into().unwrap())
        }
        // memory layout
        // 00 start u32
        // 04 end u32 
        // 08 old len u32
        // 0c new len u32
        // 10 offset u32
        // old...
        // new...
        let start = copy_u32(&value[0..4]);
        let end = copy_u32(&value[4..8]);
        let old_len = copy_u32(&value[8..0xc]);
        let new_len = copy_u32(&value[0xc..0x10]);
        let offset = copy_u32(&value[0x10..0x14]);

        let old_start_idx = 0x14usize;
        let old_end_idx = old_start_idx + old_len as usize;
        let new_start_idx = old_end_idx;
        let new_end_idx = new_start_idx + new_len as usize;
        Self {
            start,
            end,
            old: &value[old_start_idx..old_end_idx],
            new: &value[new_start_idx..new_end_idx],
            offset ,
        }
    }
}

pub const IPC_SOCK: &str = "ironic-ppc.sock";
pub const BUF_LEN: usize = 0x10000;

pub struct PpcBackend {
    /// Reference to the system bus.
    pub bus: Arc<RwLock<Bus>>,
    /// Input buffer for the socket.
    pub ibuf: [u8; BUF_LEN],
    /// Output buffer for the socket.
    pub obuf: [u8; BUF_LEN],
    /// Counter to prevent infinite retry on the socket
    socket_errors: u8,
    /// Should we be appending an IRQ status byte to every response?
    forward_irqs: bool
}
impl PpcBackend {
    pub fn new(bus: Arc<RwLock<Bus>>) -> Self {
        PpcBackend {
            bus,
            ibuf: [0; BUF_LEN],
            obuf: [0; BUF_LEN],
            socket_errors: 0,
            forward_irqs: false
        }
    }

    fn recv(client: &mut UnixStream, buf: &mut [u8]) -> anyhow::Result<bool> {
        let mut offset = 0usize;
        while offset < buf.len() {
            match client.read(&mut buf[offset..])? {
                0 if offset == 0 => {
                    return Ok(false);
                },
                0 => anyhow::bail!("Socket closed mid-frame: expected {} bytes, got {offset}", buf.len()),
                n => offset += n,
            }
        }
        Ok(true)
    }
}


impl PpcBackend {

    fn resolve_socket_path() -> PathBuf {
        if cfg!(target_os = "macos") {
            return PathBuf::from(format!("/tmp/{IPC_SOCK}"));
        }
        let mut dir = temp_dir();
        dir.push(IPC_SOCK);
        dir
    }

    /// Handle clients connected to the socket.
    pub fn server_loop(&mut self, sock: UnixListener) -> anyhow::Result<()> {
            let res = sock.accept();
            let mut client = match res {
                Ok((stream, _)) => stream,
                Err(e) => {
                    if self.socket_errors > 10 {
                        info!(target:"PPC", "accept() error {e:?}");
                        return Err(anyhow::anyhow!(e));
                    }
                    else {
                        self.socket_errors += 1;
                        std::thread::sleep(Duration::from_millis(50));
                        return Ok(());
                    }
                }
            };
            self.socket_errors = 0;

            while let Some(req) = self.wait_for_request(&mut client)? {
                // Remember whether forwarding was already on before this
                // command, so the EnableFlipperIrqForwarding response
                // itself doesn't get the extra byte.
                let was_forwarding = self.forward_irqs;

                match req.cmd {
                    Command::Ack => self.handle_ack(req)?,
                    Command::HostRead => self.handle_read(&mut client, req)?,
                    Command::HostWrite => self.handle_write(&mut client, req)?,
                    Command::Message => {
                        self.handle_message(&mut client, req)?;
                        let armmsg = self.wait_for_resp();
                        client.write_all(&u32::to_le_bytes(armmsg))?;
                    },
                    Command::MessageNoReturn => {
                        self.handle_message(&mut client, req)?;
                    },
                    Command::PPCRead8 => self.handle_read8(&mut client, req)?,
                    Command::PPCRead16 => self.handle_read16(&mut client, req)?,
                    Command::PPCRead32 => self.handle_read32(&mut client, req)?,
                    Command::PPCWrite8 => self.handle_write8(&mut client, req)?,
                    Command::PPCWrite16 => self.handle_write16(&mut client, req)?,
                    Command::PPCWrite32 => self.handle_write32(&mut client, req)?,
                    Command::PatchRange => {
                        self.handle_patch_range(&mut client, req)?;
                    },
                    Command::DisableProtections => {
                        let mut bus = self.bus.write();
                        bus.hlwd.busctrl.ahbprot = 0xFFFFFFFF;
                        bus.hlwd.busctrl.srnprot &= 0x1F;
                        log::info!(target: "RTPATCH", "AHBPROT and SRNPROT protections disabled");
                        client.write_all(b"OK")?;
                    }
                    Command::Shutdown => {
                        client.write_all(b"kk")?;
                        break;
                    }
                    Command::EnableFlipperIrqForwarding => {
                        client.write_all("OK".as_bytes())?;
                        self.forward_irqs = true;
                    }
                    Command::FlipperIrq => break, // server->client only
                    Command::Unimpl => {
                        error!(target: "PPC", "recieved unimplemented command");
                        break;
                    },
                }
                // Piggyback the IRQ status on every response so the
                // client never needs to poll/peek (zero extra syscalls).
                if was_forwarding {
                    self.append_irq_flag(&mut client)?;
                }
                debug!(target:"PPC", "waiting for command");
            }
            client.shutdown(Shutdown::Both)?;
        Ok(())
    }

    /// Block until we get a response from ARM-world.
    fn wait_for_resp(&mut self) -> u32 {
        debug!(target: "PPC", "waiting for response ...");
        loop {
            if self.bus.read().hlwd.irq.ppc_irq_output {
                debug!(target: "PPC", "got irq");
                let mut bus = self.bus.write();

                if bus.hlwd.ipc.state.ppc_ack {
                    debug!(target: "PPC", "got extra ACK");
                    bus.hlwd.ipc.state.ppc_ack = false;
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    continue
                }

                if bus.hlwd.ipc.state.ppc_req {
                    let armmsg = bus.hlwd.ipc.arm_msg;
                    debug!(target: "PPC", "Got message from ARM {armmsg:08x}");
                    bus.hlwd.ipc.state.ppc_req = false;
                    bus.hlwd.ipc.state.arm_ack = true;
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    return armmsg;
                }

                drop(bus); // Release RwLock
                error!(target: "PPC", "Invalid IRQ state");
                unreachable!("Invalid IRQ state. You forgot to update your IRQ lines somewhere!");
            } else {
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    /// Block until we get an ACK from ARM-world.
    fn wait_for_ack(&mut self) {
        debug!(target: "PPC", "waiting for ACK ...");
        loop {
            if self.bus.read().hlwd.irq.ppc_irq_output {
                debug!(target: "PPC", "got irq");
                let mut bus = self.bus.write();

                if bus.hlwd.ipc.state.ppc_ack {
                    bus.hlwd.ipc.state.ppc_ack = false;
                    debug!(target: "PPC", "got ACK");
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    break;
                }
                if bus.hlwd.ipc.state.ppc_req {
                    let armmsg = bus.hlwd.ipc.arm_msg;
                    debug!(target: "PPC", "Got extra message from ARM {armmsg:08x}");
                    bus.hlwd.ipc.state.ppc_req = false;
                    bus.hlwd.ipc.state.arm_ack = true;
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    continue;
                }

                drop(bus); // Release RwLock
                error!(target: "PPC", "Invalid IRQ state");
                unreachable!("Invalid IRQ state. You forgot to update your IRQ lines somewhere!")
            } else {
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    /// Append a 1-byte IRQ latch flag after the response.
    /// The client reads this extra byte as part of the same recv.
    /// Clears the latch so each assertion only produces one notification.
    fn append_irq_flag(&self, client: &mut UnixStream) -> anyhow::Result<()> {
        let mut bus = self.bus.write();
        let flag: u8 = if bus.hlwd.pi.irq_latch { 1 } else { 0 };
        bus.hlwd.pi.irq_latch = false;
        drop(bus);
        client.write_all(&[flag])?;
        Ok(())
    }

    /// Block until we receive some command message from a client.
    fn wait_for_request(&mut self, client: &mut UnixStream) -> anyhow::Result<Option<SocketReq>> {
        if !Self::recv(client, &mut self.ibuf[..0xc])? {
            return Ok(None);
        }

        let req = SocketReq::from_buf(&self.ibuf[..0xc].try_into().unwrap());
        if req.len as usize > BUF_LEN - 0xc {
            error!(target: "PPC", "Socket message exceeds BUF_LEN {BUF_LEN:x}");
            anyhow::bail!("Socket message exceeds BUF_LEN {BUF_LEN:x}");
        }

        let payload_len = match req.cmd {
            // HostWrite carries `len` bytes inline after the header.
            Command::HostWrite => req.len as usize,
            // Raw PPC writes also carry the value inline after the header.
            Command::PPCWrite8 => 1,
            Command::PPCWrite16 => 2,
            Command::PPCWrite32 => 4,
            _ => 0,
        };

        if payload_len > 0 {
            let payload_end = 0xc + payload_len;
            if !Self::recv(client, &mut self.ibuf[0xc..payload_end])? {
                anyhow::bail!("Socket closed while reading payload");
            }
        }

        Ok(Some(req))
    }

    /// Read from physical memory.
    pub fn handle_read(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        debug!(target: "PPC", "read {:x} bytes at {:08x}", req.len, req.addr);
        self.bus.read().dma_read(req.addr,
            &mut self.obuf[0..req.len as usize])?;
        client.write_all(&self.obuf[0..req.len as usize])?;
        Ok(())
    }


    /// Read from physical memory.
    pub fn handle_read8(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        debug!(target: "PPC", "read8 at {:08x}", req.addr);
        self.obuf[0] = self.bus.read().read8(req.addr)?;
        client.write_all(&self.obuf[0..1])?;
        Ok(())
    }

    /// Read from physical memory.
    pub fn handle_read16(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        debug!(target: "PPC", "read16 at {:08x}", req.addr);
        let tmpval = self.bus.read().read16(req.addr)?;
        self.obuf[0] = ((tmpval & 0xff00) >> 8) as u8;
        self.obuf[1] = (tmpval & 0x00ff) as u8;
        client.write_all(&self.obuf[0..2])?;
        Ok(())
    }

    /// Read from physical memory.
    pub fn handle_read32(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let tmpval = self.bus.read().read32(req.addr)?;
        debug!(target: "PPC", "read32 at {:08x}, val={:08x}", req.addr, tmpval);
        self.obuf[0] = ((tmpval & 0xff000000) >> 24) as u8;
        self.obuf[1] = ((tmpval & 0x00ff0000) >> 16) as u8;
        self.obuf[2] = ((tmpval & 0x0000ff00) >> 8) as u8;
        self.obuf[3] = (tmpval & 0x000000ff) as u8;
        client.write_all(&self.obuf[0..4])?;
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        debug!(target: "PPC", "write {:x} bytes at {:08x}", req.len, req.addr);
        let data = &self.ibuf[0xc..(0xc + req.len as usize)];
        self.bus.write().dma_write(req.addr, data)?;
        client.write_all(b"OK")?;
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write8(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        debug!(target: "PPC", "write8 at {:08x} with {:02x}", req.addr, self.ibuf[0xc]);
        let _ = self.bus.write().write8(req.addr, self.ibuf[0xc])?;
        client.write_all("OK".as_bytes())?;
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write16(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let val = u16::from_le_bytes(self.ibuf[0xc..0xe].try_into().unwrap());
        debug!(target: "PPC", "write16 at {:08x} with {:04x}", req.addr, val);
        let _ = self.bus.write().write16(req.addr, val)?;
        client.write_all("OK".as_bytes())?;
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write32(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let val = u32::from_le_bytes(self.ibuf[0xc..0x10].try_into().unwrap());
        debug!(target: "PPC", "write32 at {:08x} with {:08x}", req.addr, val);
        let _ = self.bus.write().write32(req.addr, val)?;
        client.write_all("OK".as_bytes())?;
        Ok(())
    }

    /// Tell ARM-world that an IPC request is ready at the location indicated
    /// by the pointer in PPC_MSG.
    pub fn handle_message(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let mut bus = self.bus.write();
        bus.hlwd.ipc.ppc_msg = req.addr;
        bus.hlwd.ipc.state.arm_req = true;
        bus.hlwd.ipc.state.arm_ack = true;
        client.write_all(b"OK")?;
        Ok(())
    }

    /// Search for a memory range and patch some bytes
    /// libruntimeiospatch inspired
    pub fn handle_patch_range(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        use log::{debug, info, error};
        use anyhow::bail;
        let mut bus = self.bus.write();
        let mut copy = vec![0u8; req.len as usize];
        if let Err(e) = bus.dma_read(req.addr, &mut copy) {
            error!(target: "RTPATCH", "Failed initial read of {:x} for runtime patch. {e:?}", req.addr);
            client.write_all(&[0,0])?;
            bail!(e);
        }
        use std::ops::Deref;
        let p = PatchRange::from(copy.deref()); // wtf ?
        debug!(target: "RTPATCH", "Decoded runtime patch {p:?}");
        let mut found = 0u16;

        let mut current = p.start;
        let mut buf = vec![0u8; p.old.len()];
        while current < (p.end - p.old.len() as u32) {
            if let Err(a) = bus.dma_read(current, &mut buf) {
                error!(target: "RTPATCH", "Failed to read memory at {current:x} {a:?}. Found: {found}");
                break;
            }
            if buf == p.old {
                if let Err(e) = bus.dma_write(current+p.offset, p.new) {
                    error!(target: "RTPATCH", "Failed during patch apply: {current:x}+{:x}. {e:?}", p.offset);
                    bail!(e);
                }
                found += 1;
            }
            current += 1;
        }
        info!(target: "RTPATCH", "Applied patch {} times", found);
        client.write_all(&found.to_le_bytes())?;
        Ok(())
    }

    pub fn handle_ack(&mut self, _req: SocketReq) -> anyhow::Result<()> {
        let mut bus = self.bus.write();
        let ppc_ctrl = bus.hlwd.ipc.read_handler(4)? & 0x3c;
        bus.hlwd.ipc.write_handler(4, ppc_ctrl | 0x8)?;
        Ok(())
    }

}


impl Backend for PpcBackend {
    fn run(&mut self) -> anyhow::Result<()> {
        info!(target: "PPC", "PPC backend thread started");
        self.bus.write().hlwd.ipc.state.ppc_ctrl_write(0x36);

        loop {
            if self.bus.read().hlwd.ppc_on {
                info!(target: "PPC", "Broadway came online");
                break;
            }
            thread::sleep(std::time::Duration::from_millis(500));
        }

        // Block until we get an IRQ with an ACK/MSG
        self.wait_for_ack();

        // Send an extra ACK
        self.bus.write().hlwd.ipc.state.arm_ack = true;
        thread::sleep(std::time::Duration::from_millis(100));

        loop {
            // Try binding to the socket
            let res = std::fs::remove_file(PpcBackend::resolve_socket_path());
            match res {
                Ok(_) => {},
                Err(_e) => {},
            }
            let res = UnixListener::bind(PpcBackend::resolve_socket_path());
            let sock = match res {
                Ok(sock) => Some(sock),
                Err(e) => {
                    error!(target: "PPC", "Couldn't bind to {},\n{e:?}", PpcBackend::resolve_socket_path().to_string_lossy());
                    None
                }
            };

            // If we successfully bind, run the server until it exits
            if sock.is_some() {
                info!(target: "PPC", "Socket bound, starting PPC server");
                match self.server_loop(sock.unwrap()) {
                    Ok(()) => info!(target: "PPC", "PPC server terminated gracefully. Restarting socket"),
                    Err(e) => error!(target: "PPC", "PPC server returned error: {e:?}"),
                }
            }
        }
    }
}
