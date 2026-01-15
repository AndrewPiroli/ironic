//! Backend for handling PowerPC HLE.
//!
//! NOTE: The socket is blocking right now, but I guess ultimately we don't
//! want that. 

use ironic_core::bus::*;
use ironic_core::dev::hlwd::irq::*;
use crate::back::*;

use log::{info, error};
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
    Shutdown,
    PPCRead8,
    PPCRead16,
    PPCRead32,
    PPCWrite8,
    PPCWrite16,
    PPCWrite32,
    Unimpl
}
impl Command {
    fn from_u32(x: u32) -> Self {
        match x {
            1  => Self::HostRead,
            2  => Self::HostWrite,
            3  => Self::Message,
            4  => Self::Ack,
            5  => Self::MessageNoReturn,
            6  => Self::PPCRead8,
            7  => Self::PPCRead16,
            8  => Self::PPCRead32,
            9  => Self::PPCWrite8,
            10 => Self::PPCWrite16,
            11 => Self::PPCWrite32,
            255 => Self::Shutdown,
            _  => Self::Unimpl,
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
    socket_errors: u8
}
impl PpcBackend {
    pub fn new(bus: Arc<RwLock<Bus>>) -> Self {
        PpcBackend {
            bus,
            ibuf: [0; BUF_LEN],
            obuf: [0; BUF_LEN],
            socket_errors: 0,
        }
    }

    fn recv(&mut self, client: &mut UnixStream) -> Option<usize> {
        let res = client.read(&mut self.ibuf);
        match res {
            Ok(len) => if len == 0 { None } else { Some(len) },
            Err(_) => None
        }
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

            loop {
                let res = self.wait_for_request(&mut client);
                if let Some(req) = res {
                    match req.cmd {
                        Command::Ack => self.handle_ack(req)?,
                        Command::HostRead => self.handle_read(&mut client, req)?,
                        Command::PPCRead8 => self.handle_read8(&mut client, req)?,
                        Command::PPCRead16 => self.handle_read16(&mut client, req)?,
                        Command::PPCRead32 => self.handle_read32(&mut client, req)?,
                        Command::HostWrite => self.handle_write(&mut client, req)?,
                        Command::PPCWrite8 => self.handle_write8(&mut client, req)?,
                        Command::PPCWrite16 => self.handle_write16(&mut client, req)?,
                        Command::PPCWrite32 => self.handle_write32(&mut client, req)?,
                        Command::Message => {
                            self.handle_message(&mut client, req)?;
                            let armmsg = self.wait_for_resp();
                            let _ = client.write(&u32::to_le_bytes(armmsg))?; // maybe FIXME: is it ok to ignore the # of bytes written here?
                        },
                        Command::MessageNoReturn => {
                            self.handle_message(&mut client, req)?;
                        },
                        Command::Shutdown => {
                            let _ = client.write(b"kk")?;
                            break;
                        }
                        Command::Unimpl => break,
                    }
                }
            }
            client.shutdown(Shutdown::Both)?;
        Ok(())
    }

    /// Block until we get a response from ARM-world.
    fn wait_for_resp(&mut self) -> u32 {
        info!(target: "PPC", "waiting for response ...");
        loop {
            if self.bus.read().hlwd.irq.ppc_irq_output {
                info!(target: "PPC", "got irq");
                let mut bus = self.bus.write();

                if bus.hlwd.ipc.state.ppc_ack {
                    info!(target: "PPC", "got extra ACK");
                    bus.hlwd.ipc.state.ppc_ack = false;
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    continue
                }

                if bus.hlwd.ipc.state.ppc_req {
                    let armmsg = bus.hlwd.ipc.arm_msg;
                    info!(target: "PPC", "Got message from ARM {armmsg:08x}");
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
        info!(target: "PPC", "waiting for ACK ...");
        loop {
            if self.bus.read().hlwd.irq.ppc_irq_output {
                info!(target: "PPC", "got irq");
                let mut bus = self.bus.write();

                if bus.hlwd.ipc.state.ppc_ack {
                    bus.hlwd.ipc.state.ppc_ack = false;
                    info!(target: "PPC", "got ACK");
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    break;
                }
                if bus.hlwd.ipc.state.ppc_req {
                    let armmsg = bus.hlwd.ipc.arm_msg;
                    info!(target: "PPC", "Got extra message from ARM {armmsg:08x}");
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

    /// Block until we receive some command message from a client.
    fn wait_for_request(&mut self, client: &mut UnixStream) -> Option<SocketReq> {
        let mut long_block = 0u8;
        loop {
            let try_recv = self.recv(client); // maybe FIXME: allow discarding recv length here?
            // As we wait longer, increase the time we sleep
            if try_recv.is_none() {
                long_block = long_block.saturating_add(1);
                std::thread::sleep(std::time::Duration::from_millis(5 * long_block as u64));
            }
            else {
                break;
            }
        }
        let req = SocketReq::from_buf(
            &self.ibuf[0..0xc].try_into().unwrap()
        );
        if req.len as usize > BUF_LEN - 0xc {
            error!(target: "PPC", "Socket message exceeds BUF_LEN {BUF_LEN:x}");
            panic!("Socket message exceeds BUF_LEN {BUF_LEN:x}");
        }
        Some(req)
    }

    /// Read from physical memory.
    pub fn handle_read(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        info!(target: "PPC", "read {:x} bytes at {:08x}", req.len, req.addr);
        self.bus.read().dma_read(req.addr,
            &mut self.obuf[0..req.len as usize])?;
        let _ = client.write(&self.obuf[0..req.len as usize])?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }


    /// Read from physical memory.
    pub fn handle_read8(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        // vvv   these logs produce massive spam for PPC LLE, so they're commented out for now
        //info!(target: "PPC", "read8 at {:08x}", req.addr);
        self.obuf[0] = self.bus.read().read8(req.addr)?;
        let _ = client.write(&self.obuf[0..1])?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Read from physical memory.
    pub fn handle_read16(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        //info!(target: "PPC", "read16 at {:08x}", req.addr);
        let tmpval = self.bus.read().read16(req.addr)?;
        self.obuf[0] = ((tmpval & 0xff00) >> 8) as u8;
        self.obuf[1] = (tmpval & 0x00ff) as u8;
        let _ = client.write(&self.obuf[0..2])?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Read from physical memory.
    pub fn handle_read32(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let tmpval = self.bus.read().read32(req.addr)?;
        //info!(target: "PPC", "read32 at {:08x}, val={:08x}", req.addr, tmpval);
        self.obuf[0] = ((tmpval & 0xff000000) >> 24) as u8;
        self.obuf[1] = ((tmpval & 0x00ff0000) >> 16) as u8;
        self.obuf[2] = ((tmpval & 0x0000ff00) >> 8) as u8;
        self.obuf[3] = (tmpval & 0x000000ff) as u8;
        let _ = client.write(&self.obuf[0..4])?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        info!(target: "PPC", "write {:x} bytes at {:08x}", req.len, req.addr);
        let data = &self.ibuf[0xc..(0xc + req.len as usize)];
        self.bus.write().dma_write(req.addr, data)?;
        let _ = client.write("OK".as_bytes())?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write8(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        //info!(target: "PPC", "write8 at {:08x} with {:08x}", req.addr, req.len);
        let _ = self.bus.write().write8(req.addr, self.ibuf[0xc])?;
        let _ = client.write("OK".as_bytes())?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write16(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        //info!(target: "PPC", "write16 at {:08x} with {:08x}", req.addr, req.len);
        let val = u16::from_le_bytes(self.ibuf[0xc..0xe].try_into().unwrap());
        let _ = self.bus.write().write16(req.addr, val)?;
        let _ = client.write("OK".as_bytes())?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Write to physical memory.
    pub fn handle_write32(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        //info!(target: "PPC", "write32 at {:08x} with {:08x}", req.addr, req.len);
        let val = u32::from_le_bytes(self.ibuf[0xc..0x10].try_into().unwrap());
        let _ = self.bus.write().write32(req.addr, val)?;
        let _ = client.write("OK".as_bytes())?; // maybe FIXME: is it ok to ignore the # of bytes written here?
        Ok(())
    }

    /// Tell ARM-world that an IPC request is ready at the location indicated
    /// by the pointer in PPC_MSG.
    pub fn handle_message(&mut self, client: &mut UnixStream, req: SocketReq) -> anyhow::Result<()> {
        let mut bus = self.bus.write();
        bus.hlwd.ipc.ppc_msg = req.addr;
        bus.hlwd.ipc.state.arm_req = true;
        bus.hlwd.ipc.state.arm_ack = true;
        let _ = client.write("OK".as_bytes())?; // maybe FIXME: is it ok to ignore the # of bytes written here?
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
                self.server_loop(sock.unwrap())?;
            }
        }
    }
}

