use log::{debug, error, info, trace, warn};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::Mutex;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use super::EXITransferRequest;
use super::super::EXITransfer;

// same port used by Dolphin's USB Gecko emulation +1
pub const USBGECKO_DEFAULT_PORT: u16 = 55021;
const TX_FIFO_CAP: usize = 0x10000;
const RX_FIFO_CAP: usize = 0x1000;

#[derive(Debug, Default)]
pub(crate) struct UsbGeckoBridge {
    /// Guest-to-host FIFO
    tx: Mutex<VecDeque<u8>>,
    /// Host-to-guest FIFO
    rx: Mutex<VecDeque<u8>>,
    /// client connected
    connected: AtomicBool,
}

// Mostly implementing what can be gathered about the protocol from libogc
// `gc/usbgecko.c` and the Linux driver:
// https://github.com/torvalds/linux/blob/master/arch/powerpc/platforms/embedded6xx/usbgecko_udbg.c
// ... there isn't much in terms of docs for it, sadly.
#[derive(Debug, Clone, Default)]
pub struct UsbGeckoDevice {
    bridge: Arc<UsbGeckoBridge>,
}

impl UsbGeckoDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "UG", "USB Gecko transfer: {req:?}");
        if req.kind != EXITransfer::ReadWrite {
            warn!(target: "UG", "USB Gecko only does rw transfers");
            return Ok(0x0000_0000)
        }

        let cmd = (req.data & 0xf000_0000) >> 28;
        match cmd {
            // ID see: libogc `gecko_isalive`
            0x9 => Ok(0x0470_0000),
            // Read a byte (host-to-guest). Bit 27 == success, with the
            // received byte in bits 23:16 see: libogc `gecko_recvbyte`
            0xa => {
                let byte = self.bridge.rx.lock().pop_front();
                match byte {
                    Some(b) => Ok(0x0800_0000 | ((b as u32) << 16)),
                    None => Ok(0x0000_0000),
                }
            },
            // Write a byte (guest-to-host), from bits 27:20. Bit 26 flags
            // that the byte was accepted see: libogc `gecko_sendbyte`
            0xb => {
                let b = ((req.data & 0x0ff0_0000) >> 20) as u8;
                if self.bridge.connected.load(Ordering::Relaxed) {
                    let mut tx = self.bridge.tx.lock();
                    if tx.len() < TX_FIFO_CAP {
                        tx.push_back(b);
                    } else { // warning?
                        debug!(target: "UG", "TX FIFO full, dropping byte {b:02x}");
                    }
                } else {
                    // do not stall guest if there's no one listening
                    trace!(target: "UG", "no client, dropping byte {b:02x}");
                }
                Ok(0x0400_0000)
            },
            // Check if TX FIFO is ready (it always is here)
            0xc => Ok(0x0400_0000), 
            // Check if RX FIFO is ready: bit 26 set when data is available
            0xd => Ok((!self.bridge.rx.lock().is_empty() as u32) << 26),
            _ => {
                warn!(target: "UG", "Unrecognized USB Gecko command: {cmd:x}");
                Ok(0x0000_0000)
            }
        }
    }

    // serve this gecko's serial stream on TCP socket bound to `127.0.0.1:port`.
    // One client at a time pls
    // todo: move this out of core?
    pub fn spawn_server_thread(&self, port: u16) -> anyhow::Result<JoinHandle<()>> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        self.spawn_server_thread_on(listener)
    }

    // Spawn the host-side I/O thread on an already-bound listener.
    // see above
    pub fn spawn_server_thread_on(&self, listener: TcpListener) -> anyhow::Result<JoinHandle<()>> {
        info!(target: "UG", "USB Gecko server listening on {}", listener.local_addr()?);
        let bridge = self.bridge.clone();
        let handle = std::thread::Builder::new()
            .name("GeckoThread".to_owned())
            .spawn(move || Self::server_loop(bridge, listener))?;
        Ok(handle)
    }

    fn server_loop(bridge: Arc<UsbGeckoBridge>, listener: TcpListener) {
        loop {
            let (stream, peer) = match listener.accept() {
                Ok(x) => x,
                Err(e) => {
                    // todo relaunch like ppc server
                    error!(target: "UG", "accept() failed: {e}; USB Gecko server exiting");
                    return;
                },
            };
            info!(target: "UG", "client connected from {peer}");
            bridge.connected.store(true, Ordering::Relaxed);
            if let Err(e) = Self::handle_client(&bridge, stream) {
                debug!(target: "UG", "client i/o error: {e}");
            }
            bridge.connected.store(false, Ordering::Relaxed);
            info!(target: "UG", "client disconnected");
        }
    }

    fn handle_client(bridge: &UsbGeckoBridge, mut stream: TcpStream) -> anyhow::Result<()> {
        stream.set_read_timeout(Some(Duration::from_millis(5)))?;
        stream.set_nodelay(true)?;
        let mut buf = [0u8; 0x1000];
        loop {
            // TX first
            let pending: Vec<u8> = { // FIXME: don't alloc here every time
                let mut tx = bridge.tx.lock();
                tx.drain(..).collect()
            };
            if !pending.is_empty() {
                stream.write_all(&pending)?;
            }

            let space = RX_FIFO_CAP.saturating_sub(bridge.rx.lock().len());
            if space == 0 {
                // shouldn't really happen that much but FIXME don't sleep in IO threads
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            let max = space.min(buf.len());
            match stream.read(&mut buf[..max]) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    let mut rx = bridge.rx.lock();
                    rx.extend(&buf[..n]);
                },
                Err(e) if matches!(e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {},
                Err(e) => return Err(e.into()),
            }
        }
    }
}
