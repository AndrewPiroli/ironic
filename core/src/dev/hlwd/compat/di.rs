use std::path::Path;

use log::{debug, warn};
use anyhow::bail;

use crate::bus::Bus;
use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;
use crate::dev::hlwd::compat::pi::FlipperIrq;
use crate::mem::BigEndianMemory;

const DVD_BLOCK_SIZE: u64 = 2048;

/// Wii disc magic word, located at byte offset 0x18 of a genuine disc image.
const WII_MAGIC: u32 = 0x5d1c_9ea3;
/// GameCube disc magic word, located at byte offset 0x1c of a genuine disc image.
const GCN_MAGIC: u32 = 0xc233_9f3d;

/// Device-Error Interrupt status (W1C).
const DISR_DEINT:             u32 = 0x0000_0004;
/// Device-Error Interrupt Mask.
const DISR_DEINTMASK:         u32 = 0x0000_0002;
/// Transfer-Complete Interrupt status (W1C).
const DISR_TCINT:             u32 = 0x0000_0010;
/// Transfer-Complete Interrupt Mask.
const DISR_TCINTMASK:         u32 = 0x0000_0008;

/// Drive commands sent over DI
const DI_CMD_INQUIRY:         u32 = 0x1200_0000;
const DI_CMD_READ_DISC_ID:    u32 = 0xa800_0040;
const DI_CMD_READ_NORMAL:     u32 = 0xa800_0000;
const DI_CMD_READ_DVDR:       u32 = 0xd000_0000;
const DI_CMD_READ_PHYSINFO:   u32 = 0xad00_0000;
const DI_CMD_GET_STATUS:      u32 = 0xe000_0000;
const DI_CMD_STOP_MOTOR:      u32 = 0xe300_0000;

/// Upper byte of a drive status word, represents the status
const DI_STATUS_OK:           u32 = 0x0 << 24;
const DI_STATUS_LID_OPEN:     u32 = 0x1 << 24;
/*
const DI_STATUS_DISC_CHANGED: u32 = 0x2 << 24;
const DI_STATUS_NO_DISC:      u32 = 0x3 << 24;
const DI_STATUS_MOTOR_OFF:    u32 = 0x4 << 24;
*/
const DI_STATUS_ID_NOT_READ:  u32 = 0x5 << 24;

/// Lower bytes of a drive status word, represents error states
const DI_ERROR_OK:                  u32 = 0x0000_0000;
const DI_ERROR_DISC_ID_NOT_READ:    u32 = 0x0002_0401;
/*
const DI_ERROR_MOTOR_STOPPED:       u32 = 0x0002_0400;
const DI_ERROR_COVER_OPENED:        u32 = 0x0002_3a00;
const DI_ERROR_SEEK_FAILED:         u32 = 0x0003_0200;
const DI_ERROR_UNRECOVERABLE_READ:  u32 = 0x0003_1100;
const DI_ERROR_PROTOCOL_ERROR:      u32 = 0x0004_0800;
const DI_ERROR_ILLEGAL_COMMAND:     u32 = 0x0005_2000;
const DI_ERROR_AUDIO_BUF_NOT_SET:   u32 = 0x0005_2001;
*/
const DI_ERROR_LBA_OUT_OF_RANGE:    u32 = 0x0005_2100;
/*
const DI_ERROR_ILLEGAL_CMD_FIELD:   u32 = 0x0005_2400;
const DI_ERROR_ILLEGAL_AUDIO_CMD:   u32 = 0x0005_2401;
const DI_ERROR_CONFIG_OUT_OF_PER:   u32 = 0x0005_2402;
*/
// TODO: find a real source for this; found this in CleanRip's driver but unnamed
const DI_ERROR_NORMAL_READ_ON_DVDR: u32 = 0x0005_3000;
/*
const DI_ERROR_END_OF_USER_AREA:    u32 = 0x0005_6300;
const DI_ERROR_MEDIA_CHANGED:       u32 = 0x0006_2800;
const DI_ERROR_MEDIUM_REMOVAL_REQ:  u32 = 0x000b_5a01;
*/

/// Legacy disc drive interface.
#[derive(Default, Debug)]
#[allow(dead_code)]
pub struct DriveInterface {
    disr: u32,
    dicvr: u32,
    dicmdbuf: [u32; 3],
    dimar: u32,
    dilength: u32,
    dicr: u32,
    diimmbuf: u32,
    dicfg: u32,

    /// Backing store for the emulated disc image, if one was provided.
    disc: Option<BigEndianMemory>,
    /// Whether `disc` looks like a genuine GameCube/Wii disc image, as opposed to
    /// some other data burned to a DVD-R.
    genuine: bool,
    /// Status/error word to report back on the next `DI_CMD_GET_STATUS`.
    last_error: u32,
}
impl DriveInterface {
    pub fn new(dvd: Option<&Path>) -> Self {
        let disc = dvd.and_then(|path| {
            let len = std::fs::metadata(path).ok()?.len() as usize;
            match BigEndianMemory::from_file(len, path, false) {
                Ok(mem) => Some(mem),
                Err(e) => {
                    warn!(target: "DI", "Failed to load {}: {e}", path.display());
                    None
                },
            }
        });

        let genuine = disc.as_ref().is_some_and(Self::looks_genuine);
        if let (Some(disc), Some(path)) = (&disc, dvd) {
            debug!(target: "DI", "Loaded {}: {} bytes, genuine={genuine}", path.display(), disc.data.len());
        } else {
            debug!(target: "DI", "No disc image given, emulating an empty drive");
        }

        Self { disc, genuine, ..Default::default() }
    }

    /// Genuine GameCube/Wii discs carry a magic word identifying their format at a
    /// fixed offset; anything else is treated as a plain DVD-R.
    fn looks_genuine(disc: &BigEndianMemory) -> bool {
        let wii = disc.read::<u32>(0x18).map(|v| v == WII_MAGIC).unwrap_or(false);
        let gcn = disc.read::<u32>(0x1c).map(|v| v == GCN_MAGIC).unwrap_or(false);
        wii || gcn
    }

    /// Read `len` bytes at `off` from the backing disc image, returning the
    /// resulting DMA payload, and updating `last_error` accordingly.
    fn read_disc(&mut self, off: u64, len: usize) -> Option<BusTask> {
        let Some(disc) = &self.disc else {
            self.last_error = DI_STATUS_OK | DI_ERROR_OK;
            return Some(BusTask::Di { error: true, dma: None });
        };

        if len == 0 {
            self.last_error = DI_STATUS_OK | DI_ERROR_OK;
            return Some(BusTask::Di { error: false, dma: Some(Vec::new()) });
        }

        let off = off as usize;
        if off.checked_add(len).is_none_or(|end| end > disc.data.len()) {
            warn!(target: "DI", "read past end of disc image: offset {off:x}, length {len:x}, disc size {:x}",
                disc.data.len());
            self.last_error = DI_STATUS_OK | DI_ERROR_LBA_OUT_OF_RANGE;
            return Some(BusTask::Di { error: true, dma: None });
        }

        let mut buf = vec![0u8; len];
        if disc.read_buf(off, &mut buf).is_err() {
            self.last_error = DI_STATUS_OK | DI_ERROR_LBA_OUT_OF_RANGE;
            return Some(BusTask::Di { error: true, dma: None });
        }

        self.last_error = DI_STATUS_OK | DI_ERROR_OK;
        Some(BusTask::Di { error: false, dma: Some(buf) })
    }

    /// Whether DI currently has an unmasked, unacknowledged interrupt
    /// condition pending. Polled on every bus step to drive PI's DI level,
    /// mirroring how VI and PE-finish IRQs are handled.
    pub fn irq_pending(&self) -> bool {
        (self.disr & DISR_DEINT != 0 && self.disr & DISR_DEINTMASK != 0)
            || (self.disr & DISR_TCINT != 0 && self.disr & DISR_TCINTMASK != 0)
    }

    fn do_cmd(&mut self) -> Option<BusTask> {
        let dma: bool = self.dicr & 0x0000_0002 == 0x0000_0002;
        let write: bool = self.dicr & 0x0000_0004 == 0x0000_0004;
        let cmd = self.dicmdbuf;
        let dimar = self.dimar & 0x03ffffe0; // FIXME: YAGCD says this is the DIMAR mask, but how
                                             // would MEM2 work then?  Must've been bumped up
                                             // somewhat for Hollywood, but by how far?

        if dma && write {
            debug!(target: "DI", "DMA command from {:x}, {}B, [ {:x}, {:x}, {:x} ]", dimar, self.dilength, cmd[0], cmd[1], cmd[2]);
        }
        else if dma {
            debug!(target: "DI", "DMA command to {:x}, {}B, [ {:x}, {:x}, {:x} ]", dimar, self.dilength, cmd[0], cmd[1], cmd[2]);
        }
        else {
            debug!(target: "DI", "Immediate command [ {:x}, {:x}, {:x} ]", cmd[0], cmd[1], cmd[2]);
        }

        match cmd[0] {
            // Identify the drive, most notable part of the response is the
            // drive date.
            DI_CMD_INQUIRY => {
                let mut resp = [0u8; 32];
                // Pretend to be a D2C/D2E, a pretty common revision
                resp[4..8].copy_from_slice(&0x2007_0213u32.to_be_bytes());
                let len = (self.dilength as usize).min(resp.len());
                Some(BusTask::Di { error: false, dma: Some(resp[..len].to_vec()) })
            },

            // Report the last error/status word, or "no disc inserted" if we
            // don't have a backing dvd.iso at all.
            DI_CMD_GET_STATUS => {
                self.diimmbuf = match &self.disc {
                    // FIXME: Wii drive seems to report LID_OPEN w/o a disc?
                    None => DI_STATUS_LID_OPEN | DI_ERROR_OK,
                    Some(_) => self.last_error,
                };
                Some(BusTask::Di { error: false, dma: None })
            },

            // Pretend that it succeeded
            DI_CMD_STOP_MOTOR => {
                Some(BusTask::Di { error: false, dma: None})
            },

            // Report the disc ID (the first bytes of the image), but only for
            // genuine media - a DVD-R never has a real disc ID to read.
            DI_CMD_READ_DISC_ID => {
                if self.genuine {
                    self.read_disc(0, self.dilength as usize)
                } else {
                    self.last_error = DI_STATUS_ID_NOT_READ | DI_ERROR_DISC_ID_NOT_READ;
                    Some(BusTask::Di { error: true, dma: None })
                }
            },

            // Standard reads only work on genuine media; a DVD-R must be read
            // with DI_CMD_READ_DVDR instead.
            DI_CMD_READ_NORMAL => {
                if self.genuine {
                    let off = (cmd[1] as u64) << 2;
                    self.read_disc(off, self.dilength as usize)
                } else {
                    self.last_error = DI_STATUS_OK | DI_ERROR_NORMAL_READ_ON_DVDR;
                    Some(BusTask::Di { error: true, dma: None })
                }
            },

            // DVD-R style reads work on any backing image, genuine or not.
            DI_CMD_READ_DVDR => {
                let off = (cmd[1] as u64) * DVD_BLOCK_SIZE;
                self.read_disc(off, self.dilength as usize)
            },

            // Report the extent of the "user data area" so a reader can figure
            // out the disc's size, based on the file's actual length.
            DI_CMD_READ_PHYSINFO => {
                if let Some(disc) = &self.disc {
                    let mut resp = [0u8; 2048];
                    let last_psn = ((disc.data.len() as u64 / DVD_BLOCK_SIZE).saturating_sub(1)) as u32;
                    resp[4..8].copy_from_slice(&0u32.to_be_bytes());
                    resp[8..12].copy_from_slice(&last_psn.to_be_bytes());
                    let len = (self.dilength as usize).min(resp.len());
                    self.last_error = DI_STATUS_OK | DI_ERROR_OK;
                    Some(BusTask::Di { error: false, dma: Some(resp[..len].to_vec()) })
                } else {
                    self.last_error = DI_STATUS_OK | DI_ERROR_OK;
                    Some(BusTask::Di { error: true, dma: None })
                }
            },

            // Anything else
            _ => {
                warn!(target: "DI", "unhandled command [ {:08x}, {:08x}, {:08x} ]", cmd[0], cmd[1], cmd[2]);
                Some(BusTask::Di { error: true, dma: None })
            },
        }
    }
}

impl Bus {
    pub fn handle_task_di(&mut self, error: bool, dma: Option<Vec<u8>>) -> anyhow::Result<()> {
        if let Some(data) = dma {
            let addr = self.hlwd.di.dimar & 0x03ffffe0; // FIXME: see DIMAR comment above
            self.dma_write(Requester::Soc, addr, &data)?;
            self.hlwd.di.dilength = 0; // fully transferred, no residual
        }

        let di = &mut self.hlwd.di;
        di.dicr &= !0x0000_0001; // TSTART self-clears on completion
        di.disr |= if error { DISR_DEINT } else { DISR_TCINT };

        self.hlwd.pi.set_level(FlipperIrq::Di, self.hlwd.di.irq_pending());
        Ok(())
    }

    /// The guest wrote DISR (status W1C and/or mask bits) - re-derive
    /// whether DI's PI line should still be asserted.
    pub fn handle_task_di_irq_sync(&mut self) {
        self.hlwd.pi.set_level(FlipperIrq::Di, self.hlwd.di.irq_pending());
    }
}

impl MmioDevice for DriveInterface {
    type Width = u32;
    fn read(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.disr,
            0x04 => self.dicvr,
            0x08..=0x10 => self.dicmdbuf[(off - 0x08) / 4],
            0x14 => self.dimar,
            0x18 => self.dilength,
            0x1c => self.dicr,
            0x20 => self.diimmbuf,
            0x24 => self.dicfg,
            _ => { bail!("DI read to undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, _access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                const DISR_W1C_MASK: u32 = 0x0000_0054;
                // Bits the guest writes as 1 (within the W1C mask) are acked/cleared.
                let acked = val & DISR_W1C_MASK;

                // Take the write as-is outside the W1C positions (e.g. the mask
                // bits), and restore only the status bits that weren't acked.
                let mut new_val = val & !DISR_W1C_MASK;
                new_val |= (self.disr & DISR_W1C_MASK) & !acked;

                self.disr = new_val;
                return Ok(Some(BusTask::DiIrqSync));
            },
            0x04 => {
                const DICVR_W1C_MASK: u32 = 0x0000_0004; // CVRINT
                const DICVR_RO_MASK: u32 = 0x0000_0001; // CVR
                let mut new_val = val;

                if (new_val & DICVR_W1C_MASK) != 0 {
                    new_val &= !(new_val & DICVR_W1C_MASK);
                }

                new_val &= !DICVR_RO_MASK;
                new_val |= self.dicvr & DICVR_RO_MASK;

                self.dicvr = new_val;
            },
            0x08..=0x10 => self.dicmdbuf[(off - 0x08) / 4] = val,
            0x14 => self.dimar = val,
            0x18 => self.dilength = val,
            0x1c => {
                self.dicr = val & !0x0000_00001;

                if val & 0x0000_0001 == 0x0000_0001 {
                    // TSTART=1, begin a transfer
                    return Ok(self.do_cmd());
                }
            },
            0x20 => self.diimmbuf = val,
            _ => { bail!("DI write {val:08x?} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}


