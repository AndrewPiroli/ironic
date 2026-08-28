use log::{debug, warn};
use anyhow::bail;

use crate::bus::Bus;
use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;
use crate::dev::hlwd::compat::pi::FlipperIrq;

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
/*
const DI_STATUS_OK:           u32 = 0x0 << 24;
*/
const DI_STATUS_LID_OPEN:     u32 = 0x1 << 24;
/*
const DI_STATUS_DISC_CHANGED: u32 = 0x2 << 24;
const DI_STATUS_NO_DISC:      u32 = 0x3 << 24;
const DI_STATUS_MOTOR_OFF:    u32 = 0x4 << 24;
const DI_STATUS_ID_NOT_READ:  u32 = 0x5 << 24;
*/

/// Lower bytes of a drive status word, represents error states
const DI_ERROR_OK:                  u32 = 0x0000_0000;
/*
const DI_ERROR_MOTOR_STOPPED:       u32 = 0x0002_0400;
const DI_ERROR_DISC_ID_NOT_READ:    u32 = 0x0002_0401;
const DI_ERROR_COVER_OPENED:        u32 = 0x0002_3a00;
const DI_ERROR_SEEK_FAILED:         u32 = 0x0003_0200;
const DI_ERROR_UNRECOVERABLE_READ:  u32 = 0x0003_1100;
const DI_ERROR_PROTOCOL_ERROR:      u32 = 0x0004_0800;
const DI_ERROR_ILLEGAL_COMMAND:     u32 = 0x0005_2000;
const DI_ERROR_AUDIO_BUF_NOT_SET:   u32 = 0x0005_2001;
const DI_ERROR_LBA_OUT_OF_RANGE:    u32 = 0x0005_2100;
const DI_ERROR_ILLEGAL_CMD_FIELD:   u32 = 0x0005_2400;
const DI_ERROR_ILLEGAL_AUDIO_CMD:   u32 = 0x0005_2401;
const DI_ERROR_CONFIG_OUT_OF_PER:   u32 = 0x0005_2402;
*/
// TODO: find a real source for this; found this in CleanRip's driver but unnamed
/*
const DI_ERROR_NORMAL_READ_ON_DVDR: u32 = 0x0005_3000;
const DI_ERROR_END_OF_USER_AREA:    u32 = 0x0005_6300;
const DI_ERROR_MEDIA_CHANGED:       u32 = 0x0006_2800;
const DI_ERROR_MEDIUM_REMOVAL_REQ:  u32 = 0x000b_5a01;
*/

/// Legacy disc drive interface.
#[derive(Default, Debug, Clone)]
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
}
impl DriveInterface {
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

            // Report "no disc inserted", unconditionally, since we don't emulate a disc.
            DI_CMD_GET_STATUS => {
                // FIXME: Wii drive seems to report LID_OPEN w/o a disc?
                self.diimmbuf = DI_STATUS_LID_OPEN | DI_ERROR_OK;
                Some(BusTask::Di { error: false, dma: None })
            },

            // Pretend that it succeeded
            DI_CMD_STOP_MOTOR => {
                Some(BusTask::Di { error: false, dma: None})
            },

            // Every command that would need to touch actual media fails,
            // since there's never a disc inserted.
            DI_CMD_READ_DISC_ID | DI_CMD_READ_NORMAL | DI_CMD_READ_DVDR | DI_CMD_READ_PHYSINFO => {
                Some(BusTask::Di { error: true, dma: None })
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
            let addr = self.hlwd.di.dimar;
            self.dma_write(Requester::Soc, addr, &data)?;
            self.hlwd.di.dilength = 0; // fully transferred, no residual
        }

        let di = &mut self.hlwd.di;
        di.dicr &= !0x0000_0001; // TSTART self-clears on completion
        di.disr |= if error { DISR_DEINT } else { DISR_TCINT };

        let masked = if error {
            di.disr & DISR_DEINTMASK != 0
        } else {
            di.disr & DISR_TCINTMASK != 0
        };

        if masked {
            self.hlwd.pi.set_level(FlipperIrq::Di, true);
        }
        Ok(())
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
                let mut new_val = val;

                if (new_val & DISR_W1C_MASK) != 0 {
                    new_val &= !(new_val & DISR_W1C_MASK);
                }

                // keep un-cleared W1C bits
                new_val |= (self.disr & DISR_W1C_MASK) & !(new_val & DISR_W1C_MASK);

                self.disr = new_val;
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


