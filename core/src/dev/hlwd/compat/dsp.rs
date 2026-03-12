use anyhow::bail;
use log::info;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Legacy DSP
/// TODO: This is a crappy stub of the DSP that just pretends that everything is "fine".
/// This thing is kind of weird, Wiibrew and YAGCD list it's registers as all 16-bit, yet some of
/// them behave like 32-bit registers, and 32-bit writes to them are also valid.  So, this ended up
/// being kind of a mess in order to accomodate that.
/// TODO: Clean up?
/// Also, we begrudgingly need to emulate ARAM transfers here, since, even though ARAM physically
/// doesn't exist in the Wii, some crappy software (_cough cough_ libogc _cough cough_) relies on
/// ARAM transfers to claim to complete (even though they don't go anywhere), which technically
/// happens on real hardware,  even though it really shouldn't be relied on.....
#[derive(Debug, Clone)]
pub struct DigitalSignalProcessor {
    pub mailbox_in_h: u16,
    pub mailbox_in_l: u16,
    pub mailbox_out_h: u16,
    pub mailbox_out_l: u16,
    pub unk_08: u16,
    pub control_status: u16,
    pub unk_0c: u16,
    pub unk_0e: u16,
    pub unk_10: u16,
    pub ar_size: u16,
    pub unk_14: u16,
    pub ar_mode: u16,
    pub unk_18: u16,
    pub ar_refresh: u16,
    pub unk_1c: u16,
    pub unk_1e: u16,
    pub ar_dma_mmaddr_h: u16,
    pub ar_dma_mmaddr_l: u16,
    pub ar_dma_araddr_h: u16,
    pub ar_dma_araddr_l: u16,
    pub ar_dma_size_h: u16,
    pub ar_dma_size_l: u16,
    pub unk_2c: u16,
    pub unk_2e: u16,
    pub dma_start_addr_h: u16,
    pub dma_start_addr_l: u16,
    pub unk_34: u16,
    pub dma_control_length: u16,
    pub unk_38: u16,
    pub dma_bytes_left: u16,

    // internal state
    iram: Vec<u8>,
    dram: Vec<u8>,
    irom: Vec<u8>,
    drom: Vec<u8>,

    dma_dir: bool,
    dma_src_ptr: u32,
    dma_dest_ptr: u32,
    halt: bool,
    reset: bool
}
impl Default for DigitalSignalProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalSignalProcessor {
    pub fn new() -> Self {
        DigitalSignalProcessor {
            mailbox_in_h: 0,
            mailbox_in_l: 0,
            mailbox_out_h: 0,
            mailbox_out_l: 0,
            unk_08: 0,
            // at least, this is the state that Linux has it in at idle
            control_status: 0x0816,
            unk_0c: 0,
            unk_0e: 0,
            unk_10: 0,
            ar_size: 0,
            unk_14: 0,
            ar_mode: 0,
            unk_18: 0,
            ar_refresh: 0,
            unk_1c: 0,
            unk_1e: 0,
            ar_dma_mmaddr_h: 0,
            ar_dma_mmaddr_l: 0,
            ar_dma_araddr_h: 0,
            ar_dma_araddr_l: 0,
            ar_dma_size_h: 0,
            ar_dma_size_l: 0,
            unk_2c: 0,
            unk_2e: 0,
            dma_start_addr_h: 0,
            dma_start_addr_l: 0,
            unk_34: 0,
            dma_control_length: 0,
            unk_38: 0,
            dma_bytes_left: 0,

            iram: vec![0; 8 * 1024],
            dram: vec![0; 8 * 1024],
            irom: vec![0; 8 * 1024],
            drom: vec![0; 4 * 1024],

            halt: false,
            reset: false,
            dma_dir: false,
            dma_src_ptr: 0,
            dma_dest_ptr: 0,
        }
    }
}

/*
 * TODO: port over DMA and timing-related code from
 * https://github.com/Wii-Linux/dol-tools/blob/main/src/dol-run/mmio/dsp.c
 */

impl MmioDeviceMultiWidth for DigitalSignalProcessor {
    fn read8(&self, off: usize) -> anyhow::Result<BusPacket> {
        bail!("DSP unsupported 8-bit read from offset {off:x}");
    }
    fn read16(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.mailbox_in_h,
            0x02 => self.mailbox_in_l,
            0x04 => self.mailbox_out_h,
            0x06 => self.mailbox_out_l,
            0x08 => self.unk_08,
            0x0a => self.control_status,
            0x0c => self.unk_0c,
            0x0e => self.unk_0e,
            0x10 => self.unk_10,
            0x12 => self.ar_size,
            0x14 => self.unk_14,
            0x16 => self.ar_mode,
            0x18 => self.unk_18,
            0x1a => self.ar_refresh,
            0x1c => self.unk_1c,
            0x1e => self.unk_1e,
            0x20 => self.ar_dma_mmaddr_h,
            0x22 => self.ar_dma_mmaddr_l,
            0x24 => self.ar_dma_araddr_h,
            0x26 => self.ar_dma_araddr_l,
            0x28 => self.ar_dma_size_h,
            0x2a => self.ar_dma_size_l,
            0x2c => self.unk_2c,
            0x2e => self.unk_2e,
            0x30 => self.dma_start_addr_h,
            0x32 => self.dma_start_addr_l,
            0x34 => self.unk_34,
            0x36 => self.dma_control_length,
            0x38 => self.unk_38,
            0x3a => self.dma_bytes_left,
            _ => { bail!("DSP 16-bit read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Half(val))
    }
    fn read32(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val: u32 = match off {
            0x00 => (self.mailbox_in_h as u32) << 16 & self.mailbox_in_l as u32,
            0x04 => (self.mailbox_out_h as u32) << 16 & self.mailbox_out_l as u32,
            0x20 => (self.ar_dma_mmaddr_h as u32) << 16 & self.ar_dma_mmaddr_l as u32,
            0x24 => (self.ar_dma_araddr_h as u32) << 16 & self.ar_dma_araddr_l as u32,
            0x30 => (self.dma_start_addr_h as u32) << 16 & self.dma_start_addr_l as u32,
            _ => { bail!("DSP 32-bit read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }

    fn write8(&mut self, off: usize, val: u8) -> anyhow::Result<Option<BusTask>> {
        bail!("DSP unsupported 8-bit write {val:02x} to offset {off:x}");
    }
    fn write16(&mut self, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                self.mailbox_in_h = val;
                if val & 0x8000 == 0 {
                    self.mailbox_out_h &= 0x7fff;
                }
            },
            0x02 => self.mailbox_in_l = val,
            0x04 => {
                // only allow writes to the MSb, keep the rest the same
                if val & 0x8000 == 0 {
                    self.mailbox_out_h |= 0x8000;
                }
                else {
                    self.mailbox_out_h &= 0x7fff;
                }
            }
            0x06 => self.mailbox_out_l = val,
            0x08 => self.unk_08 = val,
            0x0a => {
                info!(target: "DSP", "CSR written with {val:x}");
                // check RES bit
                if val & 0x0001 == 0x0001 {
                    info!(target: "DSP", "DSP Reset");
                    self.mailbox_out_h &= 0x7fff;
                }

                // check HALT bit
                if val & 0x0004 == 0x0004 && self.control_status & 0x0004 == 0x0000 {
                    info!(target: "DSP", "DSP Halted");
                    self.halt = true;
                }
                else if val & 0x0004 == 0x0000 && self.control_status & 0x0004 == 0x0004 {
                    info!(target: "DSP", "DSP Resumed");
                    self.halt = false;
                    self.mailbox_out_h |= 0x8000;
                }

                // sent interrupt bits
                if val & 0x0008 == 0x0008 {
                    info!(target: "DSP", "Clear AI Interrupt");
                    self.control_status &= 0xfff7;
                }

                if val & 0x0020 == 0x0020 {
                    info!(target: "DSP", "Clear ARAM Interrupt");
                    self.control_status &= 0xffdf;
                }

                if val & 0x0080 == 0x0080 {
                    info!(target: "DSP", "Clear DSP Interrupt");
                    self.control_status &= 0xff7f;
                }

                // keep existing (potentially-updated) values of AIDINT/ARINT/DSPINT, always clear
                // RES bit
                self.control_status = (val & 0xff56) | (self.control_status & 0x00a8);
            },
            0x0c => self.unk_0c = val,
            0x0e => self.unk_0e = val,
            0x10 => self.unk_10 = val,
            0x12 => self.ar_size = val,
            0x14 => self.unk_14 = val,
            0x16 => self.ar_mode = val,
            0x18 => self.unk_18 = val,
            0x1a => self.ar_refresh = val,
            0x1c => self.unk_1c = val,
            0x1e => self.unk_1e = val,
            0x20 => self.ar_dma_mmaddr_h = val,
            0x22 => self.ar_dma_mmaddr_l = val,
            0x24 => self.ar_dma_araddr_h = val,
            0x26 => self.ar_dma_araddr_l = val,
            0x28 => self.ar_dma_size_h = val,
            0x2a => {
                self.ar_dma_size_l = val;

                if self.ar_dma_size_h & 0x8000 == 0x8000 {
                    info!(target: "DSP", "ARAM DMA operation: transfer from ARAM to Main Memory: {:x} (ARAM) to {:x} (Main Memory)", (self.ar_dma_araddr_h as u32) << 16 | self.ar_dma_araddr_l as u32, (self.ar_dma_mmaddr_h as u32) << 16 | self.ar_dma_mmaddr_l as u32);
                }
                else {
                    info!(target: "DSP", "ARAM DMA operation: transfer from Main Memory to ARAM: {:x} (ARAM) from {:x} (Main Memory)", (self.ar_dma_araddr_h as u32) << 16 | self.ar_dma_araddr_l as u32, (self.ar_dma_mmaddr_h as u32) << 16 | self.ar_dma_mmaddr_l as u32);
                }

                // TODO: once emulating timing, raise ARDMASTAT for a bit first
                self.control_status |= 0x0020; // raise ARINT
            }
            0x2c => self.unk_2c = val,
            0x2e => self.unk_2e = val,
            0x30 => self.dma_start_addr_h = val,
            0x32 => self.dma_start_addr_l = val,
            0x34 => self.unk_34 = val,
            0x36 => self.dma_control_length = val,
            0x38 => self.unk_38 = val,
            0x3a => self.dma_bytes_left = val,
            _ => { bail!("DSP 16-bit write {val:04x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
    fn write32(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                self.mailbox_in_h = ((val & 0xffff0000) >> 16) as u16;
                self.mailbox_in_l = (val & 0x0000ffff) as u16;
            },
            0x04 => {
                self.mailbox_out_h = ((val & 0xffff0000) >> 16) as u16;
                self.mailbox_out_l = (val & 0x0000ffff) as u16;
            },
            0x20 => {
                self.ar_dma_mmaddr_h = ((val & 0xffff0000) >> 16) as u16;
                self.ar_dma_mmaddr_l = (val & 0x0000ffff) as u16;
            },
            0x24 => {
                self.ar_dma_araddr_h = ((val & 0xffff0000) >> 16) as u16;
                self.ar_dma_araddr_l = (val & 0x0000ffff) as u16;
            },
            0x28 => {
                self.ar_dma_size_h = ((val & 0xffff0000) >> 16) as u16;
                self.ar_dma_size_l = (val & 0x0000ffff) as u16;

                if self.ar_dma_size_h & 0x8000 == 0x8000 {
                    info!(target: "DSP", "ARAM DMA operation: transfer from ARAM to Main Memory: {:x} (ARAM) to {:x} (Main Memory)", (self.ar_dma_araddr_h as u32) << 16 | self.ar_dma_araddr_l as u32, (self.ar_dma_mmaddr_h as u32) << 16 | self.ar_dma_mmaddr_l as u32);
                }
                else {
                    info!(target: "DSP", "ARAM DMA operation: transfer from Main Memory to ARAM: {:x} (ARAM) from {:x} (Main Memory)", (self.ar_dma_araddr_h as u32) << 16 | self.ar_dma_araddr_l as u32, (self.ar_dma_mmaddr_h as u32) << 16 | self.ar_dma_mmaddr_l as u32);
                }

                // TODO: once emulating timing, raise ARDMASTAT for a bit first
                self.control_status |= 0x0020; // raise ARINT
            },
            0x30 => {
                self.dma_start_addr_h = ((val & 0xffff0000) >> 16) as u16;
                self.dma_start_addr_l = (val & 0x0000ffff) as u16;
            },
            _ => { bail!("DSP 32-bit write {val:08x} to undefined offset {off:x}"); },
        };
        Ok(None)
    }
}

