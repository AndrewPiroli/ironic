use anyhow::bail;
use log::{debug, error};

use crate::bus::Bus;
use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

use super::bp::BpEvent;

/// GX Command Processor (CP)
///
/// CP decodes commands out of the FIFO and is responsible for driving
/// the rest of the GX pipeline

#[derive(Default, Debug, Clone)]
pub struct CommandProcessor {
    // MMIO regs
    pub cr: u16,
    pub clear: u16,
    pub perf_select: u16,
    pub token: u16,
    pub bbox_l: u16,
    pub bbox_r: u16,
    pub bbox_t: u16,
    pub bbox_b: u16,
    pub fifo_base: u32,
    pub fifo_end: u32,
    pub fifo_hi_watermark: u32,
    pub fifo_lo_watermark: u32,
    pub fifo_rw_distance: u32,
    pub fifo_wr_ptr: u32,
    pub fifo_rd_ptr: u32,
    pub fifo_bp: u32,

    bp_hit: bool,

    // Internal regs
    pub vcd_lo: u32,
    pub vcd_hi: u32,
    pub vat_group0: [u32; 8],
    pub vat_group1: [u32; 8],
    pub vat_group2: [u32; 8],
}
impl CommandProcessor {
    /// Compute the SR value based on current state
    pub fn status(&self) -> u16 {
        let mut sr = 0u16;
        // ReadIdle / CommandIdle: no unconsumed bytes between rd/wr ptrs
        // TODO: once real command decoding exists, CommandIdle should
        // instead reflect whether the CP is mid-command
        if self.fifo_rw_distance == 0 {
            sr |= 0x0004; // ReadIdle
            sr |= 0x0008; // CommandIdle
        }

        // Breakpoint: `bp_hit` is already correctly maintained (including being cleared
        // while BPEnable is off) by `update_breakpoint_latch`.
        if self.bp_hit {
            sr |= 0x0010;
        }

        if self.fifo_hi_watermark != 0 && self.fifo_rw_distance >= self.fifo_hi_watermark {
            sr |= 0x0001; // OverflowHiWatermark
        }

        if self.fifo_rw_distance <= self.fifo_lo_watermark {
            sr |= 0x0002; // UnderflowLoWatermark
        }

        sr
    }

    /// Whether the CP interrupt line should be asserted
    pub fn irq_pending(&self) -> bool {
        let sr = self.status();
        (sr & 0x0001 != 0 && self.cr & 0x0004 != 0)  // OverflowHiWatermark
            || (sr & 0x0002 != 0 && self.cr & 0x0008 != 0)  // UnderflowLoWatermark
            || (sr & 0x0010 != 0 && self.cr & 0x0020 != 0)  // Breakpoint
    }

    fn update_breakpoint_latch(&mut self) {
        if self.cr & 0x0002 != 0 {
            if self.fifo_rd_ptr == self.fifo_bp {
                self.bp_hit = true;
            } else {
                self.bp_hit = false;
            }
        } else {
            self.bp_hit = false;
        }
    }

    pub fn read_reg(&self, _addr: u8) -> u32 {
        0
    }
    pub fn write_reg(&mut self, addr: u8, val: u32) {
        match addr {
            0x50 => self.vcd_lo = val,
            0x60 => self.vcd_hi = val,
            0x70..=0x77 => self.vat_group0[(addr - 0x70) as usize] = val,
            0x80..=0x87 => self.vat_group1[(addr - 0x80) as usize] = val,
            0x90..=0x97 => self.vat_group2[(addr - 0x90) as usize] = val,
            _ => {},
        }
    }

    /// Compute the size of a single vertex according to the current VCD
    /// and VAT
    pub fn vertex_size(&self, vat: u8) -> u32 {
        let g0 = self.vat_group0[vat as usize];
        let g1 = self.vat_group1[vat as usize];
        let g2 = self.vat_group2[vat as usize];

        // PosMatIdx + Tex0-7MatIdx: one byte each, when enabled.
        let matidx_size = (self.vcd_lo & 0x1ff).count_ones();

        let pos_presence = VtxCompPresence::from(self.vcd_lo >> 9);
        let pos_elements = if g0 & 1 == 0 { 2 } else { 3 };
        let pos_format = VtxCompFormat::from(g0 >> 1);
        let pos_size = direct_indexed_size(pos_presence, pos_format.size() * pos_elements);

        let normal_presence = VtxCompPresence::from(self.vcd_lo >> 11);
        let normal_ntb = (g0 >> 9) & 1 != 0;
        let normal_format = VtxCompFormat::from(g0 >> 10);
        let normal_index3 = (g0 >> 31) & 1 != 0;
        let normal_size = match normal_presence {
            VtxCompPresence::NotPresent => 0,
            VtxCompPresence::Direct => normal_format.size() * if normal_ntb { 9 } else { 3 },
            VtxCompPresence::Index8 => if normal_ntb && normal_index3 { 3 } else { 1 },
            VtxCompPresence::Index16 => if normal_ntb && normal_index3 { 6 } else { 2 },
        };

        let color0_presence = VtxCompPresence::from(self.vcd_lo >> 13);
        let color0_format = VtxColorFormat::from(g0 >> 14);
        let color0_size = color_size(color0_presence, color0_format);

        let color1_presence = VtxCompPresence::from(self.vcd_lo >> 15);
        let color1_format = VtxColorFormat::from(g0 >> 18);
        let color1_size = color_size(color1_presence, color1_format);

        // Tex0-7: presence bits come from VCD_HI (2 bits each); element
        // count/format come from the VAT groups (frac bits are irrelevant
        // to wire size, so they're skipped).
        let tex_presence: [VtxCompPresence; 8] = core::array::from_fn(|i| {
            VtxCompPresence::from(self.vcd_hi >> (i * 2))
        });
        let tex_elements_format = [
            ((g0 >> 21) & 1, g0 >> 22), // Tex0
            ((g1 >> 0) & 1, g1 >> 1),   // Tex1
            ((g1 >> 9) & 1, g1 >> 10),  // Tex2
            ((g1 >> 18) & 1, g1 >> 19), // Tex3
            ((g1 >> 27) & 1, g1 >> 28), // Tex4
            ((g2 >> 5) & 1, g2 >> 6),   // Tex5
            ((g2 >> 14) & 1, g2 >> 15), // Tex6
            ((g2 >> 23) & 1, g2 >> 24), // Tex7
        ];
        let tex_size: u32 = (0..8).map(|i| {
            let (elem_bit, format_bits) = tex_elements_format[i];
            let elements = if elem_bit == 0 { 1 } else { 2 };
            let format = VtxCompFormat::from(format_bits);
            direct_indexed_size(tex_presence[i], format.size() * elements)
        }).sum();

        matidx_size + pos_size + normal_size + color0_size + color1_size + tex_size
    }
}

/// Per-attribute presence
#[derive(Debug, Clone, Copy, PartialEq)]
enum VtxCompPresence {
    NotPresent,
    Direct,
    Index8,
    Index16,
}
impl From<u32> for VtxCompPresence {
    fn from(val: u32) -> Self {
        match val & 0x3 {
            0 => VtxCompPresence::NotPresent,
            1 => VtxCompPresence::Direct,
            2 => VtxCompPresence::Index8,
            _ => VtxCompPresence::Index16,
        }
    }
}

/// Per-component wire format
#[derive(Debug, Clone, Copy)]
enum VtxCompFormat {
    UByte,
    Byte,
    UShort,
    Short,
    Float,
}
impl From<u32> for VtxCompFormat {
    fn from(val: u32) -> Self {
        match val & 0x7 {
            0 => VtxCompFormat::UByte,
            1 => VtxCompFormat::Byte,
            2 => VtxCompFormat::UShort,
            3 => VtxCompFormat::Short,
            _ => VtxCompFormat::Float,
        }
    }
}
impl VtxCompFormat {
    fn size(self) -> u32 {
        match self {
            VtxCompFormat::UByte | VtxCompFormat::Byte => 1,
            VtxCompFormat::UShort | VtxCompFormat::Short => 2,
            VtxCompFormat::Float => 4,
        }
    }
}

/// Vertex color wire format, decoded from a 3-bit VAT field.
#[derive(Debug, Clone, Copy)]
enum VtxColorFormat {
    Rgb565,
    Rgb888,
    Rgb888x,
    Rgba4444,
    Rgba6666,
    Rgba8888,
}
impl From<u32> for VtxColorFormat {
    fn from(val: u32) -> Self {
        match val & 0x7 {
            0 => VtxColorFormat::Rgb565,
            1 => VtxColorFormat::Rgb888,
            2 => VtxColorFormat::Rgb888x,
            3 => VtxColorFormat::Rgba4444,
            4 => VtxColorFormat::Rgba6666,
            _ => VtxColorFormat::Rgba8888,
        }
    }
}
impl VtxColorFormat {
    fn size(self) -> u32 {
        match self {
            VtxColorFormat::Rgb565 | VtxColorFormat::Rgba4444 => 2,
            VtxColorFormat::Rgb888 | VtxColorFormat::Rgba6666 => 3,
            VtxColorFormat::Rgb888x | VtxColorFormat::Rgba8888 => 4,
        }
    }
}

/// Common Direct/Index8/Index16/NotPresent -> byte size mapping used by
/// position and texcoord attributes
fn direct_indexed_size(presence: VtxCompPresence, direct_size: u32) -> u32 {
    match presence {
        VtxCompPresence::NotPresent => 0,
        VtxCompPresence::Direct => direct_size,
        VtxCompPresence::Index8 => 1,
        VtxCompPresence::Index16 => 2,
    }
}

fn color_size(presence: VtxCompPresence, format: VtxColorFormat) -> u32 {
    direct_indexed_size(presence, format.size())
}

/// Known opcodes that the CP can consume
#[derive(Debug, PartialEq)]
enum GxCpOpcode {
    Nop = 0x00,
    LoadCpReg = 0x08,
    LoadXfReg = 0x10,
    LoadIndxA = 0x20,
    LoadIndxB = 0x28,
    LoadIndxC = 0x30,
    LoadIndxD = 0x38,
    CmdCallDl = 0x40,
    CmdUnknownMetrics = 0x44,
    CmdInvlVc = 0x48,
    LoadBpReg = 0x61,
}
impl TryFrom<u8> for GxCpOpcode {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            x if x == GxCpOpcode::Nop as u8 => Ok(GxCpOpcode::Nop),
            x if x == GxCpOpcode::LoadCpReg as u8 => Ok(GxCpOpcode::LoadCpReg),
            x if x == GxCpOpcode::LoadXfReg as u8 => Ok(GxCpOpcode::LoadXfReg),
            x if x == GxCpOpcode::LoadIndxA as u8 => Ok(GxCpOpcode::LoadIndxA),
            x if x == GxCpOpcode::LoadIndxB as u8 => Ok(GxCpOpcode::LoadIndxB),
            x if x == GxCpOpcode::LoadIndxC as u8 => Ok(GxCpOpcode::LoadIndxC),
            x if x == GxCpOpcode::LoadIndxD as u8 => Ok(GxCpOpcode::LoadIndxD),
            x if x == GxCpOpcode::CmdCallDl as u8 => Ok(GxCpOpcode::CmdCallDl),
            x if x == GxCpOpcode::CmdUnknownMetrics as u8 => Ok(GxCpOpcode::CmdUnknownMetrics),
            x if x == GxCpOpcode::CmdInvlVc as u8 => Ok(GxCpOpcode::CmdInvlVc),
            x if x == GxCpOpcode::LoadBpReg as u8 => Ok(GxCpOpcode::LoadBpReg),
            unmapped_value => Err(unmapped_value),
        }
    }
}

/// Known primitive types
#[derive(Debug, PartialEq)]
enum GxPrimType {
    Quads = 0,
    Quads2 = 1,
    Triangles = 2,
    TriangleStrip = 3,
    TriangleFan = 4,
    Lines = 5,
    LineStrip = 6,
    Points = 7,
}
impl TryFrom<u8> for GxPrimType {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            x if x == GxPrimType::Quads as u8 => Ok(GxPrimType::Quads),
            x if x == GxPrimType::Quads2 as u8 => Ok(GxPrimType::Quads2),
            x if x == GxPrimType::Triangles as u8 => Ok(GxPrimType::Triangles),
            x if x == GxPrimType::TriangleStrip as u8 => Ok(GxPrimType::TriangleStrip),
            x if x == GxPrimType::TriangleFan as u8 => Ok(GxPrimType::TriangleFan),
            x if x == GxPrimType::Lines as u8 => Ok(GxPrimType::Lines),
            x if x == GxPrimType::LineStrip as u8 => Ok(GxPrimType::LineStrip),
            x if x == GxPrimType::Points as u8 => Ok(GxPrimType::Points),
            unmapped_value => Err(unmapped_value),
        }
    }
}

impl Bus {
    /// Drain the GX FIFO, decoding and executing commands out of memory at
    /// at the CP's read pointer.
    ///
    /// We need to read memory here so this is on Bus instead of
    /// CommandProcessor.
    fn gx_fifo_addr(&self, offset: u32) -> u32 {
        let cp = &self.hlwd.gx.cp;
        let pi = &self.hlwd.pi;
        if pi.fifo_base_end <= pi.fifo_base_start {
            // XXX Unconfigured, fall back to linear addressing
            return cp.fifo_rd_ptr + offset;
        }

        // end = base + size - 4, see wrapping in PI FIFO
        let size = pi.fifo_base_end - pi.fifo_base_start + 4;
        let rel = cp.fifo_rd_ptr.wrapping_sub(pi.fifo_base_start).wrapping_add(offset) % size;
        pi.fifo_base_start.wrapping_add(rel)
    }

    pub fn gx_process_fifo(&mut self) -> anyhow::Result<()> {
        while self.hlwd.gx.cp.fifo_rw_distance != 0 {
            // We at least have an opcode, handle it
            let opc_byte = self.read8(Requester::Soc, self.gx_fifo_addr(0))?;
            let mut consumed = 1;
            let mut needed = 0;

            'opc_match: {
                match GxCpOpcode::try_from(opc_byte) {
                    Ok(opc) => match opc {
                        GxCpOpcode::Nop => {
                            debug!(target: "CP", "nop")
                        },
                        GxCpOpcode::LoadCpReg => {
                            debug!(target: "CP", "Load CP Reg");
                            if self.hlwd.gx.cp.fifo_rw_distance < 6 {
                                needed = 6 - self.hlwd.gx.cp.fifo_rw_distance;
                                break 'opc_match;
                            }
                            consumed = 6;

                            let reg = self.read8(Requester::Soc, self.gx_fifo_addr(1))?;
                            let data = self.read32(Requester::Soc, self.gx_fifo_addr(2))?;
                            debug!(target: "CP", " -> reg = {reg:02x}, data = {data:08x}");
                            self.hlwd.gx.cp.write_reg(reg, data);
                        },
                        GxCpOpcode::LoadXfReg => {
                            debug!(target: "CP", "Load XF Reg");
                            if self.hlwd.gx.cp.fifo_rw_distance < 3 {
                                needed = 3 - self.hlwd.gx.cp.fifo_rw_distance;
                                break 'opc_match;
                            }

                            let len: u32 = self.read16(Requester::Soc, self.gx_fifo_addr(1))? as u32 + 1;
                            if self.hlwd.gx.cp.fifo_rw_distance < 1 + 2 + 2 + (4 * len) {
                                needed = (1 + 2 + 2 + (4 * len)) - self.hlwd.gx.cp.fifo_rw_distance;
                                break 'opc_match;
                            }

                            consumed = 1 + 2 + 2 + (4 * len);
                            let addr = self.read16(Requester::Soc, self.gx_fifo_addr(3))?;
                            debug!(target: "CP", " -> len = {len}, addr = {addr:04x}");

                            // TODO: write [len] XF regs
                        }
                        GxCpOpcode::LoadIndxA => debug!(target: "CP", "Load Indx A"),
                        GxCpOpcode::LoadIndxB => debug!(target: "CP", "Load Indx B"),
                        GxCpOpcode::LoadIndxC => debug!(target: "CP", "Load Indx C"),
                        GxCpOpcode::LoadIndxD => debug!(target: "CP", "Load Indx D"),
                        GxCpOpcode::CmdCallDl => debug!(target: "CP", "Call DL"),
                        GxCpOpcode::CmdUnknownMetrics => debug!(target: "CP", "Unknown Metrics"),
                        GxCpOpcode::CmdInvlVc => debug!(target: "CP", "Invalidate VC"),
                        GxCpOpcode::LoadBpReg => {
                            debug!(target: "CP", "Load BP Reg");
                            if self.hlwd.gx.cp.fifo_rw_distance < 5 {
                                needed = 5 - self.hlwd.gx.cp.fifo_rw_distance;
                                break 'opc_match;
                            }
                            consumed = 5;

                            let operand = self.read32(Requester::Soc, self.gx_fifo_addr(1))?;
                            let reg = ((operand & 0xff00_0000) >> 24) as u8;
                            let data = operand & 0x00ff_ffff;
                            debug!(target: "CP", " -> reg = {reg:02x}, data = {data:06x}");
                            match self.hlwd.gx.bp.write_reg(reg, data) {
                                Some(BpEvent::PeFinish) => {
                                    self.hlwd.gx.pe.request_finish_irq();
                                },
                                None => {},
                            }
                        },
                    }
                    Err(opc) => {
                        match opc {
                            // primitive data
                            0x80..=0xbf => {
                                let prim_type_raw = opc & 0x78;
                                let vat = opc & 0x07;

                                if self.hlwd.gx.cp.fifo_rw_distance < 3 {
                                    needed = 3 - self.hlwd.gx.cp.fifo_rw_distance;
                                    break 'opc_match;
                                }

                                let num_vtx = self.read16(Requester::Soc, self.gx_fifo_addr(1))? as u32;

                                let prim_type = match GxPrimType::try_from(prim_type_raw) {
                                    Ok(prim_type) => prim_type,
                                    Err(prim_type) => bail!("Unknown GX primitive type {:x}", prim_type as u8),
                                };

                                let vtx_size = self.hlwd.gx.cp.vertex_size(vat);
                                let total = 3 + vtx_size * num_vtx;
                                if self.hlwd.gx.cp.fifo_rw_distance < total {
                                    needed = total - self.hlwd.gx.cp.fifo_rw_distance;
                                    break 'opc_match;
                                }
                                consumed = total;

                                match prim_type {
                                    GxPrimType::Quads => debug!(target: "CP", "Prim: Quads (num={num_vtx})"),
                                    GxPrimType::Quads2 => debug!(target: "CP", "Prim: Quads2 (num={num_vtx})"),
                                    GxPrimType::Triangles => debug!(target: "CP", "Prim: Triangles (num={num_vtx})"),
                                    GxPrimType::TriangleStrip => debug!(target: "CP", "Prim: TriangleStrip (num={num_vtx})"),
                                    GxPrimType::TriangleFan => debug!(target: "CP", "Prim: TriangleFan (num={num_vtx})"),
                                    GxPrimType::Lines => debug!(target: "CP", "Prim: Lines (num={num_vtx})"),
                                    GxPrimType::LineStrip => debug!(target: "CP", "Prim: LineStrip (num={num_vtx})"),
                                    GxPrimType::Points => debug!(target: "CP", "Prim: Points (num={num_vtx})"),
                                }
                            },
                            _ => {
                                let rd_ptr = self.hlwd.gx.cp.fifo_rd_ptr;
                                let mut dump = String::new();
                                for i in 0..48u32 {
                                    let byte = self.read8(Requester::Soc, self.gx_fifo_addr(i)).unwrap_or(0xee);
                                    dump.push_str(&format!("{byte:02x} "));
                                }
                                error!(target: "CP",
                                    "Unknown GX opcode {:x} @ fifo_rd_ptr={:08x} (mapped={:08x}), \
                                    fifo_rw_distance={:08x}, cp.fifo_wr_ptr={:08x}, cp.fifo_base={:08x}, cp.fifo_end={:08x}, \
                                    pi.fifo_base_start={:08x}, pi.fifo_base_end={:08x}, pi.fifo_cur_write_ptr={:08x}\n\
                                    next 48 bytes from rd_ptr: {dump}",
                                    opc as u8, rd_ptr, self.gx_fifo_addr(0),
                                    self.hlwd.gx.cp.fifo_rw_distance, self.hlwd.gx.cp.fifo_wr_ptr,
                                    self.hlwd.gx.cp.fifo_base, self.hlwd.gx.cp.fifo_end,
                                    self.hlwd.pi.fifo_base_start, self.hlwd.pi.fifo_base_end, self.hlwd.pi.fifo_cur_write_ptr,
                                );
                                bail!("Unknown GX opcode {:x}", opc as u8);
                            },
                        }
                    }
                }
            }

            if needed > 0 {
                debug!(target: "CP", "Need {} more bytes for this command", needed);
                break;
            }

            self.hlwd.gx.cp.fifo_rd_ptr = self.gx_fifo_addr(consumed);
            self.hlwd.gx.cp.fifo_rw_distance -= consumed;
            self.hlwd.gx.cp.update_breakpoint_latch();
        }
        Ok(())
    }
}
impl MmioDeviceMultiWidth for CommandProcessor {
    fn read8(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let _val = match off {
            _ => bail!("CP 8-bit read to undefined offset {off:x}"),
        };
        //Ok(BusPacket::Byte(val))
    }
    fn read16(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.status(),
            0x02 => self.cr,
            0x04 => self.clear,
            0x06 => self.perf_select,
            0x0e => self.token,
            0x10 => self.bbox_l,
            0x12 => self.bbox_r,
            0x14 => self.bbox_t,
            0x16 => self.bbox_b,
            0x20 => (self.fifo_base & 0xffff) as u16,
            0x22 => (self.fifo_base >> 16) as u16,
            0x24 => (self.fifo_end & 0xffff) as u16,
            0x26 => (self.fifo_end >> 16) as u16,
            0x28 => (self.fifo_hi_watermark & 0xffff) as u16,
            0x2a => (self.fifo_hi_watermark >> 16) as u16,
            0x2c => (self.fifo_lo_watermark & 0xffff) as u16,
            0x2e => (self.fifo_lo_watermark >> 16) as u16,
            0x30 => (self.fifo_rw_distance & 0xffff) as u16,
            0x32 => (self.fifo_rw_distance >> 16) as u16,
            0x34 => (self.fifo_wr_ptr & 0xffff) as u16,
            0x36 => (self.fifo_wr_ptr >> 16) as u16,
            0x38 => (self.fifo_rd_ptr & 0xffff) as u16,
            0x3a => (self.fifo_rd_ptr >> 16) as u16,
            0x3c => (self.fifo_bp & 0xffff) as u16,
            0x3e => (self.fifo_bp >> 16) as u16,
            _ => bail!("CP 16-bit read to undefined offset {off:x}"),
        };
        Ok(BusPacket::Half(val))
    }
    fn read32(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x20 => self.fifo_base,
            0x24 => self.fifo_end,
            0x28 => self.fifo_hi_watermark,
            0x2c => self.fifo_lo_watermark,
            0x30 => self.fifo_rw_distance,
            0x34 => self.fifo_wr_ptr,
            0x38 => self.fifo_rd_ptr,
            0x3c => self.fifo_bp,
            _ => bail!("CP 32-bit read to undefined offset {off:x}"),
        };
        Ok(BusPacket::Word(val))
    }
    fn write8(&mut self, _access: AccessContext, off: usize, _val: u8) -> anyhow::Result<Option<BusTask>> {
        match off {
            _ => bail!("CP 8-bit write to undefined offset {off:x}"),
        };
        //Ok(None)
    }
    fn write16(&mut self, _access: AccessContext, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            // Only bits 0-5 are defined, the rest are masked off, matching Dolphin
            0x02 => self.cr = val & 0x3f,
            0x04 => self.clear = val,
            // this is what Dolphin does for this register; YAGCD doesn't document it
            0x06 => self.perf_select = val & 0x7,
            0x0e => self.token = val,
            0x10 => self.bbox_l = val,
            0x12 => self.bbox_r = val,
            0x14 => self.bbox_t = val,
            0x16 => self.bbox_b = val,
            0x20 => { self.fifo_base &= 0xffff0000; self.fifo_base |= val as u32; },
            0x22 => { self.fifo_base &= 0x0000ffff; self.fifo_base |= (val as u32) << 16; },
            0x24 => { self.fifo_end &= 0xffff0000; self.fifo_end |= val as u32; },
            0x26 => { self.fifo_end &= 0x0000ffff; self.fifo_end |= (val as u32) << 16; },
            0x28 => { self.fifo_hi_watermark &= 0xffff0000; self.fifo_hi_watermark |= val as u32; },
            0x2a => { self.fifo_hi_watermark &= 0x0000ffff; self.fifo_hi_watermark |= (val as u32) << 16; },
            0x2c => { self.fifo_lo_watermark &= 0xffff0000; self.fifo_lo_watermark |= val as u32; },
            0x2e => { self.fifo_lo_watermark &= 0x0000ffff; self.fifo_lo_watermark |= (val as u32) << 16; },
            0x30 => { self.fifo_rw_distance &= 0xffff0000; self.fifo_rw_distance |= val as u32; },
            0x32 => { self.fifo_rw_distance &= 0x0000ffff; self.fifo_rw_distance |= (val as u32) << 16; },
            0x34 => { self.fifo_wr_ptr &= 0xffff0000; self.fifo_wr_ptr |= val as u32; },
            0x36 => { self.fifo_wr_ptr &= 0x0000ffff; self.fifo_wr_ptr |= (val as u32) << 16; },
            0x38 => { self.fifo_rd_ptr &= 0xffff0000; self.fifo_rd_ptr |= val as u32; },
            0x3a => { self.fifo_rd_ptr &= 0x0000ffff; self.fifo_rd_ptr |= (val as u32) << 16; },
            0x3c => { self.fifo_bp &= 0xffff0000; self.fifo_bp |= val as u32; },
            0x3e => { self.fifo_bp &= 0x0000ffff; self.fifo_bp |= (val as u32) << 16; },
            _ => bail!("CP 16-bit write to undefined offset {off:x}"),
        };
        self.update_breakpoint_latch();
        Ok(None)
    }
    fn write32(&mut self, _access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x20 => self.fifo_base = val,
            0x24 => self.fifo_end = val,
            0x28 => self.fifo_hi_watermark = val,
            0x2c => self.fifo_lo_watermark = val,
            0x30 => self.fifo_rw_distance = val,
            0x34 => self.fifo_wr_ptr = val,
            0x38 => self.fifo_rd_ptr = val,
            0x3c => self.fifo_bp = val,
            _ => bail!("CP 32-bit write {val:08x} to undefined offset {off:x}"),
        }
        self.update_breakpoint_latch();
        Ok(None)
    }
}
