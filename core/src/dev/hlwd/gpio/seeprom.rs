#![allow(clippy::unusual_byte_groupings)]
use crate::dev::hlwd::gpio::*;
use crate::mem::*;

use log::{debug, info};

/// Set of commands to/states of the SEEPROM state machine.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeepromOp { 
    Ewds, Wral, Eral, Ewen, Ext, Write, Read, Erase, Init
}
impl SeepromOp {
    pub fn from_initial(x: u32) -> anyhow::Result<Self> {
        use SeepromOp::*;
        Ok(match x {
            0b1_00 => Ext,
            0b1_01 => Write,
            0b1_10 => Read,
            0b1_11 => Erase,
            _ => bail!("SEEPROM Invalid initial bits {x:04x}"),
        })
    }

    pub fn from_ext(x: u32) -> anyhow::Result<Self> {
        use SeepromOp::*;
        Ok(match x {
            0b1_00_00 => Ewds,
            0b1_00_01 => Wral,
            0b1_00_10 => Eral,
            0b1_00_11 => Ewen,
            _ => bail!("SEEPROM Invalid extended bits {x:04x}"),
        })
    }

}

/// Container for the state of the emulated SEEPROM device.
#[derive(Debug)]
pub struct SeepromState {
    /// Data on the SEEPROM device.
    data: BigEndianMemory,

    /// Input buffer (of some set of bits).
    pub in_buf: u32,
    /// The number of bits shifted into the input buffer.
    pub num_bits: u32,
    /// Output buffer.
    pub out_buf: Option<u16>,

    pub opcd: SeepromOp,

    /// Current command/state.
    pub wren: bool,
    pub addr: Option<usize>,
    pub write_buffer: Option<u16>,
}
impl SeepromState {
    pub fn new() -> anyhow::Result<Self> {
        Ok(SeepromState {
            in_buf: 0,
            num_bits: 0,
            out_buf: None,
            opcd: SeepromOp::Init,
            data: BigEndianMemory::from_file(0x100, "seeprom.bin", false)?,
            wren: false,
            addr: None,
            write_buffer: None,
        })
    }
}

impl SeepromState {
    pub fn reset(&mut self) {
        self.in_buf = 0;
        self.out_buf = None;
        self.num_bits = 0;
        self.opcd = SeepromOp::Init;
        self.addr = None;
        self.write_buffer = None;
    }

    pub fn step(&mut self, mosi: u32, input: u32) -> anyhow::Result<Option<u32>> {
        use SeepromOp::*;

        // Shift in a bit
        self.in_buf = (self.in_buf << 1) | mosi;
        self.num_bits += 1;

        // Parse the incoming stream of bits
        match self.num_bits {
            // All valid instructions start with 0b1
            0x01 => if self.in_buf != 0b1 { 
                self.reset();
                return Ok(Some(input | GpioPin::SeepromMiso as u32));
            },

            // After reading three bits, we can determine the opcode
            0x03 => self.opcd = SeepromOp::from_initial(self.in_buf)?,

            // If this an extended opcode, there are no more relevant bits,
            // so we can just apply whatever side-effects are necessary
            0x05 => if self.opcd == Ext {
                let extop = SeepromOp::from_ext(self.in_buf)?;
                match extop {
                    Ewen => self.wren = true,
                    Ewds => self.wren = false,
                    _ => { bail!("SEEPROM ext. op {extop:?} unimplemented"); },
                }
                info!(target: "SEEPROM", "extended Op: {extop:?}");
            },

            // At this point, the last 8 bits represent an address
            0x0b => match self.opcd {
                Read | Write | Erase => {
                    self.addr = Some((self.in_buf & 0b000_11111111) as usize);
                },
                _ => {},
            },

            // At this point, the last 16 bits represent data to-be-written
            0x1b => match self.opcd {
                Write | Wral => {
                    self.write_buffer = Some((self.in_buf
                        & 0b000_00000000_1111111111111111) as u16);
                },
                _ => {},
            },
            _ => {},
        }

        // Handle the actual side effects of commands
        match self.opcd {
            Read => {
                // Prepare the bits we're going to shift out next cycle
                if self.num_bits == 0xb {
                    let addr = self.addr.unwrap();
                    let res = self.data.read::<u16>(addr * 2)?;
                    self.out_buf = Some(res);
                    debug!(target: "SEEPROM", "read {:04x} @ {:02x}", res, addr);
                    Ok(None)
                } 
                // Shift out bits from the read command
                else if self.num_bits >= 0x0c {
                    let out = self.out_buf.unwrap();
                    let bit_idx = self.num_bits - 0x0c;
                    if (out & (0x8000 >> bit_idx)) != 0 {
                        Ok(Some(input | GpioPin::SeepromMiso as u32))
                    } else {
                        Ok(Some(input & !(GpioPin::SeepromMiso as u32)))
                    }
                } else {
                    Ok(None)
                }
            },
            Write => {
                if self.num_bits == 0x1b {
                    let val = self.write_buffer.unwrap();
                    let addr = self.addr.unwrap();
                    if self.wren {
                        self.data.write::<u16>(addr * 2, val)?;
                        info!(target: "SEEPROM", "write {val:04x} @ {addr:02x}");
                    } else {
                        bail!("SEEPROM write {val:04x} @ {addr:02x} without WREN");
                    }
                    Ok(None)
                } else {
                    Ok(None)
                }
            },
            _ => Ok(None),
        }
    }
}

impl GpioInterface {
    pub fn handle_seeprom(&mut self, val: u32) -> anyhow::Result<()> {
        let mosi = ((val & GpioPin::SeepromMosi as u32) != 0) as u32;
        let cs = (val & GpioPin::SeepromCs as u32) != 0;
        let clk_rise = (self.arm.output & GpioPin::SeepromClk as u32) == 0 
            && (val & GpioPin::SeepromClk as u32) != 0;

        // When CS is deasserted, the state of the SEEPROM is irrelevant.
        if !cs {
            self.seeprom.reset();
        } 

        // If CS is asserted and we're at the rising edge of the clock,
        // compute the next step of the serial/SPI state machine.
        if cs && clk_rise {
            let new_input = self.seeprom.step(mosi, self.arm.input)?;
            if let Some (new_input) = new_input {
                self.arm.input = new_input;
            }
        }

        // Commit the value to the output register
        self.arm.output = val;
        Ok(())
    }
}

