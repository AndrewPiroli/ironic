
use core::slice;
use std::mem;

/// Helper functions implemented on numeric primitives.
///
/// These let us easily convert between numeric primitives and byte slices.
pub trait AccessWidth: Sized {
    fn from_be_bytes(data: &[u8]) -> Self;
    fn from_le_bytes(data: &[u8]) -> Self;
    fn to_be(self) -> Self;
    fn to_le(self) -> Self;

    fn as_ptr(&self) -> *const Self { self as *const Self }
    fn as_mut(&mut self) -> *mut Self { self as *mut Self }

    fn as_bytes(&self) -> &[u8] {
        // Safety
        // This should be good for all Sized types
        unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, mem::size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // Safety
        // This should be good for all Sized types
        unsafe { slice::from_raw_parts_mut(self.as_mut() as *mut u8, mem::size_of::<Self>()) }
    }
}

/// Macro to make implementing AccessWidth a bit less verbose.
macro_rules! impl_accesswidth {
    ($type:ident) => {
        impl AccessWidth for $type {
            fn from_be_bytes(data: &[u8]) -> Self {
                Self::from_be_bytes(data.try_into().unwrap())
            }
            fn from_le_bytes(data: &[u8]) -> Self {
                Self::from_le_bytes(data.try_into().unwrap())
            }
            fn to_be(self) -> Self { Self::to_be(self) }
            fn to_le(self) -> Self { Self::to_le(self) }
        }
    };
}

// Implement AccessWidth for the supported numeric primitives.
impl_accesswidth!(u32);
impl_accesswidth!(u16);
impl_accesswidth!(u8);


/// Handle to a target for some physical memory access.
#[derive(Debug, Clone, Copy)]
pub struct DeviceHandle {
    pub dev: Device,
    pub mask: u32,
}

/// Some kind of target device for a physical memory access.
#[derive(Debug, Clone, Copy)]
pub enum Device { Mem(MemDevice), Io(IoDevice) }

/// Different kinds of memory devices that support physical memory accesses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemDevice { MaskRom, Sram0, Sram1, Mem1, Mem2 }

/// Different kinds of I/O devices that support physical memory accesses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoDevice {
    Nand, 
    Aes, 
    Sha, 
    Ehci,
    Ohci0,
    Ohci1,
    Sdhc0,
    Sdhc1,

    Hlwd, 
    Ahb, 
    Ddr,
    Vi, 
    Pi, 
    Di, 
    Si, 
    Exi, 
    Ai,
    Mi,
}

/// A message on the bus containing some value.
#[derive(Debug, Clone, Copy)]
pub enum BusPacket { Byte(u8), Half(u16), Word(u32) }

/// The width of an access on the bus.
#[derive(Debug, Clone, Copy)]
pub enum BusWidth { B, H, W }

/// An abstract request on the bus.
#[derive(Debug)]
pub struct BusReq {
    pub handle: DeviceHandle,
    pub msg: Option<BusPacket>,
}

/// An abstract reply to a bus request.
#[derive(Debug)]
pub struct BusRep {
    pub msg: Option<BusPacket>,
}


