
use std::path::Path;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::mem;

use crate::bus::prim::AccessWidth;

/// An abstract, generic memory device.
pub struct BigEndianMemory {
    /// Vector of bytes with the contents of this memory device.
    pub data: Vec<u8>,
}
impl BigEndianMemory {
    pub fn new(len: usize, init_fn: Option<&str>) -> Self {
        let data = if init_fn.is_some() {
            let filename = init_fn.unwrap();
            let mut f = File::open(filename)
                .expect("Couldn't initialize BigEndianMemory.");

            let mut data = vec![0u8; len];
            f.read(&mut data).unwrap();
            data
        } else {
            vec![0u8; len]
        };
        BigEndianMemory { data }
    }

    pub fn dump(&self, filename: &impl AsRef<Path>) {
        let mut f = File::create(filename).expect("Couldn't create file");
        let res = f.write(self.data.as_slice());
        println!("Dumped memory to {} ({:?})", filename.as_ref().display(), res);
    }
}

impl fmt::Debug for BigEndianMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BigEndianMemory").finish()
    }
}

/// Generic reads and writes.
impl BigEndianMemory {
    pub fn read<T: AccessWidth>(&self, off: usize) -> T {
        let src_len = mem::size_of::<T>();
        if off + src_len > self.data.len() {
            panic!("Out-of-bounds read at {:x}", off);
        }
        T::from_be_bytes(&self.data[off..off + src_len])
    }
    pub fn write<T: AccessWidth>(&mut self, off: usize, val: T) {
        let data = val.as_be();
        let src_slice: &[u8] = unsafe { data.as_bytes() };
        if off + src_slice.len() > self.data.len() {
            panic!("Out-of-bounds write at {:x}", off);
        }
        self.data[off..off + src_slice.len()].copy_from_slice(src_slice);
    }
}

/// Bulk reads and writes.
impl BigEndianMemory {
    pub fn read_buf(&self, off: usize, dst: &mut [u8]) {
        if off + dst.len() > self.data.len() {
            panic!("OOB bulk read on BigEndianMemory, offset {:x}", off);
        }
        dst.copy_from_slice(&self.data[off..off + dst.len()]);
    }
    pub fn write_buf(&mut self, off: usize, src: &[u8]) {
        if off + src.len() > self.data.len() {
            panic!("OOB bulk write on BigEndianMemory, offset {:x}", off);
        }
        self.data[off..off + src.len()].copy_from_slice(src);
    }
    pub fn memset(&mut self, off: usize, len: usize, val: u8) {
        if off + len > self.data.len() {
            panic!("OOB memset on BigEndianMemory, offset {:x}", off);
        }
        for d in &mut self.data[off..off+len] {
            *d = val;
        }
    }
}
