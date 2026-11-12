
use std::path::Path;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::ops::{Deref, DerefMut};
use memmap::{MmapMut, MmapOptions};

use iset::IntervalMap;
use anyhow::{bail, Context};
use log::{error, debug};

use crate::bus::prim::AccessWidth;

/// The real backing memory, either a Vec, or a memory mapped file
pub enum BackingMem {
    Local(Vec<u8>),
    Mapped(MmapMut),
}
impl Deref for BackingMem {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            BackingMem::Local(v) => v.deref(),
            BackingMem::Mapped(m) => m.deref(),
        }
    }
}
impl DerefMut for BackingMem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            BackingMem::Local(v) => v.deref_mut(),
            BackingMem::Mapped(m) => m.deref_mut(),
        }
    }
}
impl BackingMem {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            BackingMem::Local(v) => v.as_slice(),
            BackingMem::Mapped(m) => m.deref(),
        }
    }
}

/// An abstract, generic memory device.
pub struct BigEndianMemory {
    /// Vector of bytes with the contents of this memory device.
    pub data: BackingMem,
    /// Hash of initial data (used for write tracking)
    hash: Option<u32>,
    /// Holds all writes so they can be replayed next time the emulator launches
    writes: Option<IntervalMap<usize, Vec<u8>>>,
    /// write_index
    pub write_index: u8,
    already_wrote: AtomicBool,
}
impl BigEndianMemory {
    pub fn new(len: usize) -> Self {
        let data = BackingMem::Local(vec![0u8; len]);
        BigEndianMemory { data, hash: None, writes: None, write_index: 0, already_wrote: AtomicBool::new(true)}
    }

    pub fn from_file(len: usize, filename: &Path, track_writes: bool) -> anyhow::Result<Self> {
        use anyhow::Context;
        let mut hash: Option<u32> = None;
        let mut f = File::open(filename)
            .with_context(|| format!("Failed to open file at {} for memory initialization", filename.display()))?;
        let data = if let Ok(map) = unsafe { MmapOptions::new().map_copy(&f) } {
            if track_writes {
                hash = Some(crc32fast::hash(&*map));
            }
            BackingMem::Mapped(map)
        }
        else {
            error!(target: "Other", "mmaping {} failed, falling back to copy", filename.display());
            let mut data = vec![0u8; len];
            let _ = f.read(&mut data)?; // ignore partial read
            if track_writes {
                hash = Some(crc32fast::hash(&data));
            }
            BackingMem::Local(data)
        };
        let writes: Option<IntervalMap<usize, Vec<u8>>> = if track_writes {
            debug!(target: "MEMSAVE", "BEMemory: Writes Enabled, hash: {}", hash.unwrap());
            Some(IntervalMap::new())
        }
        else {
            None
        };
        let mut res = BigEndianMemory { data, hash, writes, write_index: 0, already_wrote: AtomicBool::new(true)};
        if track_writes {
            if let Ok((write_index, mpfs)) = BigEndianMemory::get_patchfiles(hash.unwrap()) {
                res.write_index = write_index.checked_add(1).unwrap();
                for mpf in mpfs {
                    res.patch(mpf)?;
                }
            }
        }
        Ok(res)
    }

    /// Get the patches to apply persistent writes
    /// Returns the highest numbered patch file, so this time around we can write to n+1
    fn get_patchfiles(hash: u32) -> anyhow::Result<(u8, Vec<MemoryPatchFile>)> {
        let dir = match std::fs::read_dir(format!("./saved-writes/{hash}/")) {
            Ok(dir) => dir,
            Err(err) => {
                match err.raw_os_error() {
                    // Handle no directory by creating it.
                    Some(2) => {
                        std::fs::create_dir_all(format!("./saved-writes/{hash}/"))?;
                        return Ok((0, Vec::with_capacity(0)));
                    },
                    Some(_) | None => { return Err(err).context(format!("Failed to open directory ./saved-writes/{hash}/ for get_patchfiles")) }
                }
            },
        };
        // Get all files saved to the directory that matches our hash and who's filenames can be parsed into a u8
        // deserialize them, and save their filename with
        let mut pfs: Vec<(u8, MemoryPatchFile)> = dir.filter_map(|maybe_entry|{
            if let Ok(entry) = maybe_entry {
                debug!(target: "MEMSAVE", "Candidate entry: {:?}", entry.path());
                if let Ok(num) = entry.file_name().to_string_lossy().into_owned().parse::<u8>() {
                    let mpf = MemoryPatchFile::from_file(entry.path());
                    debug!(target: "MEMSAVE", "Found MemoryPatchFile: {num} {:?}", entry.path());
                    Some((num, mpf))
                }
                else {
                    None
                }
            }
            else {
                error!(target: "MEMSAVE", "Unable to read ./saved-writes/{hash}/");
                None
            }
        }).collect();
        // Sort by filename
        pfs.sort_by(|a, b| {
            a.0.cmp(&b.0)
        });
        let max = pfs.iter().map(|x|x.0).max().unwrap_or(0);
        Ok((max, pfs.iter().map(|x|x.1.clone()).collect()))
    }

    pub fn dump(&self, filename: &impl AsRef<Path>) -> anyhow::Result<()> {
        let filename = filename.as_ref();
        let mut f = File::create(filename).context(format!("BigEndianMemory: Couldn't create dump file: {}", filename.to_string_lossy()))?;
        let res = f.write(self.data.as_slice())?;
        debug!(target: "Other", "Dumped memory to {} ({res:?})", filename.display());
        Ok(())
    }

    fn patch(&mut self, patchfile: MemoryPatchFile) -> anyhow::Result<()> {
        if self.hash.unwrap() != patchfile.hash {
            bail!("Mismatched patch file!");
        }
        let temp = std::mem::take(&mut self.writes); // Or else the subsequent calls to write_buf will double-count these writes.
        for range in patchfile.ranges {
            debug!(target: "MEMSAVE", "Patching memory at offset {}: #{} bytes", range.offset, &range.data.len());
            self.write_buf(range.offset, &range.data)?;
        }
        self.writes = temp;
        Ok(())
    }

    pub fn dump_writes(&self) -> anyhow::Result<()> {
        if self.writes.is_none() {
            bail!("dump_writes but writes not enabled!");
        }
        let hash = self.hash.unwrap();
        if self.already_wrote.load(Relaxed) {
            debug!(target: "MEMSAVE", "dump_writes but already wrote the latest changes!");
            return Ok(());
        }
        self.already_wrote.store(true, Relaxed);
        let patches: Vec<MemoryPatch> = self.writes.as_ref().unwrap().iter(..).map(|x|{
            MemoryPatch { offset: x.0.start, data: x.1.clone() }
        }).collect();
        let mut mpf = MemoryPatchFile {
            hash,
            ranges: patches,
        };
        mpf.merge_adjacent_ranges();
        mpf.to_file(format!("./saved-writes/{hash}/{}", self.write_index).into())?;
        Ok(())
    }
}

impl fmt::Debug for BigEndianMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BigEndianMemory").finish()
    }
}

/// Generic reads and writes.
impl BigEndianMemory {
    pub fn read<T: AccessWidth>(&self, off: usize) -> anyhow::Result<T> {
        let src_len = mem::size_of::<T>();
        if off + src_len > self.data.len() {
            bail!("Out-of-bounds read at {off:x}");
        }
        Ok(T::from_be_bytes(&self.data[off..off + src_len]))
    }
    pub fn write<T: AccessWidth>(&mut self, off: usize, val: T) -> anyhow::Result<()> {
        let data = val.to_be();
        let src_slice: &[u8] = data.as_bytes() ;
        if off + src_slice.len() > self.data.len() {
            bail!("Out-of-bounds write at {off:x}");
        }
        if self.writes.is_some() {
            self.handle_write_tracking(off, src_slice)
        }
        self.data[off..off + src_slice.len()].copy_from_slice(src_slice);
        Ok(())
    }
}

/// Bulk reads and writes.
impl BigEndianMemory {
    pub fn read_buf(&self, off: usize, dst: &mut [u8]) -> anyhow::Result<()> {
        if off + dst.len() > self.data.len() {
            bail!("OOB bulk read on BigEndianMemory, offset {off:x}");
        }
        dst.copy_from_slice(&self.data[off..off + dst.len()]);
        Ok(())
    }
    pub fn write_buf(&mut self, off: usize, src: &[u8]) -> anyhow::Result<()> {
        if off + src.len() > self.data.len() {
            bail!("OOB bulk write on BigEndianMemory, offset {off:x}");
        }
        if self.writes.is_some() {
            self.handle_write_tracking(off, src);
        }
        self.data[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }
    pub fn memset(&mut self, off: usize, len: usize, val: u8) -> anyhow::Result<()> {
        if off + len > self.data.len() {
            bail!("OOB memset on BigEndianMemory, offset {off:x}");
        }
        if self.writes.is_some() {
            self.handle_write_tracking(off, &(vec![val; len]));
        }
        for d in &mut self.data[off..off+len] {
            *d = val;
        }
        Ok(())
    }

    fn handle_write_tracking(&mut self, off: usize, data: &[u8]) {
        use std::cmp::*;
        self.already_wrote.store(false, Relaxed);
        let writes = self.writes.as_mut().unwrap();
        // Check if we have a write in this range already
        if writes.has_overlap(off..off+data.len()) {
            // ok find the overlapping range
            let (found_range, _) = writes.iter(off..off+data.len()).next().unwrap();
            // calculate new combined range
            let new_range = min(found_range.start, off)..max(found_range.end, off+data.len());
            // if the new writes are entirely inside an existing range, just modify the data in place.
            if found_range == new_range {
                let existing_data = writes.get_mut(found_range.start..found_range.end).unwrap();
                let inner_offset = off - found_range.start;
                existing_data[inner_offset..(inner_offset+data.len())].copy_from_slice(data);
                return;
            }
            // Not the case... so the range has to grow, but it's immutable in the tree
            // So we have to pop it, modify the range+data, then re-insert
            let found_data = writes.remove(found_range.clone()).unwrap();
            let mut temp: Vec<u8> = vec![0; new_range.len()];
            if found_range.start == new_range.start {
                // grow right
                temp[0..found_data.len()].copy_from_slice(&found_data);
                let offset_start = off - found_range.start;
                temp[offset_start..(offset_start+data.len())].copy_from_slice(data);
            }
            else {
                // grow left
                temp[(new_range.start - found_range.start)..found_range.len()].copy_from_slice(&found_data);
                temp[0..data.len()].copy_from_slice(data);
            }
            writes.insert(new_range, temp);
        }
        else {
            // trivial case, just a new range
            writes.insert(off..off+data.len(), data.to_vec());
        }
    }
}

fn encode_varint<W: Write>(writer: &mut W, val: u32) -> io::Result<usize> {
    const SINGLE_BYTE_MAX: u8 = 250;
    const U16_BYTE: u8 = 251;
    const U32_BYTE: u8 = 252;

    if val <= SINGLE_BYTE_MAX as _ {
        writer.write(&[val as u8])
    } else if val <= u16::MAX as _ {
        writer.write(&[U16_BYTE])?;
        writer.write(&(val as u16).to_le_bytes()).map(|x| x + 1)
    } else {
        writer.write(&[U32_BYTE])?;
        writer.write(&val.to_le_bytes()).map(|x| x + 1)
    }
}

fn encode_slice<W: Write>(writer: &mut W, slice: &[u8]) -> io::Result<usize> {
    let len = encode_varint(writer, slice.len() as u32)?;
    writer.write_all(slice)?;
    Ok(len + slice.len())
}

fn encode_memory_patch<W: Write>(writer: &mut W, memory_patch: &MemoryPatch) -> io::Result<usize> {
    let mut len = encode_varint(writer, memory_patch.offset as u32)?;
    len += encode_slice(writer, &memory_patch.data)?;
    Ok(len)
}

fn encode_memory_patch_file<W: Write>(writer: &mut W, memory_patch_file: &MemoryPatchFile) -> io::Result<usize> {
    let mut len = encode_varint(writer, memory_patch_file.hash)?;
    len += encode_varint(writer, memory_patch_file.ranges.len() as u32)?;
    for memory_patch in memory_patch_file.ranges.iter() {
        len += encode_memory_patch(writer, memory_patch)?;
    }
    Ok(len)
}

fn decode_varint<R: Read>(reader: &mut R) -> io::Result<u32> {
    const SINGLE_BYTE_MAX: u8 = 250;
    const U16_BYTE: u8 = 251;
    const U32_BYTE: u8 = 252;

    let mut bytes = [0u8; 1];
    reader.read(&mut bytes)?;

    match bytes[0] {
        byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u32),
        U16_BYTE => {
            let mut bytes = [0u8; 2];
            reader.read(&mut bytes)?;
            Ok(u16::from_le_bytes(bytes) as u32)
        }
        U32_BYTE => {
            let mut bytes = [0u8; 4];
            reader.read(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes) as u32)
        }
        byte => panic!("Invalid byte while reading varint: {byte}"),
    }
}

fn decode_vec<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = decode_varint(reader)?;
    let mut vec = vec![0u8; len as usize];
    reader.read_exact(&mut vec)?;
    Ok(vec)
}

fn decode_memory_patch<R: Read>(reader: &mut R) -> io::Result<MemoryPatch> {
    let offset = decode_varint(reader)?;
    let data = decode_vec(reader)?;
    Ok(MemoryPatch { offset: offset as usize, data })
}

fn decode_memory_patch_file<R: Read>(reader: &mut R) -> io::Result<MemoryPatchFile> {
    let hash = decode_varint(reader)?;
    let len = decode_varint(reader)?;
    let mut ranges = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let memory_patch = decode_memory_patch(reader)?;
        ranges.push(memory_patch);
    }
    Ok(MemoryPatchFile { hash, ranges })
}

#[derive(PartialEq, Debug, Clone)]
pub struct MemoryPatch {
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct MemoryPatchFile {
    hash: u32,
    ranges: Vec<MemoryPatch>,
}

impl MemoryPatchFile {
    pub fn from_file(path: std::path::PathBuf) -> Self {
        use lz4_flex::frame::*;
        let mut decoder = FrameDecoder::new(std::fs::File::open(path).unwrap());
        let res: MemoryPatchFile = decode_memory_patch_file(&mut decoder).unwrap();
        debug!(target: "MEMSAVE", "decoded MemoryPatchFile: hash: {} # of ranges: {}", res.hash, res.ranges.len());
        res
    }

    pub fn to_file(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        use std::io::BufWriter;
        use lz4_flex::frame::*;
        let mut file = std::fs::File::create(&path)?;
        let mut writer = BufWriter::new(&mut file);
        let mut encoder = FrameEncoder::new(&mut writer);
        let len = encode_memory_patch_file(&mut encoder, self)?;
        encoder.finish()?;
        drop(writer);
        file.flush()?;
        let real_size = len as f64;
        let written = file.metadata()?.len() as f64;
        debug!(target: "MEMSAVE", "encoded MemoryPatchFile to {path:?}, size {:.1}k compressed to {:.1}k. ({:.2}%)", (real_size/1024f64), (written/1024f64), (written/real_size));
        Ok(())
    }
    pub fn merge_adjacent_ranges(&mut self) {
        fn adjacent(a: &MemoryPatch, b: &MemoryPatch) -> bool {
            a.offset + a.data.len() == b.offset
        }
        let mut done = false;
        while !done {
            let mut found = false;
            for i in 0..(self.ranges.len()-1) {
                if adjacent(&self.ranges[i], &self.ranges[i+1]) {
                    found = true;
                    let extend = std::mem::take(&mut self.ranges[i+1].data);
                    self.ranges[i+1].offset = 0xDEADC0DE;
                    self.ranges[i].data.extend(extend.iter());
                }
            }
            self.ranges.retain(|x|x.offset != 0xDEADC0DE);
            if !found { done = true; }
        }
    }
}

pub(crate) mod wrappers {
    use super::*;
    const EMBEDDED_BOOT0: &'static [u8] = include_bytes!("../../friiboot0/boot0.bin");
    #[repr(transparent)]
    pub struct Boot0(pub BigEndianMemory);
    impl Boot0 {
        pub(crate) fn new(path: &Path) -> Self {
            match BigEndianMemory::from_file(0x0000_2000, path, false) {
                Ok(x) => Self(x),
                Err(_) => {
                    log::warn!(target:"Other", "boot0.bin not detected, falling back to embedded boot0");
                    let embedded_size = EMBEDDED_BOOT0.len();
                    let mut temp = BigEndianMemory::new(0x2000);
                    temp.data[0..embedded_size].copy_from_slice(EMBEDDED_BOOT0);
                    Self(temp)
                },
            }
        }
    }
    impl Deref for Boot0 {
        type Target = BigEndianMemory;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl DerefMut for Boot0 {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
}