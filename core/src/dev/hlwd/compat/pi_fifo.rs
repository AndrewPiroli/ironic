use anyhow::bail;
use log::debug;

use crate::bus::Bus;
use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;

/// Processor Interface FIFO
///
/// PPC does 32-byte (not bit) DMA bursts (usually, but not always, from
/// the write-gather pipe) into this region, and we write it into memory.
/// The GX CP may also (and usually does, but not always) consume this data.
#[derive(Default, Debug, Clone)]
pub struct ProcessorInterfaceFIFO;

impl MmioDevice for ProcessorInterfaceFIFO {
    type Width = [u8; 32];
    fn read(&self, _access: AccessContext, _off: usize) -> anyhow::Result<BusPacket> {
        bail!("FIFO is write-only");
    }
    fn write(&mut self, _access: AccessContext, _off: usize, val: [u8; 32]) -> anyhow::Result<Option<BusTask>> {
        Ok(Some(BusTask::PiFifo(val)))
    }
}

impl Bus {
    /// Deliver a completed 32-byte burst from the bus: write it into memory
    /// at the PI FIFO write pointer, then advance that pointer by 32B.
    pub fn handle_task_pi_fifo(&mut self, burst: [u8; 32]) -> anyhow::Result<()> {
        let wr_ptr = self.hlwd.pi.fifo_cur_write_ptr;
        self.dma_write(Requester::Soc, wr_ptr, &burst)?;

        let mut next_ptr = wr_ptr.wrapping_add(32);
        if next_ptr > self.hlwd.pi.fifo_base_end {
            next_ptr = self.hlwd.pi.fifo_base_start;
        }
        self.hlwd.pi.fifo_cur_write_ptr = next_ptr;
        debug!(target: "WGP", "Wrote 32B burst to {wr_ptr:08x}, new write ptr {next_ptr:08x}");

        let cr = self.hlwd.gx.cp.cr;
        // GPReadEnable and GPLinkEnable must both be set for CP to track this
        // burst, the PI FIFO is authoritative for where the burst actually
        // lands, but the CP's own write pointer wraps independently against
        // its own base/end registers, not PI's.
        if cr & 0x11 == 0x11 {
            let gx = &mut self.hlwd.gx;
            gx.cp.fifo_wr_ptr = if gx.cp.fifo_wr_ptr.wrapping_add(32) > gx.cp.fifo_end {
                gx.cp.fifo_base
            } else {
                gx.cp.fifo_wr_ptr.wrapping_add(32)
            };
            gx.cp.fifo_rw_distance = gx.cp.fifo_rw_distance.wrapping_add(32);

            // The CP is enabled: consume whatever is now available
            self.gx_process_fifo()?;
        }

        Ok(())
    }
}
