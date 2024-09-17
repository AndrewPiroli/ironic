use super::*;
pub struct WiFiCard {

}



impl SDHCDevice for WiFiCard {
    fn try_new() -> (Self, bool) {
        (WiFiCard{}, true)
    }

    fn issue(&mut self, _cmd: Command, _argument: u32) -> Option<Response> {
        todo!()
    }

    fn tx_status(&self) -> DeviceTXStatus {
        todo!()
    }

    fn set_tx_status(&mut self, _new: DeviceTXStatus) {
        todo!()
    }

    fn _state(&self) -> CardState {
        todo!()
    }

    fn set_state(&mut self, _new: CardState) {
        todo!()
    }

    fn data_index(&self) -> usize {
        todo!()
    }

    fn set_data_index(&self, _new: usize) {
        todo!()
    }

    fn data_stop(&self) -> usize {
        todo!()
    }

    fn set_data_stop(&mut self, _new: usize) {
        todo!()
    }

    fn lock_data(&self) -> parking_lot::MutexGuard<BigEndianMemory> {
        todo!()
    }
}