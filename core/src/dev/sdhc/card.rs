type ResponseLength = u8;
#[derive(Debug, Clone)]
pub struct Command {
    index: u8,
    ty: CommandType,
    data_present: bool,
    command_idx_ck: bool,
    crc_ck: bool,
    response_ty: Option<ResponseLength>,
}

impl From<u32> for Command {
    fn from(value: u32) -> Self {
            let response_ty = match value & 0b11 {
                0b00 => None,
                0b01 => Some(136),
                _ => Some(48),
            };
            Self {
                index: ((value & 0x3f00) >> 8) as u8,
                ty: CommandType::new(((value & (1<<6)) >> 6) == 1, ((value & (1<<7)) >> 7) == 1),
                data_present: ((value & (1<<5)) >> 5 == 1),
                command_idx_ck: ((value & (1<<4)) >> 5 == 1),
                crc_ck: ((value & (1<<3)) >> 5 == 1),
                response_ty,
            }
    }
}

#[derive(Debug, Clone, Copy)]
enum CommandType {
    Abort, // CMD12, CMD52 for writing I/O Abort in CCCR
    Resume, // CMD52 for writing Function Select in CCCR
    Suspend, // CMD 52 for writing Bus Suspend in CCCR
    Normal, // All other commands
}
impl CommandType {
    fn new(bit6: bool, bit7: bool) -> Self {
        match (bit6, bit7) {
            (true, true) => Self::Abort,
            (true, false) => Self::Resume,
            (false, true) => Self::Suspend,
            (false, false) => Self::Normal,
        }
    }
}


struct Card {
    state: (),
    backing_mem: Option<Vec<u8>>,
    
}