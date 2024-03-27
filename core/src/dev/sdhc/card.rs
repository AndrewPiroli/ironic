// type ResponseLength = u8;
#[derive(Debug, Clone)]
pub struct Command {
    pub index: u8,
    ty: CommandType,
    data_present: bool,
    // command_idx_ck: bool,
    // crc_ck: bool,
    response: bool,
}

impl From<u32> for Command {
    fn from(value: u32) -> Self {
            Self {
                index: ((value & 0x3f00) >> 8) as u8,
                ty: CommandType::new(((value & (1<<6)) >> 6) == 1, ((value & (1<<7)) >> 7) == 1),
                data_present: ((value & (1<<5)) >> 5 == 1),
                // command_idx_ck: ((value & (1<<4)) >> 5 == 1),
                // crc_ck: ((value & (1<<3)) >> 5 == 1),
                response: value & 0b11 != 0,
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

#[derive(Debug, Default)]
pub(super) struct Card {
    state: CardState,
    backing_mem: Option<Vec<u8>>,
    acmd: bool,
}

impl Card {
    pub(super) fn issue(&mut self, cmd: Command, argument: u32) -> Option<Response> {
        let acmd = std::mem::replace(&mut self.acmd, false);
        match (acmd, cmd.index) {
            (false, 0) => { return Some(self.cmd0(argument)); }
            (false, 8) => {
                return Some(self.cmd8(argument));
            },
            (_, 55) => {
                self.acmd = true;
                return Some(Response::Regular(0));
            }
            _ => unimplemented!(),
        }
    }
    fn cmd8(&mut self, argument: u32) -> Response {
        // CMD8 echo back in response
        Response::Regular(argument & 0xfff)
    }
    fn cmd0(&mut self, _argument: u32) -> Response {
        self.state = CardState::Idle;
        Response::Regular(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
// The card response.
// Different types are for mapping the Part 1 response field bits to Part 2 Response Register bits
pub(super) enum Response {
    Regular(u32), // R1, R3, R4, R5, R6, R7. Part 1 [39:8] to Part 2 [31:0]
    AutoCMD12(u32), // Part 1 [39:8] to Part 2 [127:96]
    R2(u128), // Part 1 [127:8] to Part 2 [119:0]
}

#[derive(Debug)]
enum CardState {
    Idle,
}
impl Default for CardState {
    fn default() -> Self {
        Self::Idle
    }
}