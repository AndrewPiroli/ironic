use std::fmt::Debug;
use axum::{Json, extract::{Multipart, Path, State}, http::StatusCode};
use fxhash::FxHashSet;
use super::*;
use ironic_core::{bus::prim::BusWidth, cpu::mmu::prim::Access, dbg::*};
use log::error;
use serde::Deserialize;

static EMPTY_REGS: [u32;17] = [0u32;17];

pub(crate) async fn get_registers( State(state): State<DebugProxy>) -> (StatusCode, Json<[u32;17]>) {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::ReadRegs(EMPTY_REGS)).unwrap();
    let cpuregs = rx.recv().unwrap();
    if let DebugCommands::ReadRegs(cpuregs) = cpuregs {
        (StatusCode::OK, Json(cpuregs))
    }
    else {
        error!(target: "REMOTE", "get_registers fail");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(EMPTY_REGS))
    }
}

pub(crate) async fn set_registers(State(state): State<DebugProxy>, new_regs: Json<[u32;17]>) -> StatusCode {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::WriteRegs(new_regs.0)).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        error!(target:"REMOTE", "set_registers fail");
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn step(State(state): State<DebugProxy>, num: Json<u32>) -> StatusCode {
    if num.0 > 1 {
        error!(target: "REMOTE", "debugger attempted n-step, only single step is supported");
        return StatusCode::CONFLICT;
    }
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::Step(num.0)).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn resume(State(state): State<DebugProxy>) -> StatusCode {
        let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::Resume).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn interrupt(State(state): State<DebugProxy>) -> StatusCode {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::CtrlC).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn list_bkpts(State(state): State<DebugProxy>) -> (StatusCode, Json<FxHashSet<u32>>) {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::ListBreakpoints(Default::default())).unwrap();
    if let DebugCommands::ListBreakpoints(res) = rx.recv().unwrap() {
        (StatusCode::OK, Json(res))
    }
    else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(FxHashSet::default()))
    }
}

pub(crate) async fn add_bkpt(State(state): State<DebugProxy>, addr: Json<u32>) -> StatusCode {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::AddBkpt(addr.0)).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn rm_bkpt(State(state): State<DebugProxy>, addr: Json<u32>) -> StatusCode {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::RemoveBkpt(addr.0)).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn get_consoledebug(State(state): State<DebugProxy>) -> (StatusCode, Json<Option<bool>>) {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::ConsoleDebug(None)).unwrap();
    if let DebugCommands::ConsoleDebug(res) = rx.recv().unwrap() {
        (StatusCode::OK, Json(Some(res.unwrap())))
    }
    else {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
    }
}

pub(crate) async fn set_consoledebug(State(state): State<DebugProxy>, Json(set): Json<bool>) -> StatusCode {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::ConsoleDebug(Some(set))).unwrap();
    if let DebugCommands::Ack = rx.recv().unwrap() {
        StatusCode::OK
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

//unfortunate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum Width {
    B,
    H,
    W,
}
impl From<BusWidth> for Width {
    fn from(value: BusWidth) -> Self {
        match value {
            BusWidth::B => Self::B,
            BusWidth::H => Self::H,
            BusWidth::W => Self::W,
        }
    }
}
impl From<Width> for BusWidth {
    fn from(value: Width) -> BusWidth {
        match value {
            Width::B => BusWidth::B,
            Width::H => BusWidth::H,
            Width::W => BusWidth::W,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MemReadOptions {
    addr: u32,
    org: Width,
    size: u32,
}

pub(crate) async fn mem_read(State(state): State<DebugProxy>, options: Json<MemReadOptions>) -> (StatusCode, Vec<u8>) {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    tx.send(DebugCommands::Peek(options.addr, options.org.into(), Bytes(options.size))).unwrap();
    if let DebugCommands::Data(res) = rx.recv().unwrap() {
        (StatusCode::OK, res.into_vec())
    }
    else {
        (StatusCode::INTERNAL_SERVER_ERROR, Vec::with_capacity(0))
    }
}

pub(crate) async fn mem_write(State(state): State<DebugProxy>, mut mp: Multipart) -> StatusCode {
    let mut options: Option<MemReadOptions> = None;
    let mut data: Option<Vec<u8>> = None;
    while let Some(field) = mp.next_field().await.unwrap() {
        if field.name().is_some_and(|name| name == "options") {
            let fb = field.bytes().await.unwrap();
            match Json::from_bytes(&fb) {
                Ok(opts) => options = Some(opts.0),
                Err(_) => todo!(),
            }
        }
        else if field.name().is_some_and(|name| name == "data") {
            let fb = field.bytes().await.unwrap();
            data = Some(Vec::from(fb.as_ref()));
        }
    }
    if options.is_some() && data.is_some() {
        let options = options.unwrap();
        let data = data.unwrap();
        let tx = state.dbg_tx;
        let rx = state.dbg_rx;
        tx.send(DebugCommands::Poke(options.addr, options.org.into(), data.into_boxed_slice())).unwrap();
        if let DebugCommands::Ack = rx.recv().unwrap() {
            StatusCode::OK
        }
        else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
    else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

pub(crate) async fn disassmble(State(state): State<DebugProxy>, Path((ty, addr)): Path<(String, String)>) -> (StatusCode, String) {
    let tx = state.dbg_tx;
    let rx = state.dbg_rx;
    let addr = match u32::from_str_radix(&addr, 16) {
        Ok(addr) => addr,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, format!("Could not format addr: {addr} as u32\n{err}"));
        },
    };
    let arm: bool;
    match ty.to_lowercase().as_ref() {
        "thumb" => arm = false,
        "arm" => arm = true,
        "bycpsr" => {
            tx.send(DebugCommands::ReadRegs(EMPTY_REGS)).unwrap();
            let cpuregs = rx.recv().unwrap();
            if let DebugCommands::ReadRegs(cpuregs) = cpuregs {
                //          cpsr bit 5 == thumb mode
                if cpuregs[16] & (1<<5) != 0 {
                    arm = false;
                }
                else {
                    arm = true;
                }
            }
            else {
                return (StatusCode::INTERNAL_SERVER_ERROR, String::with_capacity(0));
            }
            },
        other => {return (StatusCode::BAD_REQUEST, format!("Invalid path: {other}. Try 'arm', 'thumb', or 'bycpsr'"))}
    };
    tx.send(DebugCommands::Diassemble((addr, arm))).unwrap();
    if let DebugCommands::Data(res) = rx.recv().unwrap() {
        let s = String::from_utf8(res.into()).unwrap();
        (StatusCode::OK, s)
    }
    else {
        (StatusCode::INTERNAL_SERVER_ERROR, String::with_capacity(0))
    }
}

pub(crate) async fn translate_debug(State(state): State<DebugProxy>, Path(addr): Path<String>) -> (StatusCode, String) {
    let addr = match u32::from_str_radix(&addr, 16) {
        Ok(addr) => addr,
        Err(err) => return (StatusCode::UNPROCESSABLE_ENTITY, format!("Address \'{addr}\' malformed. {err}"))
    };
    match translate_internal(&state, Access::Debug, addr) {
        Ok(paddr) => (StatusCode::OK, paddr.to_string()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(crate) async fn translate(State(state): State<DebugProxy>, Path((addr, mut access)): Path<(String, String)>) -> (StatusCode, String) {
    access.make_ascii_lowercase();
    let access = match access.as_str() {
        "read" => Access::Read,
        "write" => Access::Write,
        "debug" => Access::Debug,
        _ => return (StatusCode::UNPROCESSABLE_ENTITY, format!("Access {access} not defined. Valid access methods are Read, Write, and Debug."))
    };
    let addr = match u32::from_str_radix(&addr, 16) {
        Ok(addr) => addr,
        Err(err) => return (StatusCode::UNPROCESSABLE_ENTITY, format!("Address \'{addr}\' malformed. {err}"))
    };
    match translate_internal(&state, access, addr) {
        Ok(paddr) => (StatusCode::OK, paddr.to_string()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn translate_internal(state: &DebugProxy, access: Access, addr: u32) -> anyhow::Result<u32> {
    use anyhow::bail;
    let tx = &state.dbg_tx;
    let rx = &state.dbg_rx;
    tx.send(DebugCommands::VirtualToPhysical(access, addr)).unwrap();
    match rx.recv().unwrap() {
        DebugCommands::Fail(reason) => {
            bail!("Translation Failure: {}", reason.unwrap_or(String::from("Unknown Failure :/")))
        },
        DebugCommands::VirtualToPhysical(_, paddr) => {
            Ok(paddr)
        },
        _ => bail!("Unexpected Message from Debug Proxy")
    }
}