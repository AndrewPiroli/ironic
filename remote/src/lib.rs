#![deny(unsafe_op_in_unsafe_fn)]
#![feature(mpmc_channel)]

use std::net::IpAddr;
use ironic_core::dbg::DebugProxy;
use tokio::net::TcpListener;
use axum::{Router, routing::{get, put, post}};

mod bridge;

#[derive(Debug, Clone)]
pub struct ServerOptions {
    listenaddr: (IpAddr, u16),
    proxy: DebugProxy,
}
impl ServerOptions {
    pub fn new(listenaddr: (IpAddr, u16), proxy: DebugProxy) -> Self {
        Self { listenaddr, proxy }
    }
    pub fn start(self) {
        use tokio::runtime::Builder;
        let rt = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("tokio Runtime Builer");
        rt.block_on(async {
            let l = TcpListener::bind(self.listenaddr).await.unwrap();
            let app = Router::new()
            .route("/registers", get(bridge::get_registers))
            .route("/registers", put(bridge::set_registers))
            .route("/step", post(bridge::step))
            .route("/resume", post(bridge::resume))
            .route("/break", post(bridge::interrupt))
            .route("/breakpoints", get(bridge::list_bkpts))
            .route("/breakpoints/add", post(bridge::add_bkpt))
            .route("/breakpoints/remove", post(bridge::rm_bkpt))
            .route("/mem/read", post(bridge::mem_read))
            .route("/mem/write", post(bridge::mem_write))
            .route("/disassemble/{ty}/{addr}", get(bridge::disassmble))
            .route("/consoledbg", get(bridge::get_consoledebug))
            .route("/consoledbg", put(bridge::set_consoledebug))
            .route("/translate/{addr}", get(bridge::translate_debug))
            .route("/translate/{addr}/{access}", get(bridge::translate))
            .with_state(self.proxy);
            axum::serve(l, app).await.unwrap();
        });
    }
}