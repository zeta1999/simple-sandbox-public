//! Thin supervisor control-channel helpers built on `simple_network` TCP transport.
//!
//! Full PQC sessions can opt into `simple_network`'s `pqc` feature later.

use std::net::SocketAddr;

use simple_network::transport::tcp::TcpTransport;
use simple_network::transport::traits::{Connection, Listener, Transport};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control channel: {0}")]
    Message(String),
}

/// Placeholder for a supervisor↔helper link using simple_network TCP.
pub struct ControlChannel {
    listener: Box<dyn Listener>,
    addr: SocketAddr,
}

impl ControlChannel {
    pub async fn bind(addr: &str) -> Result<Self, ControlError> {
        let transport = TcpTransport;
        let listener = transport
            .bind(addr)
            .await
            .map_err(|e| ControlError::Message(e.to_string()))?;
        let addr = listener
            .local_addr()
            .map_err(|e| ControlError::Message(e.to_string()))?;
        Ok(Self { listener, addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn accept(&mut self) -> Result<Box<dyn Connection>, ControlError> {
        self.listener
            .accept()
            .await
            .map_err(|e| ControlError::Message(e.to_string()))
    }

    pub async fn connect(addr: &str) -> Result<Box<dyn Connection>, ControlError> {
        TcpTransport
            .connect(addr)
            .await
            .map_err(|e| ControlError::Message(e.to_string()))
    }
}
