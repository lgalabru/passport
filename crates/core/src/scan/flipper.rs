//! The Flipper Zero's USB serial port, read as a stream of log lines.
//!
//! The Flipper CLI sits on the port; `log info` makes it print every
//! info-level log line, which includes the app's `scan/1` events.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use serialport::{SerialPort, SerialPortType};

use super::error::ScanError;
use super::session::LineSource;

/// USB ids of the Flipper Zero's CDC interface.
const VENDOR_ID: u16 = 0x0483;
const PRODUCT_ID: u16 = 0x5740;

/// Ctrl+C: ends `log` and hands the CLI back.
const INTERRUPT: u8 = 0x03;

/// The first Flipper port found. On macOS the `cu.` device is preferred: it
/// opens without waiting for a carrier.
pub fn find_port() -> Result<String, ScanError> {
    let ports = serialport::available_ports().map_err(|e| ScanError::Link(e.to_string()))?;
    let mut names: Vec<String> = ports
        .into_iter()
        .filter(|port| match &port.port_type {
            SerialPortType::UsbPort(usb) => {
                (usb.vid, usb.pid) == (VENDOR_ID, PRODUCT_ID)
                    || usb
                        .product
                        .as_deref()
                        .is_some_and(|p| p.to_lowercase().contains("flipper"))
            }
            _ => port.port_name.to_lowercase().contains("flip"),
        })
        .map(|port| port.port_name)
        .collect();
    names.sort_by_key(|name| !name.contains("/cu."));
    names.into_iter().next().ok_or(ScanError::NoDevice)
}

/// An open connection that streams the Flipper's log.
#[derive(Debug)]
pub struct FlipperLog {
    port: Box<dyn SerialPort>,
    lines: LineBuffer,
}

impl FlipperLog {
    /// Open `path`, or the Flipper found by [`find_port`], and start the log.
    pub fn open(path: Option<&str>) -> Result<Self, ScanError> {
        let name = match path {
            Some(path) => path.to_string(),
            None => find_port()?,
        };
        let mut port = serialport::new(&name, 230_400)
            .timeout(Duration::from_millis(50))
            .open()
            .map_err(|e| ScanError::Open {
                port: name.clone(),
                reason: e.to_string(),
            })?;
        let link = |e: std::io::Error| ScanError::Link(e.to_string());
        // A bare return wakes the prompt; then ask for the log.
        port.write_all(b"\r").map_err(link)?;
        thread::sleep(Duration::from_millis(150));
        port.write_all(b"log info\r").map_err(link)?;
        Ok(Self {
            port,
            lines: LineBuffer::default(),
        })
    }
}

impl LineSource for FlipperLog {
    fn next_line(&mut self, wait: Duration) -> Result<Option<String>, ScanError> {
        let deadline = Instant::now() + wait;
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(line) = self.lines.pop() {
                return Ok(Some(line));
            }
            match self.port.read(&mut chunk) {
                Ok(0) => {}
                Ok(n) => self.lines.push(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {}
                Err(e) => return Err(ScanError::Link(e.to_string())),
            }
            if Instant::now() >= deadline && self.lines.is_empty() {
                return Ok(None);
            }
        }
    }
}

impl Drop for FlipperLog {
    fn drop(&mut self) {
        // Best effort: leaving the log running would keep the CLI busy.
        let _ = self.port.write_all(&[INTERRUPT]);
    }
}

/// Splits a byte stream into lines, tolerating CR, LF or CRLF and lines that
/// arrive in pieces.
#[derive(Debug, Default)]
struct LineBuffer {
    partial: Vec<u8>,
    ready: VecDeque<String>,
}

impl LineBuffer {
    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' || byte == b'\r' {
                if !self.partial.is_empty() {
                    let line = String::from_utf8_lossy(&self.partial).into_owned();
                    self.ready.push_back(line);
                    self.partial.clear();
                }
            } else {
                self.partial.push(byte);
            }
        }
    }

    fn pop(&mut self) -> Option<String> {
        self.ready.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(buffer: &mut LineBuffer) -> Vec<String> {
        std::iter::from_fn(|| buffer.pop()).collect()
    }

    #[test]
    fn splits_on_any_line_ending() {
        let mut b = LineBuffer::default();
        b.push(b"one\r\ntwo\nthree\r\r\nfour\n");
        assert_eq!(drain(&mut b), ["one", "two", "three", "four"]);
    }

    #[test]
    fn joins_a_line_that_arrives_in_pieces() {
        let mut b = LineBuffer::default();
        b.push(b"scan/1 dg1 0a");
        assert!(b.is_empty());
        b.push(b"0b\r\n");
        assert_eq!(drain(&mut b), ["scan/1 dg1 0a0b"]);
    }

    #[test]
    fn bad_utf8_does_not_lose_the_line() {
        let mut b = LineBuffer::default();
        b.push(b"ok \xff\xfe end\n");
        assert_eq!(drain(&mut b), ["ok \u{fffd}\u{fffd} end"]);
    }
}
