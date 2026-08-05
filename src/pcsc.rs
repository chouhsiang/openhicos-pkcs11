//! PC/SC transport layer.

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::ffi::CString;

pub struct PcscConn {
    pub ctx: Context,
    pub card: Option<Card>,
    pub reader: String,
}

impl PcscConn {
    pub fn new() -> Result<Self, pcsc::Error> {
        Ok(Self {
            ctx: Context::establish(Scope::System)?,
            card: None,
            reader: String::new(),
        })
    }

    pub fn list_readers(&self) -> Result<Vec<String>, pcsc::Error> {
        Ok(self
            .ctx
            .list_readers_owned()?
            .into_iter()
            .filter_map(|c| c.to_str().ok().map(str::to_string))
            .collect())
    }

    pub fn connect(&mut self, reader: &str) -> Result<(), pcsc::Error> {
        self.disconnect();
        let name = CString::new(reader).map_err(|_| pcsc::Error::InvalidParameter)?;
        let card = self
            .ctx
            .connect(&name, ShareMode::Shared, Protocols::T0 | Protocols::T1)?;
        self.reader = reader.to_string();
        self.card = Some(card);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.card = None;
    }

    pub fn is_connected(&self) -> bool {
        self.card.is_some()
    }

    pub fn transmit(&self, cmd: &[u8], resp: &mut Vec<u8>) -> Result<u16, pcsc::Error> {
        let card = self.card.as_ref().ok_or(pcsc::Error::NoSmartcard)?;
        let mut rbuf = [0u8; 520];
        let mut data = card.transmit(cmd, &mut rbuf)?;
        let (mut sw1, mut sw2) = parse_sw(data);

        if sw1 == 0x6C && cmd.len() >= 5 {
            let mut retry = cmd.to_vec();
            let last = retry.len() - 1;
            retry[last] = sw2;
            data = card.transmit(&retry, &mut rbuf)?;
            (sw1, sw2) = parse_sw(data);
        }

        let mut acc = data.to_vec();
        while sw1 == 0x61 {
            let getresp = [0x00, 0xC0, 0x00, 0x00, sw2];
            let more = card.transmit(&getresp, &mut rbuf)?;
            if acc.len() >= 2 {
                acc.truncate(acc.len() - 2);
            }
            acc.extend_from_slice(more);
            (sw1, sw2) = parse_sw(&acc);
        }

        if acc.len() >= 2 {
            resp.clear();
            resp.extend_from_slice(&acc[..acc.len() - 2]);
            Ok(((sw1 as u16) << 8) | (sw2 as u16))
        } else {
            resp.clear();
            Ok(((sw1 as u16) << 8) | (sw2 as u16))
        }
    }
}

fn parse_sw(data: &[u8]) -> (u8, u8) {
    if data.len() >= 2 {
        (data[data.len() - 2], data[data.len() - 1])
    } else {
        (0, 0)
    }
}

impl Drop for PcscConn {
    fn drop(&mut self) {
        self.disconnect();
    }
}
