// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{WincClient, Xfer};
use crate::error;
use crate::manager::{Manager, SOCKET_BUFFER_MAX_LENGTH};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

pub struct WincTxToken<'a, X: Xfer> {
    client: Option<&'a mut Manager<X>>,
}

pub struct WincRxToken<'a> {
    buffer: &'a mut [u8],
}

impl<X: Xfer> phy::Device for WincClient<'_, X> {
    type RxToken<'a>
        = WincRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = WincTxToken<'a, X>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let result = self
            .manager
            .recv_ethernet_packet(&mut self.callbacks.recv_buffer);

        if result.is_err() {
            error!("Error occurred while recieving ethernet packet.");
            self.callbacks.recv_buffer.fill(0);
            return None;
        }

        let rx_token = WincRxToken {
            buffer: &mut self.callbacks.recv_buffer,
        };

        let tx_token = WincTxToken { client: None };
        return Some((rx_token, tx_token));
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let tx_token = WincTxToken {
            client: Some(&mut self.manager),
        };
        Some(tx_token)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = SOCKET_BUFFER_MAX_LENGTH;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }
}

impl<'a> phy::RxToken for WincRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(self.buffer);
        result
    }
}

impl<'a, X: Xfer> phy::TxToken for WincTxToken<'a, X> {
    fn consume<R, F>(self, _len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut tx_buffer = [0u8; SOCKET_BUFFER_MAX_LENGTH];
        let result = f(&mut tx_buffer);

        if let Some(manager) = self.client {
            let _ = manager.send_ethernet_packet(&tx_buffer);
        } else {
            error!("No client availble to send the packet.");
        }

        result
    }
}
