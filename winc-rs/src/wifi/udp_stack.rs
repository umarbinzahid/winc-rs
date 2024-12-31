use embedded_nal::UdpClientStack;

use crate::transfer::Xfer;
use crate::{Handle, WincClient};

#[derive(Debug, PartialEq)]
pub enum UdpClientError {
    SocketStorageNotSet,
    OutOfSockets,
    IPV6NotSupported,
    NotImplemented,
    SocketError,
    NoManager,
    Illegal,
}

impl<X: Xfer> UdpClientStack for WincClient<X> {
    type UdpSocket = Handle;
    type Error = UdpClientError;
    fn socket(&mut self) -> Result<Self::UdpSocket, Self::Error> {
        let s = self.get_next_session_id();
        self.udp_sockets
            .add(s)
            .map_err(|_| UdpClientError::OutOfSockets)
    }
    fn connect(
        &mut self,
        socket: &mut Self::UdpSocket,
        remote: core::net::SocketAddr,
    ) -> Result<(), Self::Error> {
        let mgr = self.manager.as_mut().ok_or(UdpClientError::NoManager)?;
        let (sh, op) = self
            .udp_sockets
            .get(*socket)
            .ok_or(UdpClientError::SocketError)?;

        // ensure network is connected
        // maybe bind ?
        match remote {
            core::net::SocketAddr::V4(addr) => {
                mgr.send_socket_connect(*sh, addr)
                    .map_err(|_| UdpClientError::SocketError)?;
                // spin here until connected or timeout
                Ok(())
            }
            _ => Err(UdpClientError::IPV6NotSupported),
        }
    }
    fn receive(
        &mut self,
        socket: &mut Self::UdpSocket,
        _buffer: &mut [u8],
    ) -> embedded_nal::nb::Result<(usize, core::net::SocketAddr), Self::Error> {
        self.spin().ok();
        let mgr = self.manager.as_mut().ok_or(UdpClientError::NoManager)?;
        let (sh, op) = self
            .udp_sockets
            .get(*socket)
            .ok_or(UdpClientError::SocketError)?;
        mgr.send_recv(*sh, 0)
            .map_err(|_| UdpClientError::SocketError)?;
        todo!()
    }
    fn send(
        &mut self,
        _socket: &mut Self::UdpSocket,
        _buffer: &[u8],
    ) -> embedded_nal::nb::Result<(), Self::Error> {
        self.spin().map_err(|_| Self::Error::Illegal)?;
        todo!()
    }
    fn close(&mut self, _socket: Self::UdpSocket) -> Result<(), Self::Error> {
        self.spin().ok();
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::PrefixXfer;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use embedded_nal::UdpClientStack;

    #[test]
    fn test_udp_stack() {
        let mut f = [0u8; 1024];
        let mut client = WincClient::from_xfer(f.as_mut_slice());

        let mut socket = client.socket().unwrap();
        let addr = core::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80);

        <WincClient<_> as UdpClientStack>::connect(&mut client, &mut socket, addr.into()).unwrap();

        let addr6 = core::net::SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 80, 0, 0);
        let res =
            <WincClient<_> as UdpClientStack>::connect(&mut client, &mut socket, addr6.into());
        assert_eq!(res, Err(UdpClientError::IPV6NotSupported));
    }
}
