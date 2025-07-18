use core::net::SocketAddrV4;

use super::ClientSocketOp;
use super::Handle;
use super::StackError;
use super::WincClient;
use embedded_nal::UdpClientStack;
use embedded_nal::UdpFullStack;

use super::Xfer;

use crate::debug;
use crate::manager::SocketError;
use crate::stack::socket_callbacks::SendRequest;
use crate::stack::socket_callbacks::NUM_TCP_SOCKETS;
use crate::stack::socket_callbacks::{AsyncOp, AsyncState};
use embedded_nal::nb;

use crate::stack::sock_holder::SocketStore;

impl<X: Xfer> WincClient<'_, X> {
    fn send_udp_inner(
        &mut self,
        socket: &mut Handle,
        addr: SocketAddrV4,
        data: &[u8],
    ) -> nb::Result<(), StackError> {
        let res = Self::async_op(
            false,
            socket,
            &mut self.callbacks,
            &mut self.manager,
            self.poll_loop_delay_us,
            |op| matches!(op, AsyncOp::SendTo(..)),
            |sock, manager| -> Result<ClientSocketOp, StackError> {
                let to_send = data.len().min(Self::MAX_SEND_LENGTH);
                let req = SendRequest {
                    offset: 0,
                    grand_total_sent: 0,
                    total_sent: 0,
                    remaining: to_send as i16,
                };
                debug!(
                    "Sending INITIAL send_send to {:?} len:{}/{} req:{:?}",
                    sock,
                    to_send,
                    data.len(),
                    req
                );
                manager
                    .send_sendto(*sock, addr, &data[..to_send])
                    .map_err(StackError::SendSendFailed)?;
                Ok(ClientSocketOp::AsyncOp(
                    AsyncOp::SendTo(req, None),
                    AsyncState::Pending(None),
                ))
            },
            |sock, manager, _, asyncop| {
                if let AsyncOp::SendTo(req, Some(_len)) = asyncop {
                    let total_sent = req.total_sent;
                    let grand_total_sent = req.grand_total_sent + total_sent;
                    let offset = req.offset + total_sent as usize;
                    if offset >= data.len() {
                        Ok(())
                    } else {
                        let to_send = data[offset..].len().min(Self::MAX_SEND_LENGTH);
                        let new_req = SendRequest {
                            offset,
                            grand_total_sent,
                            total_sent: 0,
                            remaining: to_send as i16,
                        };
                        *asyncop = AsyncOp::SendTo(new_req, None);
                        manager
                            .send_sendto(*sock, addr, &data[offset..offset + to_send])
                            .map_err(StackError::SendSendFailed)?;
                        Err(StackError::ContinueOperation)
                    }
                } else {
                    Err(StackError::Unexpected)
                }
            },
        );
        self.test_hook();
        res
    }
}

impl<X: Xfer> UdpClientStack for WincClient<'_, X> {
    type UdpSocket = Handle;

    type Error = StackError;

    fn socket(&mut self) -> Result<Self::UdpSocket, Self::Error> {
        debug!("<> Calling new UDP socket");
        self.dispatch_events()?;
        let s = self.get_next_session_id();
        let handle = self
            .callbacks
            .udp_sockets
            .add(s)
            .ok_or(StackError::OutOfSockets)?;
        debug!("<> Got handle {:?} ", handle.0);
        Ok(handle)
    }

    // Not a blocking call
    fn connect(
        &mut self,
        socket: &mut Self::UdpSocket,
        remote: core::net::SocketAddr,
    ) -> Result<(), Self::Error> {
        self.dispatch_events()?;
        match remote {
            core::net::SocketAddr::V4(addr) => {
                debug!("<> Connect handle is {:?}", socket.0);
                let (sock, _op) = self.callbacks.udp_sockets.get(*socket).unwrap();
                self.callbacks.udp_socket_connect_addr[sock.v as usize - NUM_TCP_SOCKETS] =
                    Some(addr);
            }
            core::net::SocketAddr::V6(_) => unimplemented!("IPv6 not supported"),
        }
        Ok(())
    }

    fn send(&mut self, socket: &mut Self::UdpSocket, data: &[u8]) -> nb::Result<(), Self::Error> {
        let addr = {
            let (sock, _op) = self
                .callbacks
                .udp_sockets
                .get(*socket)
                .ok_or(StackError::SocketNotFound)?;
            self.callbacks.udp_socket_connect_addr[sock.v as usize - NUM_TCP_SOCKETS]
                .ok_or(StackError::Unexpected)?
        };
        self.send_udp_inner(socket, addr, data)
    }

    // Todo: consider consolidating this with TCP
    // Todo: Bug: If a caller passes us a very large buffer that is larger than
    // max receive buffer, this should loop through serveral packets with
    // an offset - like send does.
    fn receive(
        &mut self,
        socket: &mut Self::UdpSocket,
        buffer: &mut [u8],
    ) -> nb::Result<(usize, core::net::SocketAddr), Self::Error> {
        // Check if we have a previous operation with remaining data
        let store = &mut self.callbacks.udp_sockets;
        if let Some((_sock, op)) = store.get(*socket) {
            if let ClientSocketOp::AsyncOp(
                AsyncOp::RecvFrom(Some(ref mut recv_result)),
                AsyncState::Done,
            ) = op
            {
                if recv_result.return_offset < recv_result.recv_len {
                    let remaining_data = recv_result.recv_len - recv_result.return_offset;
                    let copy_len = remaining_data.min(buffer.len());

                    // Copy remaining data from recv_buffer
                    buffer[..copy_len].copy_from_slice(
                        &self.callbacks.recv_buffer
                            [recv_result.return_offset..recv_result.return_offset + copy_len],
                    );

                    recv_result.return_offset += copy_len;
                    let from_addr = recv_result.from_addr;

                    // Clear operation if all data consumed
                    if recv_result.return_offset >= recv_result.recv_len {
                        *op = ClientSocketOp::None;
                    }

                    self.test_hook();
                    return Ok((copy_len, core::net::SocketAddr::V4(from_addr)));
                }
            }
        }
        let mut from_addr = None;
        let res = Self::async_op(
            false,
            socket,
            &mut self.callbacks,
            &mut self.manager,
            self.poll_loop_delay_us,
            |op| matches!(op, AsyncOp::RecvFrom(..)),
            |sock, manager| -> Result<ClientSocketOp, StackError> {
                debug!("<> Sending udp socket send_recv to {:?}", sock);
                manager
                    .send_recvfrom(*sock, sock.get_recv_timeout())
                    .map_err(StackError::ReceiveFailed)?;
                Ok(ClientSocketOp::AsyncOp(
                    AsyncOp::RecvFrom(None),
                    AsyncState::Pending(None),
                ))
            },
            |sock, manager, recv_buffer, asyncop| {
                if let AsyncOp::RecvFrom(Some(ref mut recv_result)) = asyncop {
                    match recv_result.error {
                        SocketError::NoError => {
                            let recv_len = recv_result.recv_len;
                            from_addr = Some(recv_result.from_addr);
                            if recv_len == 0 {
                                Ok(0)
                            } else {
                                let copy_len = recv_len.min(buffer.len());
                                let dest_slice = &mut buffer[..copy_len];
                                dest_slice.copy_from_slice(&recv_buffer[..copy_len]);
                                recv_result.return_offset = copy_len;
                                if copy_len < recv_len {
                                    debug!(
                                        "Partial read: returned {} of {} bytes, {} remaining",
                                        copy_len,
                                        recv_len,
                                        recv_len - copy_len
                                    );
                                } else {
                                    debug!("Complete read: returned all {} bytes", recv_len);
                                }
                                Ok(copy_len)
                            }
                        }
                        SocketError::Timeout => {
                            debug!("Timeout on receive, re-sending receive command");
                            manager
                                .send_recvfrom(*sock, sock.get_recv_timeout())
                                .map_err(StackError::ReceiveFailed)?;
                            Err(StackError::ContinueOperation)
                        }
                        _ => {
                            debug!("Error in receive: {:?}", recv_result.error);
                            Err(StackError::OpFailed(recv_result.error))
                        }
                    }
                } else {
                    Err(StackError::Unexpected)
                }
            },
        );
        self.test_hook();
        match res {
            Ok(len) => {
                if let Some(addr) = from_addr {
                    Ok((len, core::net::SocketAddr::V4(addr)))
                } else {
                    Err(nb::Error::WouldBlock)
                }
            }
            Err(nb::Error::Other(StackError::ContinueOperation)) => Err(nb::Error::WouldBlock),
            Err(nb::Error::Other(e)) => Err(nb::Error::Other(e)),
            Err(nb::Error::WouldBlock) => Err(nb::Error::WouldBlock),
        }
    }

    // Not a blocking call
    fn close(&mut self, socket: Self::UdpSocket) -> Result<(), Self::Error> {
        self.dispatch_events()?;
        let (sock, _op) = self.callbacks.udp_sockets.get(socket).unwrap();
        let sock_id = sock.v;
        self.manager
            .send_close(*sock)
            .map_err(StackError::SendCloseFailed)?;
        self.callbacks
            .udp_sockets
            .get(socket)
            .ok_or(StackError::CloseFailed)?;
        self.callbacks.udp_sockets.remove(socket);
        // clear send addresses
        self.callbacks.udp_socket_connect_addr[sock_id as usize - NUM_TCP_SOCKETS] = None;
        Ok(())
    }
}

impl<X: Xfer> UdpFullStack for WincClient<'_, X> {
    // Not a blocking call
    fn bind(&mut self, socket: &mut Self::UdpSocket, local_port: u16) -> Result<(), Self::Error> {
        // Local server ports needs to be bound to 0.0.0.0
        let server_addr =
            core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(0, 0, 0, 0), local_port);
        let (sock, op) = self.callbacks.udp_sockets.get(*socket).unwrap();
        *op = ClientSocketOp::Bind(None);
        debug!("<> Sending UDP socket bind to {:?}", sock);
        self.manager
            .send_bind(*sock, server_addr)
            .map_err(StackError::BindFailed)?;
        self.wait_with_timeout(Self::BIND_TIMEOUT, |client, _| {
            let (_, op) = client.callbacks.udp_sockets.get(*socket).unwrap();
            let res = match op {
                ClientSocketOp::Bind(Some(bind_result)) => match bind_result.error {
                    SocketError::NoError => Some(Ok(())),
                    _ => Some(Err(StackError::OpFailed(bind_result.error))),
                },
                _ => None,
            };
            if res.is_some() {
                *op = ClientSocketOp::None;
            }
            res
        })
    }

    // Todo: Reduce copy-paste between send and send_to implementations
    fn send_to(
        &mut self,
        socket: &mut Self::UdpSocket,
        remote: core::net::SocketAddr,
        data: &[u8],
    ) -> nb::Result<(), Self::Error> {
        let addr = match remote {
            core::net::SocketAddr::V4(addr) => addr,
            core::net::SocketAddr::V6(_) => unimplemented!("IPv6 not supported"),
        };
        self.send_udp_inner(socket, addr, data)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::client::{self, test_shared::*};
    use crate::{client::SocketCallbacks, manager::EventListener, socket::Socket};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use embedded_nal::{UdpClientStack, UdpFullStack};

    #[test]
    fn test_udp_socket_open() {
        let mut client = make_test_client();
        let udp_socket = client.socket();
        assert!(udp_socket.is_ok());
    }

    #[test]
    fn test_udp_connect() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();

        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);

        let result = client.connect(&mut udp_socket, socket_addr);

        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_udp_connect_v6_failure() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();

        let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 80);

        let _ = client.connect(&mut udp_socket, socket_addr);
    }

    #[test]
    fn test_udp_send() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let packet = "Hello, World";
        let valid_len: i16 = client::WincClient::<'_, MockTransfer>::MAX_SEND_LENGTH as i16;

        // Connect to address
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let result = client.connect(&mut udp_socket, socket_addr);
        assert!(result.is_ok());

        // set callback
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_send_to(Socket::new(7, 0), valid_len as i16);
        };
        client.debug_callback = Some(&mut my_debug);

        // call send
        let result = nb::block!(client.send(&mut udp_socket, packet.as_bytes()));

        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn test_udp_receive() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let _ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let socket_addr_v4 = SocketAddrV4::new(_ipv4, 80);
        let mut recv_buff = [0u8; 32];
        let test_data = "Hello, World".as_bytes();

        // Connect to address
        let socket_addr = SocketAddr::new(IpAddr::V4(_ipv4), 80);
        let result = client.connect(&mut udp_socket, socket_addr);
        assert!(result.is_ok());

        // set callback
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_recvfrom(
                Socket::new(7, 0),
                socket_addr_v4,
                &test_data,
                SocketError::NoError,
            );
        };

        client.debug_callback = Some(&mut my_debug);

        // call receive
        let result = nb::block!(client.receive(&mut udp_socket, &mut recv_buff));

        assert_eq!(result.ok(), Some((test_data.len(), socket_addr)));
        assert_eq!(&recv_buff[..test_data.len()], test_data);
    }

    #[test]
    fn test_udp_close() {
        let mut client = make_test_client();
        let udp_socket = client.socket().unwrap();

        let result = client.close(udp_socket);

        assert!(result.is_ok());
    }

    #[test]
    fn test_udp_bind() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();

        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_bind(Socket::new(7, 0), SocketError::NoError);
        };

        client.debug_callback = Some(&mut my_debug);

        let result = client.bind(&mut udp_socket, 8080);

        assert!(result.is_ok());
    }

    #[test]
    fn test_udp_send_to() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let packet = "Hello, World";
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);

        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_send_to(Socket::new(7, 0), packet.len() as i16);
        };
        client.debug_callback = Some(&mut my_debug);

        let result = nb::block!(client.send_to(&mut udp_socket, socket_addr, packet.as_bytes()));

        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn test_udp_check_max_send_buffer() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let packet = "Hello, World";
        let socket = Socket::new(7, 0);
        let valid_len: i16 = client::WincClient::<'_, MockTransfer>::MAX_SEND_LENGTH as i16;

        // Connect to address
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let result = client.connect(&mut udp_socket, socket_addr);
        assert!(result.is_ok());

        // set callback
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_send_to(socket, valid_len);
        };
        client.debug_callback = Some(&mut my_debug);

        // call send
        let result = client.send(&mut udp_socket, packet.as_bytes());

        assert_eq!(result, Err(nb::Error::WouldBlock));

        if let Some((_, ClientSocketOp::AsyncOp(AsyncOp::SendTo(req, _), _))) =
            client.callbacks.resolve(socket)
        {
            assert!((req.total_sent == valid_len) && (req.remaining == 0 as i16));
        } else {
            assert!(false, "Expected Some value, but it returned None");
        }
    }

    #[test]
    fn test_udp_check_receive_timeout() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let _ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let socket_addr_v4 = SocketAddrV4::new(_ipv4, 80);
        let mut recv_buff = [0u8; 32];
        let mut counter = 5;

        // Connect to address
        let socket_addr = SocketAddr::new(IpAddr::V4(_ipv4), 80);
        let result = client.connect(&mut udp_socket, socket_addr);
        assert!(result.is_ok());

        // set callback
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_recvfrom(Socket::new(7, 0), socket_addr_v4, &[], SocketError::Timeout);
        };

        client.debug_callback = Some(&mut my_debug);

        while counter != 0 {
            // call receive
            let result = client.receive(&mut udp_socket, &mut recv_buff);

            assert_eq!(result.err(), Some(nb::Error::WouldBlock));
            counter -= 1;
        }
    }

    #[test]
    #[should_panic]
    fn test_udp_check_send_to_ipv6() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let packet = "Hello, World";
        let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 80);

        let _ = nb::block!(client.send_to(&mut udp_socket, socket_addr, packet.as_bytes()));
    }

    #[test]
    fn test_udp_check_bind_err() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();

        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_bind(Socket::new(7, 0), SocketError::MaxUdpSock);
        };

        client.debug_callback = Some(&mut my_debug);

        let result = client.bind(&mut udp_socket, 8080);

        assert!(result.is_err());
    }

    #[test]
    fn test_udp_check_receive_err() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let _ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let socket_addr_v4 = SocketAddrV4::new(_ipv4, 80);
        let mut recv_buff = [0u8; 32];

        // Connect to address
        let socket_addr = SocketAddr::new(IpAddr::V4(_ipv4), 80);
        let result = client.connect(&mut udp_socket, socket_addr);
        assert!(result.is_ok());

        // set callback
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_recvfrom(
                Socket::new(7, 0),
                socket_addr_v4,
                &[],
                SocketError::InvalidAddress,
            );
        };

        client.debug_callback = Some(&mut my_debug);

        // call receive
        let result = nb::block!(client.receive(&mut udp_socket, &mut recv_buff));

        assert!(result.is_err());
    }

    #[test]
    fn test_udp_large_payload_receive() {
        let mut client = make_test_client();
        let mut udp_socket = client.socket().unwrap();
        let socket_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80);
        let mut recv_buffer = [0u8; 256]; // Small caller buffer

        // Large packet from SPI - 1024 bytes, all 0xAA
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_recvfrom(
                Socket::new(7, 0),
                socket_addr,
                &[0xAA; 1024], // Large packet from SPI
                SocketError::NoError,
            );
        };
        client.debug_callback = Some(&mut my_debug);

        // First read should return 256 bytes (partial)
        let first_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(first_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0xAA));

        // Second read should return next 256 bytes (partial)
        let second_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(second_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0xAA));

        // Third read should return next 256 bytes (partial)
        let third_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(third_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0xAA));

        // Fourth read should return remaining 256 bytes (complete)
        let fourth_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(fourth_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0xAA));

        // Fifth read should initiate a new packet - different pattern
        let mut my_debug = |callbacks: &mut SocketCallbacks| {
            callbacks.on_recvfrom(
                Socket::new(7, 0),
                socket_addr,
                &[0x55; 512], // Smaller large packet
                SocketError::NoError,
            );
        };
        client.debug_callback = Some(&mut my_debug);

        let fifth_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(fifth_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0x55));

        // Sixth read should return remaining 256 bytes
        let sixth_read = nb::block!(client.receive(&mut udp_socket, &mut recv_buffer)).unwrap();
        assert_eq!(sixth_read, (256, core::net::SocketAddr::V4(socket_addr)));
        assert!(recv_buffer.iter().all(|&x| x == 0x55));
    }

    #[test]
    fn partial_receive_full_test() {
        // Test case 1: 10KB data, small SPI buffer (31 bytes), large receiver buffer (1400 bytes)
        // This tests the scenario where SPI delivers small chunks but app has large buffers
        run_udp_partial_read_test(10240, 31, 1400);

        // Test case 2: 10KB data, small SPI buffer (100 bytes), small receiver buffer (100 bytes)
        // This tests equal sized buffers under the builtin buffer sizes
        run_udp_partial_read_test(10240, 100, 100);

        // Test case 3: 10KB data, equal SPI and receiver buffers (64 bytes)
        // Another equal size test with smaller buffers
        run_udp_partial_read_test(10240, 64, 64);

        // Test case 4: 10KB data, large SPI buffer (1024 bytes), small receiver buffer (31 bytes)
        // This tests large SPI chunks but tiny app reads
        run_udp_partial_read_test(10240, 1024, 31);

        // Test case 5: 10KB data, large SPI buffer (1024 bytes), small receiver buffer (100 bytes)
        // Large SPI with medium app reads
        run_udp_partial_read_test(10240, 1024, 100);

        // Test case 6: 10KB data, equal larger buffers (1024 bytes each)
        // This tests equal sized large buffers
        run_udp_partial_read_test(10240, 1024, 1024);

        // Test case 7: 10KB data, equal large buffers (1400 bytes each - near MTU limit)
        // This tests the largest practical equal buffer sizes
        run_udp_partial_read_test(10240, 1400, 1400);

        // Test case 8: Edge case - tiny data, large buffers
        run_udp_partial_read_test(64, 1024, 1400);

        // Test case 9: Edge case - data that doesn't align with 4-byte boundaries nicely
        run_udp_partial_read_test(9996, 97, 131); // Non-round numbers to test edge cases
    }

    fn run_udp_partial_read_test(
        total_size: usize,
        spi_chunk_size: usize,
        receive_buffer_size: usize,
    ) {
        let mut client = make_test_client();
        let mut socket_handle = client.socket().unwrap();
        let socket_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80);

        // Prepare test data pattern
        let mut source_data = [0u8; 10240];
        assert!(total_size <= source_data.len());
        let source_slice = &mut source_data[0..total_size];
        crate::client::tests::generate_test_pattern(source_slice);
        let expected_checksum = crate::client::tests::compute_crc16(source_slice);

        // Storage for received data
        let mut received_data = [0u8; 10240];
        let mut app_receive_buffer = [0u8; 1400];
        assert!(receive_buffer_size <= app_receive_buffer.len());

        // Start the initial receive call to put socket in pending state
        let initial_result = client.receive(
            &mut socket_handle,
            &mut app_receive_buffer[0..receive_buffer_size],
        );
        assert_eq!(initial_result, Err(nb::Error::WouldBlock));

        let mut total_bytes_received = 0;
        let mut spi_offset = 0;

        // Simulate SPI data arriving in chunks
        while spi_offset < total_size {
            let chunk_end = (spi_offset + spi_chunk_size).min(total_size);
            let chunk = &source_slice[spi_offset..chunk_end];

            // Copy chunk to internal buffer and trigger callback
            client.callbacks.recv_buffer[..chunk.len()].copy_from_slice(chunk);
            client.callbacks.on_recvfrom(
                Socket::new(7, 0), // UDP uses socket ID 7,0
                socket_addr,
                chunk,
                SocketError::NoError,
            );

            spi_offset = chunk_end;

            // Read all available data with the specified receiver buffer size
            loop {
                let receive_slice = &mut app_receive_buffer[0..receive_buffer_size];
                let read_result = client.receive(&mut socket_handle, receive_slice);

                match read_result {
                    Ok((bytes_read, addr)) => {
                        if bytes_read == 0 {
                            break; // No more data from this SPI chunk
                        }

                        // Verify the address matches
                        assert_eq!(addr, core::net::SocketAddr::V4(socket_addr));

                        // Copy received data to our accumulator
                        received_data[total_bytes_received..total_bytes_received + bytes_read]
                            .copy_from_slice(&receive_slice[0..bytes_read]);
                        total_bytes_received += bytes_read;
                    }
                    Err(nb::Error::WouldBlock) => {
                        break; // Need more SPI data
                    }
                    Err(e) => {
                        panic!("Unexpected error: {:?}", e);
                    }
                }
            }
        }

        // Verify all data was received correctly
        assert_eq!(
            total_bytes_received, total_size,
            "Total bytes received {} != expected {} (SPI: {}, RX: {})",
            total_bytes_received, total_size, spi_chunk_size, receive_buffer_size
        );

        let received_slice = &received_data[0..total_size];
        let actual_checksum = crate::client::tests::compute_crc16(received_slice);
        assert_eq!(
            actual_checksum, expected_checksum,
            "Checksum mismatch! (SPI: {}, RX: {})",
            spi_chunk_size, receive_buffer_size
        );

        assert_eq!(
            received_slice, source_slice,
            "Data content mismatch! (SPI: {}, RX: {})",
            spi_chunk_size, receive_buffer_size
        );
    }
}
