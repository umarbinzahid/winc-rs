use wincwifi::manager::EventListener;
use wincwifi::manager::SocketError;
use wincwifi::Ipv4AddrFormatWrapper;
use wincwifi::Socket;

use wincwifi::SockHolder;

use wincwifi::wifi::errors;
use wincwifi::{ClientSocketOp, Handle};

mod stack_error;
pub use stack_error::StackError;

mod udp_stack;
mod tcp_stack;

struct SocketCallbacks {
    // #define TCP_SOCK_MAX										(7)
    // indexes 0-6
    tcp_sockets: SockHolder<7, 0>,
    // #define UDP_SOCK_MAX										4
    udp_sockets: SockHolder<4, 7>,
    recv_buffer: [u8; wincwifi::manager::SOCKET_BUFFER_MAX_LENGTH],
    recv_len: usize,
    // Todo: move this into socket
    last_error: SocketError,
    last_recv_addr: Option<wincwifi::SocketAddrV4>,
}

impl SocketCallbacks {
    pub fn new() -> Self {
        Self {
            tcp_sockets: SockHolder::new(),
            udp_sockets: SockHolder::new(),
            recv_buffer: [0; wincwifi::manager::SOCKET_BUFFER_MAX_LENGTH],
            recv_len: 0,
            last_error: SocketError::NoError,
            last_recv_addr: None,
        }
    }
    fn resolve(&mut self, socket: Socket) -> Option<&mut (Socket, ClientSocketOp)> {
        if socket.v < 7 {
            defmt::debug!("resolving tcp: {:?}", socket.v);
            self.tcp_sockets.get(Handle(socket.v))
        } else {
            defmt::debug!("resolving udp: {:?}", socket.v);
            self.udp_sockets.get(Handle(socket.v - 7))
        }
    }
}

impl EventListener for SocketCallbacks {
    fn on_dhcp(&mut self, conf: wincwifi::manager::IPConf) {
        defmt::debug!("on_dhcp: IP config: {}", conf);
    }
    fn on_connect(&mut self, socket: Socket, err: SocketError) {
        defmt::debug!("on_connect: socket {:?}", socket);

        if let Some((s, op)) = self.resolve(socket) {
            if *op == ClientSocketOp::Connect {
                defmt::debug!("on_connect: socket:{:?} error:{:?}", s, err);
                *op = ClientSocketOp::None;
                self.last_error = err;
            } else {
                defmt::error!(
                    "UNKNOWN STATE on_connect (x): socket:{:?} error:{:?} state:{:?}",
                    s,
                    err,
                    *op
                );
            }
        } else {
            defmt::error!(
                "on_connect (x): COULD NOT FIND SOCKET socket:{:?} error:{:?}",
                socket,
                err
            );
        }
    }
    fn on_send_to(&mut self, socket: Socket, len: i16) {
        defmt::debug!("on_send_to: socket:{:?} length:{:?}", socket, len);
        if let Some((s, op)) = self.resolve(socket) {
            if *op == ClientSocketOp::SendTo {
                defmt::debug!("on_send_to: socket:{:?} length:{:?}", socket, len);
                *op = ClientSocketOp::None;
            } else {
                defmt::error!(
                    "UNKNOWN STATE on_send_to (x): socket:{:?} len:{:?} state:{:?}",
                    s,
                    len,
                    *op
                );
            }
        } else {
            defmt::error!(
                "UNKNOWN STATE on_send_to (x): socket:{:?} len:{:?}",
                socket,
                len
            );
        }
    }
    fn on_send(&mut self, socket: Socket, len: i16) {
        defmt::debug!("on_send: socket {:?}", socket);

        if let Some((s, op)) = self.resolve(socket) {
            if *op == ClientSocketOp::Send {
                defmt::debug!("on_send: socket:{:?} length:{:?}", socket, len);
                *op = ClientSocketOp::None;
            } else {
                defmt::error!(
                    "UNKNOWN STATE on_send (x): socket:{:?} len:{:?} state:{:?}",
                    s,
                    len,
                    *op
                );
            }
        } else {
            defmt::error!(
                "on_send (x): COULD NOT FIND SOCKET socket:{:?} len:{:?}",
                socket,
                len
            );
        }
    }
    fn on_recv(
        &mut self,
        socket: Socket,
        address: wincwifi::SocketAddrV4,
        data: &[u8],
        err: SocketError,
    ) {
        defmt::debug!("on_recv: socket {:?}", socket);
        let mut found = false;
        if let Some((s, op)) = self.resolve(socket) {
            if *op == ClientSocketOp::Recv {
                defmt::debug!(
                    "on_recv: socket:{:?} address:{:?} data:{:?} error:{:?}",
                    s,
                    Ipv4AddrFormatWrapper::new(address.ip()),
                    data,
                    err
                );
                *op = ClientSocketOp::None;
                found = true;
            } else {
                defmt::error!(
                    "UNKNOWN on_recv: socket:{:?} address:{:?} port:{:?} data:{:?} error:{:?}",
                    socket,
                    Ipv4AddrFormatWrapper::new(address.ip()),
                    address.port(),
                    data,
                    err
                );
            }
        } else {
            defmt::error!(
                "UNKNOWN on_recv: socket:{:?} address:{:?} port:{:?} data:{:?} error:{:?}",
                socket,
                Ipv4AddrFormatWrapper::new(address.ip()),
                address.port(),
                data,
                err
            );
        }
        if found {
            self.recv_buffer[..data.len()].copy_from_slice(data);
            self.recv_len = data.len();
            self.last_error = err;
        }
    }
    fn on_recvfrom(
        &mut self,
        socket: Socket,
        address: wincwifi::SocketAddrV4,
        data: &[u8],
        err: SocketError,
    ) {
        defmt::debug!("on_recvfrom: socket {:?}", socket);
        let mut found = false;
        if let Some((s, op)) = self.resolve(socket) {
            if *op == ClientSocketOp::RecvFrom {
                defmt::debug!(
                    "on_recvfrom: socket:{:?} address:{:?} data:{:?} error:{:?}",
                    s,
                    Ipv4AddrFormatWrapper::new(address.ip()),
                    data,
                    err
                );
                *op = ClientSocketOp::None;
                self.last_error = err;
                found = true;
            } else {
                defmt::error!(
                    "UNKNOWN on_recvfrom: socket:{:?} address:{:?} data:{:?} error:{:?}",
                    socket,
                    Ipv4AddrFormatWrapper::new(address.ip()),
                    data,
                    err
                );
            }
        } else {
            defmt::error!(
                "UNKNOWN on_recvfrom: socket:{:?} address:{:?} data:{:?} error:{:?}",
                socket,
                Ipv4AddrFormatWrapper::new(address.ip()),
                data,
                err
            );
        }
        if found {
            self.recv_buffer[..data.len()].copy_from_slice(data);
            self.recv_len = data.len();
            self.last_error = err;
            self.last_recv_addr = Some(address);
        }
    }
    fn on_system_time(&mut self, year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) {
        defmt::debug!(
            "on_system_time: {}-{:02}-{:02} {:02}:{:02}:{:02}",
            year,
            month,
            day,
            hour,
            minute,
            second
        );
    }
}

pub struct WincClient<'a, X: wincwifi::transfer::Xfer, E: EventListener> {
    manager: wincwifi::manager::Manager<X, E>,
    delay: &'a mut dyn FnMut(u32) -> (),
    recv_timeout: u32,
    poll_loop_delay: u32,
    callbacks: SocketCallbacks,
    next_session_id: u16,
    // TODO: Lets change that per socket
    last_send_addr: Option<wincwifi::SocketAddrV4>,
}

impl<'a, X: wincwifi::transfer::Xfer, E: EventListener> WincClient<'a, X, E> {
    const SEND_TIMEOUT: u32 = 1000;
    const RECV_TIMEOUT: u32 = 1000;
    const CONNECT_TIMEOUT: u32 = 1000;
    const POLL_LOOP_DELAY: u32 = 100;
    pub fn new(manager: wincwifi::manager::Manager<X, E>, delay: &'a mut impl FnMut(u32)) -> Self {
        Self {
            manager,
            callbacks: SocketCallbacks::new(),
            delay,
            recv_timeout: Self::RECV_TIMEOUT,
            poll_loop_delay: Self::POLL_LOOP_DELAY,
            next_session_id: 0,
            last_send_addr: None,
        }
    }
    pub fn get_next_session_id(&mut self) -> u16 {
        let ret = self.next_session_id;
        self.next_session_id += 1;
        ret
    }
    pub fn dispatch_events(&mut self) -> Result<(), StackError> {
        self.manager
            .dispatch_events_new(&mut self.callbacks)
            .map_err(|some_err| StackError::DispatchError(some_err))
    }
    // What could possibly go wrong in this wait ?
    fn wait_for_op_ack(
        &mut self,
        handle: Handle,
        expect_op: ClientSocketOp,
        timeout: u32,
        tcp: bool, // todo: this is ugly
    ) -> Result<usize, StackError> {
        self.dispatch_events()?;
        let mut timeout = timeout as i32;
        defmt::debug!("===>Waiting for op ack for {:?}", expect_op);
        loop {
            if timeout <= 0 {
                return match expect_op {
                    ClientSocketOp::Connect => return Err(StackError::ConnectTimeout),
                    ClientSocketOp::Send => return Err(StackError::SendTimeout),
                    ClientSocketOp::Recv => return Err(StackError::RecvTimeout),
                    _ => Err(StackError::GeneralTimeout),
                };
            }
            let (_sock, op) = match tcp {
                true => self.callbacks.tcp_sockets.get(handle).unwrap(),
                false => self.callbacks.udp_sockets.get(handle).unwrap(),
            };
            if *op == ClientSocketOp::None {
                defmt::debug!(
                    "<===Ack received {:?}, recv_len:{:?}",
                    *op,
                    self.callbacks.recv_len
                );
                if self.callbacks.last_error != SocketError::NoError {
                    return Err(StackError::OpFailed(self.callbacks.last_error));
                }
                return Ok(self.callbacks.recv_len);
            }
            (self.delay)(self.poll_loop_delay);
            self.dispatch_events()?;
            timeout -= self.poll_loop_delay as i32;
        }
    }
}
