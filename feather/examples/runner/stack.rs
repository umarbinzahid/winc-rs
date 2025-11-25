use cortex_m_systick_countdown::{CountsMillis, PollingSysTick};
use feather::debug;
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    phy::Device,
    socket::dhcpv4,
    //socket::icmp,
    time::Instant,
    wire::{EthernetAddress, IpCidr},
};

pub struct Clock<'a> {
    hardware: &'a PollingSysTick,
}

pub struct Stack<'a, D: Device> {
    pub device: &'a mut D,
    pub clock: Clock<'a>,
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
}

impl<'a> Clock<'a> {
    pub(crate) fn new(hardware: &'a PollingSysTick) -> Self {
        Self { hardware }
    }

    pub fn now(&mut self) -> Instant {
        let count = self.hardware.count().0;
        debug!("Count Value: {}", count);
        Instant::from_millis(count as i64)
    }
}

impl<'a, D: Device> Stack<'a, D> {
    pub fn new<const SOCK: usize>(
        device: &'a mut D,
        random_seed: u64,
        sock_storage: &'a mut [SocketStorage<'a>; SOCK],
        clk: &'a PollingSysTick,
        mac: [u8; 6],
    ) -> Self {
        let mut config =
            Config::new(EthernetAddress([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]).into());
        config.random_seed = random_seed;

        let mut clock = Clock::new(&clk);
        let iface = Interface::new(config, device, clock.now());

        Self {
            device: device,
            sockets: SocketSet::new(&mut sock_storage[..]),
            iface: iface,
            clock: clock,
        }
    }

    pub fn config_v4(&mut self) {
        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = self.sockets.add(dhcp_socket);

        loop {
            self.iface
                .poll(self.clock.now(), self.device, &mut self.sockets);

            let event = {
                let dhcp_socket = self.sockets.get_mut::<dhcpv4::Socket>(dhcp_handle);
                dhcp_socket.poll()
            };

            match event {
                None => {}
                Some(dhcpv4::Event::Configured(config)) => {
                    debug!("DHCP config acquired!");

                    debug!("IP address: {}", config.address);

                    self.iface.update_ip_addrs(|addrs| {
                        addrs.clear();
                        addrs.push(IpCidr::Ipv4(config.address)).unwrap();
                    });

                    if let Some(router) = config.router {
                        debug!("Default gateway: {}", router);
                        self.iface
                            .routes_mut()
                            .add_default_ipv4_route(router)
                            .unwrap();
                    } else {
                        debug!("Default gateway: None");
                        self.iface.routes_mut().remove_default_ipv4_route();
                    }

                    for (i, s) in config.dns_servers.iter().enumerate() {
                        debug!("DNS server {}:    {}", i, s);
                    }
                }
                Some(dhcpv4::Event::Deconfigured) => {
                    debug!("DHCP lost config!");
                    self.iface.update_ip_addrs(|addrs| addrs.clear());
                    self.iface.routes_mut().remove_default_ipv4_route();
                }
            }
        }
    }
}
