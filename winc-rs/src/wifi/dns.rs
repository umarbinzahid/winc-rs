use core::net::IpAddr;
use embedded_nal::AddrType;
use embedded_nal::Dns;

use crate::transfer::Xfer;
use crate::WincClient;

impl<'a, X: Xfer, E: crate::manager::EventListener> Dns for WincClient<'a, X, E> {
    type Error = ();

    fn get_host_by_name(
        &mut self,
        _hostname: &str,
        _addr_type: AddrType,
    ) -> embedded_nal::nb::Result<IpAddr, Self::Error> {
        todo!();
    }

    fn get_host_by_address(
        &mut self,
        _addr: core::net::IpAddr,
        _result: &mut [u8],
    ) -> Result<usize, embedded_nal::nb::Error<<Self as Dns>::Error>> {
        todo!()
    }
}
