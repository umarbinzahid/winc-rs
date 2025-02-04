#![no_main]
#![no_std]
#![allow(unused_imports)]

use embedded_nal::UdpFullStack;

use feather as bsp;
mod runner;
use core::str::FromStr;

const DEFAULT_TEST_SSID: &str = "network";
const DEFAULT_TEST_PASSWORD: &str = "password";
const DEFAULT_TEST_PORT: &str = "12345";

use runner::{connect_and_run, ClientType, ReturnClient};
use wincwifi::StackError;

fn udp_server<T, S>(stack: &mut T, port: u16) -> Result<(), T::Error>
where
    T: UdpFullStack<UdpSocket = S> + ?Sized,
    T::Error: From<embedded_nal::nb::Error<T::Error>>,
{
    let sock = stack.socket();
    if let Ok(mut s) = sock {
        defmt::println!("-----Socket created-----");
        stack.bind(&mut s, port)?;
        defmt::println!("-----Socket bound to port {}-----", port);
    }
    // do recvfrom here .. infinite loop ? Or number of iterations ?
    Ok(())
}

// Todo: UDP server
#[cortex_m_rt::entry]
fn main() -> ! {
    if let Err(something) = connect_and_run(
        "Hello, udp server",
        ClientType::UdpFull,
        |stack: ReturnClient| -> Result<(), StackError> {
            if let ReturnClient::UdpFull(stack) = stack {
                let test_port = option_env!("TEST_PORT").unwrap_or(DEFAULT_TEST_PORT);
                let port = u16::from_str(test_port).unwrap_or(12345);
                udp_server(stack, port)?;
            }
            Ok(())
        },
    ) {
        defmt::info!("Something went wrong {}", something)
    } else {
        defmt::info!("Good exit")
    };

    loop {}
}
