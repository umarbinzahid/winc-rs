#![no_main]
#![no_std]
#![allow(unused_imports)]

use embedded_nal::UdpClientStack;
use feather as bsp;
use nb::block;

mod runner;

use bsp::shared::parse_ip_octets;
use core::str::FromStr;
use runner::{connect_and_run, ClientType, MyUdpClientStack, ReturnClient};
use wincwifi::StackError;

fn run<S, E>(stack: &mut S, target: core::net::SocketAddr) -> Result<(), E>
where
    E: core::fmt::Debug,
    S: UdpClientStack<Error = E> + ?Sized,
{
    let mut sock = stack.socket()?;
    stack.connect(&mut sock, target)?;
    // Data, V1 NON no token, GET, message ID 0x0000, 2x Uri-Path
    block!(stack.send(&mut sock, b"\x50\x01\0\0\xbb.well-known\x04core"))?;

    let mut respbuf = [0; 1500];
    let (resplen, _) = block!(stack.receive(&mut sock, &mut respbuf))?;
    let response = &respbuf[..resplen];

    defmt::println!("Response: {}", core::str::from_utf8(response).unwrap());

    Ok(())
}

const DEFAULT_TEST_IP: &str = "192.168.1.1";
const DEFAULT_TEST_PORT: &str = "12345";
const DEFAULT_TEST_SSID: &str = "network";
const DEFAULT_TEST_PASSWORD: &str = "password";

// Todo: COAP demo
#[cortex_m_rt::entry]
fn main() -> ! {
    if let Err(something) = connect_and_run(
        "Hello, udp client",
        ClientType::Udp,
        |stack: ReturnClient| -> Result<(), StackError> {
            if let ReturnClient::Udp(stack) = stack {
                defmt::info!("In UDP client stack thing");
                let test_ip = option_env!("TEST_IP").unwrap_or(DEFAULT_TEST_IP);
                let ip_values: [u8; 4] = parse_ip_octets(test_ip);
                let ip = core::net::Ipv4Addr::new(
                    ip_values[0],
                    ip_values[1],
                    ip_values[2],
                    ip_values[3],
                );
                let test_port = option_env!("TEST_PORT").unwrap_or(DEFAULT_TEST_PORT);
                let port = u16::from_str(test_port).unwrap_or(12345);
                defmt::info!("---- Starting UDP client ---- ");
                let target = core::net::SocketAddr::new(core::net::IpAddr::V4(ip), port);
                run(stack, target)?;
                defmt::info!("---- HTTP UDP done ---- ");
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
