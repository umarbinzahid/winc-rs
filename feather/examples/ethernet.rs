//! Ethernet Example

#![no_main]
#![no_std]

mod runner;

use bsp::shared::SpiStream;
use feather as bsp;
//use feather::hal::ehal::digital::OutputPin;
use feather::init::init;
use feather::shared::{create_countdowns, delay_fn};
use feather::{debug, error, info};
use rand_core::RngCore;
use smoltcp::iface::SocketStorage;

use runner::stack::Stack;
use wincwifi::{Credentials, Ssid, StackError, WifiChannel, WincClient};

const DEFAULT_TEST_SSID: &str = "network";
const DEFAULT_TEST_PASSWORD: &str = "password";
//const DEFAULT_TEST_IP: &str = "192.168.1.1";
const MAC_ADDR: [u8; 6] = [0xFC, 0x0F, 0xE7, 0x97, 0xB9, 0x36];

fn program() -> Result<(), StackError> {
    if let Ok(mut ini) = init() {
        info!("Hello, Winc Ethernet Module");

        let mut cnt = create_countdowns(&ini.delay_tick);
        //let red_led = &mut ini.red_led;

        let mut delay_ms = delay_fn(&mut cnt.0);

        //let ip = option_env!("TEST_IP").unwrap_or(DEFAULT_TEST_IP);
        let ssid = Ssid::from(option_env!("TEST_SSID").unwrap_or(DEFAULT_TEST_SSID)).unwrap();
        let password = option_env!("TEST_PASSWORD").unwrap_or(DEFAULT_TEST_PASSWORD);
        let credentials = Credentials::from_wpa(password)?;
        info!(
            "Connecting to network: {} with password: {}",
            ssid.as_str(),
            password
        );
        let mut device = WincClient::new(SpiStream::new(ini.cs, ini.spi));
        let mut sock_storage = [SocketStorage::EMPTY; 3];
        let random_seed = device.next_u64();

        let mut v = 0;
        loop {
            match device.start_wifi_module() {
                Ok(_) => break,
                Err(nb::Error::WouldBlock) => {
                    debug!("Waiting start .. {}", v);
                    v += 1;
                    delay_ms(5)
                }
                Err(e) => return Err(e.into()),
            }
        }

        for _ in 0..20 {
            device.heartbeat().unwrap();
            delay_ms(200);
        }

        info!("Started, connecting to AP ..");
        nb::block!(device.connect_to_ap(&ssid, &credentials, WifiChannel::ChannelAll, false))?;
        let mut stack = Stack::new(
            &mut device,
            random_seed,
            &mut sock_storage,
            &ini.delay_tick,
            MAC_ADDR,
        );

        stack.config_v4();
        /*
        loop {
            delay_ms(200);
            red_led.set_high().unwrap();
            delay_ms(200);
            red_led.set_low().unwrap();
            device.heartbeat().unwrap();
        }*/
    }
    Ok(())
}

#[cortex_m_rt::entry]
fn main() -> ! {
    if let Err(err) = program() {
        error!("Error: {}", err);
        panic!("Error in main program");
    } else {
        info!("Good exit")
    };
    loop {}
}
