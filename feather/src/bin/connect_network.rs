#![no_main]
#![no_std]

use bsp::hal::prelude::*;
use bsp::shared::{create_delay_closure, SpiStream};
use feather as bsp;
use feather::init::init;

use cortex_m_systick_countdown::MillisCountDown;

use wincwifi::manager::{AuthType, EventListener, Manager};

const DEFAULT_TEST_SSID: &str = "network";
const DEFAULT_TEST_PASSWORD: &str = "password";

pub struct Callbacks;
impl EventListener for Callbacks {
    fn on_dhcp(&mut self, conf: wincwifi::manager::IPConf) {
        defmt::info!("Network connected: IP config: {}", conf);
    }
    fn on_system_time(&mut self, year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) {
        defmt::info!(
            "System time received: {}-{:02}-{:02} {:02}:{:02}:{:02}",
            year,
            month,
            day,
            hour,
            minute,
            second
        );
    }
}

fn program() -> Result<(), wincwifi::error::Error> {
    if let Ok((delay_tick, mut red_led, cs, spi)) = init() {
        defmt::println!("Hello, tcp_connect with shared init!");

        let mut countdown1 = MillisCountDown::new(&delay_tick);
        let mut countdown2 = MillisCountDown::new(&delay_tick);
        let mut delay_ms = create_delay_closure(&mut countdown1);

        let mut manager = Manager::from_xfer(
            SpiStream::new(cs, spi, create_delay_closure(&mut countdown2)),
            Callbacks {},
        );
        manager.set_crc_state(true);

        manager.start(&mut |v: u32| -> bool {
            defmt::debug!("Waiting start .. {}", v);
            delay_ms(40);
            false
        })?;
        defmt::debug!("Chip started..");

        let ssid = option_env!("TEST_SSID").unwrap_or(DEFAULT_TEST_SSID);
        let password = option_env!("TEST_PASSWORD").unwrap_or(DEFAULT_TEST_PASSWORD);

        manager.send_connect(AuthType::WpaPSK, ssid, password, 0xFF, false)?;

        delay_ms(200);
        loop {
            manager.dispatch_events()?;

            delay_ms(200);
            red_led.set_high()?;
            delay_ms(200);
            red_led.set_low()?;
        }
    }
    Ok(())
}

#[cortex_m_rt::entry]
fn main() -> ! {
    if let Err(something) = program() {
        defmt::info!("Bad error {}", something);
        panic!("Error in main program");
    } else {
        defmt::info!("Good exit")
    };
    loop {}
}
