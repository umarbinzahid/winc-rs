//! Provisioning Mode
//!

#![no_main]
#![no_std]

use feather as bsp;
use feather::init::init;
use feather::{debug, error, info};

use bsp::shared::SpiStream;
use core::str;
use feather::hal::ehal::digital::OutputPin;
use feather::shared::{create_countdowns, delay_fn};
use wincwifi::{AccessPoint, HostName, Ssid, StackError, WifiChannel, WincClient, WpaKey};

const DEFAULT_TEST_SSID: &str = "winc_network";
const DEFAULT_TEST_PASSWORD: &str = "password";
const DEFAULT_TEST_HOSTNAME: &str = "admin";
const DEFAULT_PROVISIONING_TIMEOUT_IN_MINS: u32 = 15;

fn program() -> Result<(), StackError> {
    if let Ok(mut ini) = init() {
        info!("Hello, Winc Provisioning");
        let red_led = &mut ini.red_led;

        let mut cnt = create_countdowns(&ini.delay_tick);
        let mut delay_ms = delay_fn(&mut cnt.0);

        let ap_ssid = Ssid::from(option_env!("TEST_AP_SSID").unwrap_or(DEFAULT_TEST_SSID)).unwrap();
        let ap_password =
            WpaKey::from(option_env!("TEST_AP_PASSWORD").unwrap_or(DEFAULT_TEST_PASSWORD)).unwrap();
        let hostname =
            HostName::from(option_env!("TEST_AP_DNS").unwrap_or(DEFAULT_TEST_HOSTNAME)).unwrap();

        let mut stack = WincClient::new(SpiStream::new(ini.cs, ini.spi));

        let mut v = 0;
        loop {
            match stack.start_wifi_module() {
                Ok(_) => break,
                Err(nb::Error::WouldBlock) => {
                    debug!("Waiting start .. {}", v);
                    v += 1;
                    delay_ms(5)
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Configure the access point with WPA/WPA2 security using the provided SSID and password.
        let access_point = AccessPoint::wpa(&ap_ssid, &ap_password);
        // Start the provising mode.
        info!(
            "Starting Provisioning Mode for {} minutes",
            DEFAULT_PROVISIONING_TIMEOUT_IN_MINS
        );
        let result = nb::block!(stack.provisioning_mode(
            &access_point,
            &hostname,
            true,
            DEFAULT_PROVISIONING_TIMEOUT_IN_MINS,
        ));

        // Check for provisioning information is receieved for 15 minutes.
        match result {
            Ok(info) => {
                info!("Credentials received from provisioning; connecting to access point.");
                // Connect to access point.
                nb::block!(stack.connect_to_ap(
                    &info.ssid,
                    &info.key,
                    WifiChannel::ChannelAll,
                    false
                ))?;
                info!("Connected to AP");
            }
            Err(err) => {
                if err == StackError::GeneralTimeout {
                    error!(
                        "No information was received for 15 minutes. Stopping provisioning mode."
                    );
                    stack.stop_provisioning_mode()?;
                } else {
                    error!("Provisioning Failed");
                }
            }
        }

        loop {
            delay_ms(200);
            red_led.set_high().unwrap();
            delay_ms(200);
            red_led.set_low().unwrap();
            stack.heartbeat().unwrap();
        }
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
