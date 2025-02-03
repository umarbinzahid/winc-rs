# WINC1500 Rust crate

WINC1500 Wifi chip adapter. 

embedded_nal::TcpClientStack and embedded_nal::UdpClientStack are implemented
and tested on [Adafruit Feather M0 WiFi](https://www.adafruit.com/product/3010).

Note: The implementation is still very raw, but basic wire level protocol works,
connecting to AP, getting an IP, DNS lookups etc are somewhat tested.

Chip connection is abstracted in a transfer trait, but currently only tested over
SPI bus. Technically USB/UART could be supported too.

For example programs, see [feather/](https://github.com/kaidokert/winc-rs/tree/main/feather) dir.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.

