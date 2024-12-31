use super::hal;
use super::hal::ehal::spi::SpiBus;

use hal::sercom::spi::AnySpi;

pub trait TransferSpi: AnySpi + SpiBus {}
impl<U> TransferSpi for U
where
    U: AnySpi,
    U: SpiBus,
{
}
