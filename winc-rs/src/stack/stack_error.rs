use crate::manager::WifiConnError;

#[cfg(feature = "experimental-ota")]
use crate::manager::OtaUpdateError;
use crate::manager::SocketError;

use embedded_nal::nb;

/// Stack errors
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq)]
pub enum StackError {
    /// This operation requires blocking behavior to complete.
    WouldBlock,
    /// Operation timed out.
    GeneralTimeout,
    /// TCP/UDP connection timed out.
    ConnectTimeout,
    /// Receiving data from socket timed out.
    RecvTimeout,
    /// Sending data to socket timed out.
    SendTimeout,
    /// No more sockets can be configured.
    OutOfSockets,
    /// Socket is already in use.
    SocketAlreadyInUse,
    /// Closing socket failed.
    CloseFailed,
    /// Unexpected error occurred.
    Unexpected,
    /// Error occurred while processing event.
    DispatchError(crate::errors::CommError),
    /// Sending connect socket request failed.
    ConnectSendFailed(crate::errors::CommError),
    /// Receiving data from socket failed.
    ReceiveFailed(crate::errors::CommError),
    /// Sending send request failed.
    SendSendFailed(crate::errors::CommError),
    /// Sending close request failed.
    SendCloseFailed(crate::errors::CommError),
    /// Binding socket failed.
    BindFailed(crate::errors::CommError),
    /// Error occurred while communicating with WINC module.
    WincWifiFail(crate::errors::CommError),
    /// Socket operation failed.
    OpFailed(SocketError),
    /// DNS lookup timed out.
    DnsTimeout,
    /// Unexpected DNS error.
    DnsFailed,
    /// Operation was attempted in an invalid state.
    InvalidState,
    /// Module is already connected to an access point.
    AlreadyConnected,
    /// Access point join failed.
    ApJoinFailed(WifiConnError),
    /// Scan operation failed.
    ApScanFailed(WifiConnError),
    /// Continue the operation.
    ContinueOperation,
    /// Socket not found.
    SocketNotFound,
    /// Invalid parameters.
    InvalidParameters,
    #[cfg(feature = "experimental-ota")]
    /// OTA error.
    OtaFail(OtaUpdateError),
}

/// Converts `core::convert::Infallible` to `StackError`.
impl From<core::convert::Infallible> for StackError {
    fn from(_: core::convert::Infallible) -> Self {
        unreachable!()
    }
}

/// Converts a `SocketError` into a `StackError` by wrapping it in `OpFailed`.
impl From<SocketError> for StackError {
    fn from(inner: SocketError) -> Self {
        Self::OpFailed(inner)
    }
}

/// Converts a `CommError` into a `StackError` as a `WincWifiFail` variant.
impl From<crate::errors::CommError> for StackError {
    fn from(inner: crate::errors::CommError) -> Self {
        Self::WincWifiFail(inner)
    }
}

/// Converts a `CommError` directly into an `nb::Error<StackError>` for use with non-blocking APIs.
impl From<crate::errors::CommError> for nb::Error<StackError> {
    fn from(inner: crate::errors::CommError) -> Self {
        nb::Error::Other(StackError::WincWifiFail(inner))
    }
}

/// Converts a `core::net::AddrParseError` into a `StackError::InvalidParameters`,
impl From<core::net::AddrParseError> for StackError {
    fn from(_: core::net::AddrParseError) -> Self {
        Self::InvalidParameters
    }
}

/// Implements the `TcpError` trait from `embedded-nal` for `StackError`,
impl embedded_nal::TcpError for StackError {
    fn kind(&self) -> embedded_nal::TcpErrorKind {
        embedded_nal::TcpErrorKind::Other
    }
}

/// Converts a non-blocking error (`nb::Error<StackError>`) back into a `StackError`.
impl From<nb::Error<StackError>> for StackError {
    fn from(inner: nb::Error<StackError>) -> Self {
        match inner {
            nb::Error::WouldBlock => StackError::WouldBlock,
            nb::Error::Other(e) => e,
        }
    }
}

/// Implements the `Display` trait for `StackError`
impl core::fmt::Display for StackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WouldBlock => write!(f, "Operation would block"),
            Self::GeneralTimeout => write!(f, "General timeout"),
            Self::ConnectTimeout => write!(f, "TCP connection timed out"),
            Self::RecvTimeout => write!(f, "Receive timeout"),
            Self::SendTimeout => write!(f, "Send timeout"),
            Self::OutOfSockets => write!(f, "Out of sockets"),
            Self::SocketAlreadyInUse => write!(f, "Socket already in use"),
            Self::CloseFailed => write!(f, "Close failed"),
            Self::Unexpected => write!(f, "Unexpected error"),
            Self::DispatchError(err) => write!(f, "Dispatch error: {}", err),
            Self::ConnectSendFailed(err) => write!(f, "Connect send failed: {}", err),
            Self::ReceiveFailed(err) => write!(f, "Receive failed: {}", err),
            Self::SendSendFailed(err) => write!(f, "Send send failed: {}", err),
            Self::SendCloseFailed(err) => write!(f, "Send close failed: {}", err),
            Self::BindFailed(err) => write!(f, "Bind failed: {}", err),
            Self::WincWifiFail(err) => write!(f, "WincWifi fail: {}", err),
            Self::OpFailed(err) => write!(f, "Operation failed: {}", err),
            Self::DnsTimeout => write!(f, "DNS lookup timed out"),
            Self::DnsFailed => write!(f, "DNS lookup failed"),
            Self::InvalidState => write!(f, "Invalid state"),
            Self::AlreadyConnected => write!(f, "Already connected"),
            Self::ApJoinFailed(err) => write!(f, "Access point join failed: {}", err),
            Self::ApScanFailed(err) => write!(f, "Access point scan failed: {}", err),
            Self::ContinueOperation => write!(f, "Continue operation"),
            Self::SocketNotFound => write!(f, "Socket not found"),
            Self::InvalidParameters => write!(f, "Invalid parameters"),
            #[cfg(feature = "experimental-ota")]
            Self::OtaFail(err) => write!(f, "Ota failure: {:?}", err),
        }
    }
}
