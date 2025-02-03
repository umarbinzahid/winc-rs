use super::SocketError;

#[derive(Debug, defmt::Format)]
pub enum StackError {
    WouldBlock,
    GeneralTimeout,
    ConnectTimeout,
    RecvTimeout,
    SendTimeout,
    OutOfSockets,
    CloseFailed,
    Unexpected,
    DispatchError(wincwifi::errors::Error),
    ConnectSendFailed(wincwifi::errors::Error),
    ReceiveFailed(wincwifi::errors::Error),
    SendSendFailed(wincwifi::errors::Error),
    SendCloseFailed(wincwifi::errors::Error),
    WincWifiFail(wincwifi::errors::Error),
    OpFailed(SocketError),
}

impl From<core::convert::Infallible> for StackError {
    fn from(_: core::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<SocketError> for StackError {
    fn from(inner: SocketError) -> Self {
        Self::OpFailed(inner)
    }
}

impl From<wincwifi::errors::Error> for StackError {
    fn from(inner: wincwifi::errors::Error) -> Self {
        Self::WincWifiFail(inner)
    }
}

impl embedded_nal::TcpError for StackError {
    fn kind(&self) -> embedded_nal::TcpErrorKind {
        embedded_nal::TcpErrorKind::Other
    }
}

impl From<nb::Error<StackError>> for StackError {
    fn from(inner: nb::Error<StackError>) -> Self {
        match inner {
            nb::Error::WouldBlock => StackError::WouldBlock,
            nb::Error::Other(e) => e,
        }
    }
}
