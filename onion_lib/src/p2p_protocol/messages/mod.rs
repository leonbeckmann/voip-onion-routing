pub(crate) mod p2p_messages;
/*
impl From<p2p_messages::TunnelHello> for p2p_messages::TunnelFrame {
    fn from(msg: p2p_messages::TunnelHello) -> Self {
        let mut frame = Self::new();
        frame.set_tunnelHello(msg);
        frame
    }
}

impl From<p2p_messages::TunnelData> for p2p_messages::TunnelFrame {
    fn from(msg: p2p_messages::TunnelData) -> Self {
        let mut frame = Self::new();
        frame.set_tunnelData(msg);
        frame
    }
}

impl From<p2p_messages::TunnelClose> for p2p_messages::TunnelFrame {
    fn from(msg: p2p_messages::TunnelClose) -> Self {
        let mut frame = Self::new();
        frame.set_tunnelClose(msg);
        frame
    }
}
*/
