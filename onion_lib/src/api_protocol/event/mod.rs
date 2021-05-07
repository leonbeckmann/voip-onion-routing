use crate::api_protocol::messages::*;
use std::convert::TryFrom;

pub(crate) enum IncomingEvent {
    OnionTunnelBuild(Box<OnionTunnelBuild>),
    OnionTunnelDestroy(OnionTunnelDestroy),
    OnionTunnelData(Box<OnionTunnelData>),
    OnionCover(OnionCover),
}

impl TryFrom<(Vec<u8>, OnionMessageHeader)> for IncomingEvent {
    type Error = anyhow::Error;

    fn try_from((raw, hdr): (Vec<u8>, OnionMessageHeader)) -> Result<Self, Self::Error> {
        // check if raw has the correct length = hdr.size() - header_size
        if raw.len() != hdr.size() as usize - OnionMessageHeader::hdr_size() {
            return Err(anyhow::Error::msg(
                "Size of raw bytes differs from expected size",
            ));
        }

        match hdr.msg_type() {
            super::ONION_TUNNEL_BUILD => {
                let packet = Box::<OnionTunnelBuild>::try_from(raw)?;
                Ok(IncomingEvent::OnionTunnelBuild(packet))
            }
            super::ONION_TUNNEL_DESTROY => {
                let packet = OnionTunnelDestroy::try_from(raw)?;
                Ok(IncomingEvent::OnionTunnelDestroy(packet))
            }
            super::ONION_TUNNEL_DATA => {
                let packet = Box::<OnionTunnelData>::try_from(raw)?;
                Ok(IncomingEvent::OnionTunnelData(packet))
            }
            super::ONION_COVER => {
                let packet = OnionCover::try_from(raw)?;
                Ok(IncomingEvent::OnionCover(packet))
            }
            _ => Err(anyhow::Error::msg(format!(
                "Message type not supported: {:?}",
                hdr.msg_type()
            ))),
        }
    }
}

pub(crate) enum OutgoingEvent {
    OnionTunnelReady(Box<OnionTunnelReady>),
    OnionTunnelIncoming(OnionTunnelIncoming),
    OnionTunnelData(Box<OnionTunnelData>),
    OnionError(OnionError),
}
