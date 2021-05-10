use crate::api_protocol::messages::*;
use std::convert::TryFrom;

pub(crate) enum IncomingEvent {
    TunnelBuild(Box<OnionTunnelBuild>),
    TunnelDestroy(OnionTunnelDestroy),
    TunnelData(Box<OnionTunnelData>),
    Cover(OnionCover),
}

impl TryFrom<(Vec<u8>, OnionMessageHeader)> for IncomingEvent {
    type Error = anyhow::Error;

    fn try_from((raw, hdr): (Vec<u8>, OnionMessageHeader)) -> Result<Self, Self::Error> {
        // check if raw has the correct length = hdr.size() - header_size
        if raw.len() != hdr.size as usize - OnionMessageHeader::hdr_size() {
            return Err(anyhow::Error::msg(
                "Size of raw bytes differs from expected size",
            ));
        }

        match hdr.msg_type {
            super::ONION_TUNNEL_BUILD => {
                let packet = Box::<OnionTunnelBuild>::try_from(raw)?;
                Ok(IncomingEvent::TunnelBuild(packet))
            }
            super::ONION_TUNNEL_DESTROY => {
                let packet = OnionTunnelDestroy::try_from(raw)?;
                Ok(IncomingEvent::TunnelDestroy(packet))
            }
            super::ONION_TUNNEL_DATA => {
                let packet = Box::<OnionTunnelData>::try_from(raw)?;
                Ok(IncomingEvent::TunnelData(packet))
            }
            super::ONION_COVER => {
                let packet = OnionCover::try_from(raw)?;
                Ok(IncomingEvent::Cover(packet))
            }
            _ => Err(anyhow::Error::msg(format!(
                "Message type not supported: {:?}",
                hdr.msg_type
            ))),
        }
    }
}

#[derive(Debug)]
pub(crate) enum OutgoingEvent {
    TunnelReady(Box<OnionTunnelReady>),
    TunnelIncoming(OnionTunnelIncoming),
    TunnelData(Box<OnionTunnelData>),
    Error(OnionError),
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for OutgoingEvent {
    fn into(self) -> Vec<u8> {
        match self {
            OutgoingEvent::TunnelReady(packet) => packet.to_be_vec(),
            OutgoingEvent::TunnelIncoming(packet) => packet.to_be_vec(),
            OutgoingEvent::TunnelData(packet) => packet.to_be_vec(),
            OutgoingEvent::Error(packet) => packet.to_be_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api_protocol;
    use crate::api_protocol::event::{IncomingEvent, OutgoingEvent};
    use crate::api_protocol::messages::{
        OnionError, OnionMessageHeader, OnionTunnelData, OnionTunnelIncoming, OnionTunnelReady,
    };
    use std::convert::TryFrom;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn parse_event(raw: Vec<u8>, msg_type: u16) -> anyhow::Result<IncomingEvent> {
        let hdr = OnionMessageHeader::new(
            (raw.len() + OnionMessageHeader::hdr_size()) as u16,
            msg_type,
        );

        IncomingEvent::try_from((raw, hdr))
    }

    #[test]
    fn unit_onion_build_parsing() {
        /*
         * We assume a packet with wrong ip 'v' flag as valid until there is no size error
         */

        // valid with ipv4 = 127.0.0.1 and port = 1234 and arbitrary host_key = "key"
        let raw_1: Vec<u8> = vec![0, 0, 4, 210, 127, 0, 0, 1, 107, 101, 121];
        // invalid too short with ipv4
        let raw_2: Vec<u8> = raw_1[0..7].to_vec();
        // valid with ipv6 = ::1 and port 1234 and arbitrary host_key = "key"
        let raw_3: Vec<u8> = vec![
            0, 1, 4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 107, 101, 121,
        ];
        // invalid too short with ipv6
        let raw_4: Vec<u8> = raw_3[0..17].to_vec();

        match parse_event(raw_1, api_protocol::ONION_TUNNEL_BUILD).unwrap() {
            IncomingEvent::TunnelBuild(packet) => {
                assert!(packet.ip.is_ipv4());
                assert_eq!(
                    IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
                    packet.ip
                );
                assert_eq!(packet.onion_port, 1234);
                assert_eq!(packet.host_key, vec![107, 101, 121]);
            }
            _ => {
                panic!("Invalid event. Expected: OnionTunnelBuild");
            }
        };

        assert!(parse_event(raw_2, api_protocol::ONION_TUNNEL_BUILD).is_err());

        match parse_event(raw_3, api_protocol::ONION_TUNNEL_BUILD).unwrap() {
            IncomingEvent::TunnelBuild(packet) => {
                assert!(packet.ip.is_ipv6());
                assert_eq!(IpAddr::V6(Ipv6Addr::from_str("::1").unwrap()), packet.ip);
                assert_eq!(packet.onion_port, 1234);
                assert_eq!(packet.host_key, vec![107, 101, 121]);
            }
            _ => {
                panic!("Invalid event. Expected: OnionTunnelBuild");
            }
        };

        assert!(parse_event(raw_4, api_protocol::ONION_TUNNEL_BUILD).is_err());
    }

    #[test]
    fn unit_onion_destroy_parsing() {
        // valid with tunnel id = 1025
        let raw_1: Vec<u8> = vec![0, 0, 4, 1];
        match parse_event(raw_1, api_protocol::ONION_TUNNEL_DESTROY).unwrap() {
            IncomingEvent::TunnelDestroy(packet) => {
                assert_eq!(packet.tunnel_id, 1025);
            }
            _ => {
                panic!("Invalid event. Expected: OnionTunnelDestroy");
            }
        };

        // invalid, too short
        let raw_2: Vec<u8> = vec![0, 0, 4];
        assert!(parse_event(raw_2, api_protocol::ONION_TUNNEL_DESTROY).is_err());

        // invalid, too large
        let raw_3: Vec<u8> = vec![0, 0, 4, 1, 0];
        assert!(parse_event(raw_3, api_protocol::ONION_TUNNEL_DESTROY).is_err());
    }

    #[test]
    fn unit_onion_data_parsing() {
        // valid with tunnel id = 1025, data = "Data"
        let raw_1: Vec<u8> = vec![0, 0, 4, 1, 68, 97, 116, 97];
        match parse_event(raw_1, api_protocol::ONION_TUNNEL_DATA).unwrap() {
            IncomingEvent::TunnelData(packet) => {
                assert_eq!(packet.tunnel_id, 1025);
                assert_eq!(packet.data, vec![68, 97, 116, 97])
            }
            _ => {
                panic!("Invalid event. Expected: OnionTunnelData");
            }
        };

        // invalid, too short
        let raw_2: Vec<u8> = vec![0, 0, 4];
        assert!(parse_event(raw_2, api_protocol::ONION_TUNNEL_DATA).is_err());
    }

    #[test]
    fn unit_onion_cover_parsing() {
        // valid with cover_size = 1025 bytes
        let raw_1: Vec<u8> = vec![4, 1, 0, 0];
        match parse_event(raw_1, api_protocol::ONION_COVER).unwrap() {
            IncomingEvent::Cover(packet) => {
                assert_eq!(packet.cover_size, 1025);
            }
            _ => {
                panic!("Invalid event. Expected: OnionCover");
            }
        };

        // invalid, too short
        let raw_2: Vec<u8> = vec![4, 1, 0];
        assert!(parse_event(raw_2, api_protocol::ONION_COVER).is_err());

        // invalid, too large
        let raw_3: Vec<u8> = vec![4, 1, 0, 0, 0];
        assert!(parse_event(raw_3, api_protocol::ONION_COVER).is_err());
    }

    #[test]
    fn unit_onion_ready_serial() {
        let e = OutgoingEvent::TunnelReady(Box::new(OnionTunnelReady::new(
            1025,
            "key".as_bytes().to_vec(),
        )));
        let v: Vec<u8> = e.into();
        assert_eq!(v, vec![0, 0, 4, 1, 107, 101, 121]);
    }

    #[test]
    fn unit_onion_incoming_serial() {
        let e = OutgoingEvent::TunnelIncoming(OnionTunnelIncoming::new(1025));
        let v: Vec<u8> = e.into();
        assert_eq!(v, vec![0, 0, 4, 1]);
    }

    #[test]
    fn unit_onion_data_serial() {
        let e = OutgoingEvent::TunnelData(Box::new(OnionTunnelData::new(
            1025,
            "Data".as_bytes().to_vec(),
        )));
        let v: Vec<u8> = e.into();
        assert_eq!(v, vec![0, 0, 4, 1, 68, 97, 116, 97]);
    }

    #[test]
    fn unit_onion_error_serial() {
        let e = OutgoingEvent::Error(OnionError::new(api_protocol::ONION_TUNNEL_BUILD, 1025));
        let v: Vec<u8> = e.into();
        let mut v2 = api_protocol::ONION_TUNNEL_BUILD.to_be_bytes().to_vec();
        v2.extend(vec![0, 0, 0, 0, 4, 1]);
        assert_eq!(v, v2);
    }
}
