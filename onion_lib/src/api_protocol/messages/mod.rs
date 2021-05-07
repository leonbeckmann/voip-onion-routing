use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;

/*
 * Onion Message Header [size: u16, type: u16]
 * Direction: Incoming, Outgoing
 */
pub(crate) struct OnionMessageHeader {
    size: u16,
    msg_type: u16,
}

impl OnionMessageHeader {
    pub(crate) fn _new(size: u16, msg_type: u16) -> OnionMessageHeader {
        OnionMessageHeader { size, msg_type }
    }

    pub(crate) fn size(&self) -> u16 {
        self.size
    }

    pub(crate) fn msg_type(&self) -> u16 {
        self.msg_type
    }

    pub(crate) const fn hdr_size() -> usize {
        4
    }

    pub(crate) fn _to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.size.to_be_bytes().to_vec());
        v.append(&mut self.msg_type.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }
}

impl From<&[u8; OnionMessageHeader::hdr_size()]> for OnionMessageHeader {
    fn from(raw: &[u8; OnionMessageHeader::hdr_size()]) -> Self {
        OnionMessageHeader {
            size: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
            msg_type: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
        }
    }
}

/*
 * Onion Tunnel Build [reserved: u15, ip_version: u1, onion_port: u16, ip_addr: u32/u128, key: [u8]]
 * Direction: Incoming
 */
pub(crate) struct OnionTunnelBuild {
    _reserved_v: u16,
    onion_port: u16,
    ip: IpAddr,
    host_key: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Box<OnionTunnelBuild> {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() < 4 {
            return Err(anyhow::Error::msg(
                "Cannot parse OnionTunnelBuild: Invalid number of bytes",
            ));
        }

        let reserved_v = u16::from_be_bytes(raw[0..2].try_into().unwrap());

        let onion_port = u16::from_be_bytes(raw[2..4].try_into().unwrap());
        let (ip, host_key) = match (1 & reserved_v) == 1 {
            true => {
                // ipv6
                if raw.len() < 20 {
                    return Err(anyhow::Error::msg(
                        "Cannot parse OnionTunnelBuild: Invalid number of bytes",
                    ));
                }
                let mut ip_buf = [0u8; 16];
                ip_buf.copy_from_slice(&raw[4..20]);
                (IpAddr::from(ip_buf), raw[20..].to_vec())
            }
            false => {
                // ipv4
                if raw.len() < 8 {
                    return Err(anyhow::Error::msg(
                        "Cannot parse OnionTunnelBuild: Invalid number of bytes",
                    ));
                }
                let mut ip_buf = [0u8; 4];
                ip_buf.copy_from_slice(&raw[4..8]);
                (IpAddr::from(ip_buf), raw[8..].to_vec())
            }
        };
        Ok(Box::new(OnionTunnelBuild {
            _reserved_v: reserved_v,
            onion_port,
            ip,
            host_key,
        }))
    }
}

/*
 * Onion Tunnel Ready [tunnel_id: u32, host_key: [u8]]
 * Direction: Outgoing
 */
pub(crate) struct OnionTunnelReady {
    tunnel_id: u32,
    host_key: Vec<u8>,
}

/*
 * Onion Tunnel Incoming [tunnel_id: u32]
 * Direction: Outgoing
 */
pub(crate) struct OnionTunnelIncoming {
    tunnel_id: u32,
}

/*
 * Onion Tunnel Destroy [tunnel_id: u32]
 * Direction: Incoming
 */
pub(crate) struct OnionTunnelDestroy {
    tunnel_id: u32,
}

impl OnionTunnelDestroy {
    const fn packet_size() -> usize {
        4
    }
}

impl TryFrom<Vec<u8>> for OnionTunnelDestroy {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() != Self::packet_size() {
            Err(anyhow::Error::msg(
                "Cannot parse OnionTunnelDestroy: Invalid number of bytes",
            ))
        } else {
            Ok(OnionTunnelDestroy {
                tunnel_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            })
        }
    }
}

/*
 * Onion Tunnel Data [tunnel_id: u32, data: Vec<u8>]
 * Direction: Incoming, Outgoing
 */
pub(crate) struct OnionTunnelData {
    tunnel_id: u32,
    data: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Box<OnionTunnelData> {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() < 4 {
            Err(anyhow::Error::msg(
                "Cannot parse OnionTunnelData: Invalid number of bytes",
            ))
        } else {
            Ok(Box::new(OnionTunnelData {
                tunnel_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
                data: raw[4..].to_vec(),
            }))
        }
    }
}

/*
 * Onion Tunnel Error [request_type: u16, reserved: u16, tunnel_id: u32]
 * Direction: Outgoing
 */
pub(crate) struct OnionError {
    request_type: u16,
    _reserved: u16,
    tunnel_id: u32,
}

/*
 * Onion Tunnel Data [cover_size: 16, reserved: u16]
 * Direction: Incoming
 */
pub(crate) struct OnionCover {
    cover_size: u16,
    _reserved: u16,
}

impl OnionCover {
    const fn packet_size() -> usize {
        4
    }
}

impl TryFrom<Vec<u8>> for OnionCover {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() != Self::packet_size() {
            Err(anyhow::Error::msg(
                "Cannot parse OnionCover: Invalid number of bytes",
            ))
        } else {
            Ok(OnionCover {
                cover_size: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
                _reserved: 0,
            })
        }
    }
}