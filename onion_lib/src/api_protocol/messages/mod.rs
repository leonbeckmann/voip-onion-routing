use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;

/*
 * Onion Message Header [size: u16, type: u16]
 * Direction: Incoming, Outgoing
 */
#[derive(Debug, PartialEq)]
pub struct OnionMessageHeader {
    pub size: u16,
    pub msg_type: u16,
}

impl OnionMessageHeader {
    pub fn new(size: u16, msg_type: u16) -> Self {
        Self { size, msg_type }
    }

    pub const fn hdr_size() -> usize {
        4
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.size.to_be_bytes().to_vec());
        v.append(&mut self.msg_type.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }
}

impl From<&[u8; Self::hdr_size()]> for OnionMessageHeader {
    fn from(raw: &[u8; Self::hdr_size()]) -> Self {
        Self {
            size: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
            msg_type: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
        }
    }
}

/*
 * Onion Tunnel Build [reserved: u15, ip_version: u1, onion_port: u16, ip_addr: u32/u128, key: [u8]]
 * Direction: Incoming
 */
#[derive(Debug, PartialEq)]
pub struct OnionTunnelBuild {
    _reserved_v: u16,
    pub onion_port: u16,
    pub ip: IpAddr,
    pub host_key: Vec<u8>,
}

impl OnionTunnelBuild {
    pub fn new(ip: IpAddr, onion_port: u16, host_key: Vec<u8>) -> Self {
        Self {
            _reserved_v: if ip.is_ipv6() { 1 } else { 0 },
            onion_port,
            ip,
            host_key,
        }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self._reserved_v.to_be_bytes().to_vec());
        v.append(&mut self.onion_port.to_be_bytes().to_vec());
        match self.ip {
            IpAddr::V4(v4) => {
                v.append(&mut v4.octets().to_vec());
            }
            IpAddr::V6(v6) => {
                v.append(&mut v6.octets().to_vec());
            }
        }
        v.extend(&self.host_key);
        v.append(&mut vec![]);
        v
    }
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
#[derive(Debug, PartialEq)]
pub struct OnionTunnelReady {
    pub tunnel_id: u32,
    pub host_key: Vec<u8>,
}

impl OnionTunnelReady {
    pub fn new(tunnel_id: u32, host_key: Vec<u8>) -> Self {
        Self {
            tunnel_id,
            host_key,
        }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.tunnel_id.to_be_bytes().to_vec());
        v.extend(&self.host_key);
        v.append(&mut vec![]);
        v
    }
}

impl TryFrom<Vec<u8>> for Box<OnionTunnelReady> {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() < 4 {
            return Err(anyhow::Error::msg(
                "Cannot parse OnionTunnelReady: Invalid number of bytes",
            ));
        }

        Ok(Box::new(OnionTunnelReady {
            tunnel_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            host_key: raw[4..].to_vec(),
        }))
    }
}

/*
 * Onion Tunnel Incoming [tunnel_id: u32]
 * Direction: Outgoing
 */
#[derive(Debug, PartialEq)]
pub struct OnionTunnelIncoming {
    pub tunnel_id: u32,
}

impl OnionTunnelIncoming {
    pub fn new(tunnel_id: u32) -> Self {
        Self { tunnel_id }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.tunnel_id.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }

    const fn packet_size() -> usize {
        4
    }
}

impl TryFrom<Vec<u8>> for OnionTunnelIncoming {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() != Self::packet_size() {
            Err(anyhow::Error::msg(
                "Cannot parse OnionTunnelIncoming: Invalid number of bytes",
            ))
        } else {
            Ok(Self {
                tunnel_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            })
        }
    }
}

/*
 * Onion Tunnel Destroy [tunnel_id: u32]
 * Direction: Incoming
 */
#[derive(Debug, PartialEq)]
pub struct OnionTunnelDestroy {
    pub tunnel_id: u32,
}

impl OnionTunnelDestroy {
    pub fn new(tunnel_id: u32) -> Self {
        Self { tunnel_id }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.tunnel_id.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }

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
            Ok(Self {
                tunnel_id: u32::from_be_bytes(raw[0..4].try_into().unwrap()),
            })
        }
    }
}

/*
 * Onion Tunnel Data [tunnel_id: u32, data: Vec<u8>]
 * Direction: Incoming, Outgoing
 */
#[derive(Debug, PartialEq)]
pub struct OnionTunnelData {
    pub tunnel_id: u32,
    pub data: Vec<u8>,
}

impl OnionTunnelData {
    pub fn new(tunnel_id: u32, data: Vec<u8>) -> Self {
        Self { tunnel_id, data }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.tunnel_id.to_be_bytes().to_vec());
        v.extend(&self.data);
        v.append(&mut vec![]);
        v
    }
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
#[derive(Debug, PartialEq)]
pub struct OnionError {
    pub request_type: u16,
    _reserved: u16,
    pub tunnel_id: u32,
}

impl OnionError {
    pub fn new(request_type: u16, tunnel_id: u32) -> Self {
        Self {
            request_type,
            _reserved: 0,
            tunnel_id,
        }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.request_type.to_be_bytes().to_vec());
        v.append(&mut self._reserved.to_be_bytes().to_vec());
        v.append(&mut self.tunnel_id.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }

    const fn packet_size() -> usize {
        8
    }
}

impl TryFrom<Vec<u8>> for OnionError {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        if raw.len() != Self::packet_size() {
            Err(anyhow::Error::msg(
                "Cannot parse OnionError: Invalid number of bytes",
            ))
        } else {
            Ok(Self {
                request_type: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
                _reserved: 0,
                tunnel_id: u32::from_be_bytes(raw[4..8].try_into().unwrap()),
            })
        }
    }
}

/*
 * Onion Tunnel Data [cover_size: 16, reserved: u16]
 * Direction: Incoming
 */
#[derive(Debug, PartialEq)]
pub struct OnionCover {
    pub cover_size: u16,
    _reserved: u16,
}

impl OnionCover {
    pub fn new(cover_size: u16) -> Self {
        Self {
            cover_size,
            _reserved: 0,
        }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.cover_size.to_be_bytes().to_vec());
        v.append(&mut self._reserved.to_be_bytes().to_vec());
        v.append(&mut vec![]);
        v
    }

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
            Ok(Self {
                cover_size: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
                _reserved: 0,
            })
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::api_protocol::messages::{
        OnionCover, OnionError, OnionMessageHeader, OnionTunnelBuild, OnionTunnelData,
        OnionTunnelDestroy, OnionTunnelIncoming, OnionTunnelReady,
    };
    use crate::api_protocol::{ONION_TUNNEL_BUILD, ONION_TUNNEL_DATA};
    use std::convert::{TryFrom, TryInto};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn unit_test_only_messages() {
        // OnionMessageHeader
        let hdr = OnionMessageHeader::new(25, ONION_TUNNEL_DATA);
        let hdr_raw: [u8; 4] = hdr.to_be_vec().try_into().unwrap();
        let hdr2 = OnionMessageHeader::from(&hdr_raw);
        assert_eq!(hdr, hdr2);

        // OnionTunnelBuild
        let ip_addr = IpAddr::from_str("127.0.0.1").unwrap();
        let build = OnionTunnelBuild::new(ip_addr, 1234, "key".as_bytes().to_vec());
        let build2 = Box::<OnionTunnelBuild>::try_from(build.to_be_vec()).unwrap();
        assert_eq!(Box::new(build), build2);

        let ip_addr = IpAddr::from_str("::1").unwrap();
        let build = OnionTunnelBuild::new(ip_addr, 1234, "key".as_bytes().to_vec());
        let build2 = Box::<OnionTunnelBuild>::try_from(build.to_be_vec()).unwrap();
        assert_eq!(Box::new(build), build2);

        // OnionTunnelReady
        let ready = OnionTunnelReady::new(1025, "key".as_bytes().to_vec());
        let ready2 = Box::<OnionTunnelReady>::try_from(ready.to_be_vec()).unwrap();
        assert_eq!(Box::new(ready), ready2);

        // OnionTunnelIncoming
        let incoming = OnionTunnelIncoming::new(1025);
        let incoming2 = OnionTunnelIncoming::try_from(incoming.to_be_vec()).unwrap();
        assert_eq!(incoming, incoming2);

        // OnionTunnelDestroy
        let destroy = OnionTunnelDestroy::new(1025);
        let destroy2 = OnionTunnelDestroy::try_from(destroy.to_be_vec()).unwrap();
        assert_eq!(destroy, destroy2);

        // OnionTunnelData
        let data = OnionTunnelData::new(1025, "Data".as_bytes().to_vec());
        let data2 = Box::<OnionTunnelData>::try_from(data.to_be_vec()).unwrap();
        assert_eq!(Box::new(data), data2);

        // OnionError
        let error = OnionError::new(ONION_TUNNEL_BUILD, 0);
        let error2 = OnionError::try_from(error.to_be_vec()).unwrap();
        assert_eq!(error, error2);

        // OnionCover
        let cover = OnionCover::new(1025);
        let cover2 = OnionCover::try_from(cover.to_be_vec()).unwrap();
        assert_eq!(cover, cover2);
    }
}
