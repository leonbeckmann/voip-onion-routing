use crate::api_protocol::messages::OnionMessageHeader;
use crate::p2p_protocol::dtls_connections::Blocklist;
use crate::p2p_protocol::onion_tunnel::Peer;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

pub const RPS_QUERY: u16 = 540;
pub const RPS_PEER: u16 = 541;
pub const ONION_PORT: u16 = 560;

/**
 * Sample one peer via the RPS module
 */
async fn rps_get_peer(rps_addr: SocketAddr) -> anyhow::Result<Peer> {
    // connect to rps module
    let mut stream = TcpStream::connect(rps_addr).await?;

    // rps query
    let query = OnionMessageHeader::new(OnionMessageHeader::hdr_size() as u16, RPS_QUERY);
    stream.write_all(query.to_be_vec().as_ref()).await?;

    // read message header
    let mut buf = [0u8; OnionMessageHeader::hdr_size()];
    stream.read_exact(&mut buf).await?;

    // parse buf the onion_msg_hdr
    let hdr = OnionMessageHeader::try_from(&buf).unwrap();

    if hdr.msg_type != RPS_PEER {
        return Err(anyhow::Error::msg("Invalid RPS response"));
    }

    // read remaining message into buf without the hdr
    let mut buf = vec![0u8; hdr.size as usize - OnionMessageHeader::hdr_size()];
    stream.read_exact(&mut buf).await?;

    // parse to peer
    let peer = Box::<RpsPeer>::try_from(buf)?;

    // return peer
    if let Some(port) = peer.port_map.get(&ONION_PORT) {
        Ok((SocketAddr::new(peer.ip, *port), peer.host_key))
    } else {
        Err(anyhow::Error::msg(
            "RPS response does not contain an onion port",
        ))
    }
}

/**
 * Sample one peer via the RPS module, which is not blocked at the DTLS layer
 */
pub async fn rps_get_peer_filtered(
    rps_addr: SocketAddr,
    blocklist: Arc<RwLock<Blocklist>>,
) -> anyhow::Result<Peer> {
    for _ in 0..10 {
        let (socket_addr, host_key) = rps_get_peer(rps_addr).await?;
        if !blocklist.read().await.is_blocked(&socket_addr) {
            return Ok((socket_addr, host_key));
        }
    }
    Err(anyhow::Error::msg("RPS did not find non-blocked peer"))
}

#[derive(Debug, PartialEq)]
pub struct RpsPeer {
    port: u16,
    port_map_size: u8,
    _reserved_v: u8,
    port_map: HashMap<u16, u16>,
    ip: IpAddr,
    host_key: Vec<u8>,
}

impl RpsPeer {
    pub fn new(ip: IpAddr, port: u16, port_map: HashMap<u16, u16>, host_key: Vec<u8>) -> Self {
        Self {
            port,
            _reserved_v: if ip.is_ipv6() { 1 } else { 0 },
            port_map_size: port_map.len() as u8,
            port_map,
            ip,
            host_key,
        }
    }

    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.append(&mut self.port.to_be_bytes().to_vec());
        v.push(self.port_map_size);
        v.push(self._reserved_v);
        for (a, b) in self.port_map.iter() {
            v.append(&mut a.to_be_bytes().to_vec());
            v.append(&mut b.to_be_bytes().to_vec());
        }
        match self.ip {
            IpAddr::V4(v4) => {
                v.append(&mut v4.octets().to_vec());
            }
            IpAddr::V6(v6) => {
                v.append(&mut v6.octets().to_vec());
            }
        }
        v.extend(&self.host_key);
        v
    }
}

impl TryFrom<Vec<u8>> for Box<RpsPeer> {
    type Error = anyhow::Error;

    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        let mut len = 4;
        if raw.len() < len {
            return Err(anyhow::Error::msg(
                "Cannot parse RpsPeer: Invalid number of bytes",
            ));
        }

        let port = u16::from_be_bytes(raw[0..2].try_into().unwrap());
        let port_map_size = raw[2];
        let reserved_v = raw[3];

        let port_map_start = len;
        len += (port_map_size * 4) as usize;
        if raw.len() < len as usize {
            return Err(anyhow::Error::msg(
                "Cannot parse RpsPeer: Invalid number of bytes",
            ));
        }

        // get port map
        let mut port_map = HashMap::new();
        for i in 0..port_map_size {
            let index = port_map_start + i as usize * 4;
            let a = u16::from_be_bytes(raw[index..(index + 2)].try_into().unwrap());
            let b = u16::from_be_bytes(raw[(index + 2)..(index + 4)].try_into().unwrap());
            port_map.insert(a, b);
        }

        let old_len = len;
        let (ip, host_key) = match (1 & reserved_v) == 1 {
            true => {
                // ipv6
                len += 16;
                if raw.len() < len {
                    return Err(anyhow::Error::msg(
                        "Cannot parse RpsPeer: Invalid number of bytes",
                    ));
                }
                let mut ip_buf = [0u8; 16];
                ip_buf.copy_from_slice(&raw[old_len..len]);
                (IpAddr::from(ip_buf), raw[len..].to_vec())
            }
            false => {
                // ipv4
                len += 4;
                if raw.len() < len {
                    return Err(anyhow::Error::msg(
                        "Cannot parse RpsPeer: Invalid number of bytes",
                    ));
                }
                let mut ip_buf = [0u8; 4];
                ip_buf.copy_from_slice(&raw[old_len..len]);
                (IpAddr::from(ip_buf), raw[len..].to_vec())
            }
        };

        Ok(Box::new(RpsPeer {
            port,
            port_map_size,
            _reserved_v: reserved_v,
            ip,
            host_key,
            port_map,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::p2p_protocol::rps_api::RpsPeer;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn unit_test_rps_messages() {
        let mut port_map = HashMap::new();
        port_map.insert(1, 2);
        port_map.insert(3, 4);
        let ip_addr = IpAddr::from_str("127.0.0.1").unwrap();
        let peer = RpsPeer::new(ip_addr, 1234, port_map.clone(), "key".as_bytes().to_vec());
        let peer2 = Box::<RpsPeer>::try_from(peer.to_be_vec()).unwrap();
        assert_eq!(Box::new(peer), peer2);

        let ip_addr = IpAddr::from_str("::1").unwrap();
        let peer = RpsPeer::new(ip_addr, 1234, port_map, "key".as_bytes().to_vec());
        let peer2 = Box::<RpsPeer>::try_from(peer.to_be_vec()).unwrap();
        assert_eq!(Box::new(peer), peer2);
    }
}
