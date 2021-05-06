
use std::net::{SocketAddrV4, SocketAddrV6};

mod config_parser;
mod api_protocol;
mod p2p_protocol;

pub(crate) enum CustomSocketAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Hostname(String, u16)
}

impl CustomSocketAddr {
    pub fn is_ipv4(&self) -> bool {
        match self {
            CustomSocketAddr::V4(_) => true,
            _ => false
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match self {
            CustomSocketAddr::V6(_) => true,
            _ => false
        }
    }

    pub fn is_hostname(&self) -> bool {
        match self {
            CustomSocketAddr::Hostname(_,_) => true,
            _ => false
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            CustomSocketAddr::V4(ip) => ip.port(),
            CustomSocketAddr::V6(ip) => ip.port(),
            CustomSocketAddr::Hostname(_, port) => *port
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
