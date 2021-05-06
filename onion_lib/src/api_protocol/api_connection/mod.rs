use tokio::net::TcpStream;

pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Connection {
        Connection { stream }
    }
}
