pub(crate) mod p2p_messages;
//pub(crate) mod message_codec;

// Alice -> H1 -> Bob (data)
// 1. Alice creates m = DecryptedData   // length x
// 2. Alice c = enc(k_bob, m)   // length x
// 3. Alice c_2 = enc(k_h1, c)  // length x
// 5. Alice m_3 = Frame(ID, c_2) // length z
// 6. H1 receives m_3 and extracts c_2 by parsing // length x
// 7. H1 c = dec(k_h1, c2) // length x
// 8. H1 m_4 = Frame(ID, c) // length z
// 9. Bob receives m_4 and extracts c // length x
// 10. Bob m = dec(k_bob, c) // length x DecryptedData
// 11. parsing m leads to handshake or application data by parsing

// Alice -> H1 -> Bob (handshake data)
// 1. Alice creates m = handshakeData   // length x
// 3. Alice c = enc(k_h1, m)  // length x
// 5. Alice m_2 = Frame(ID, c) // length z
// 6. H1 receives m_2 and extracts c by parsing // length x
// 7. H1 m = dec(k_h1, c) // length x
// 8. H1 m_3 = Frame(1, m) // length z
// 9. Bob receives m_3 and extracts m // length x
// 11. parsing m leads to handshake data

// Alice -> Bob (handshake data)
// 1. Alice creates m = handshakeData // length x
// 2. Alice sends m_2 = Frame(ID, m) // length z
// 3. Bob receives m_2 and extracts m by parsing // length x

// Alice -> Bob (encrypted handshake data)
// 1. Alice creates m = DecryptedHandshakeData // length x
// 2. Alice c = enc(k_bob, m) // length x
// 3. Alice sends m_2 = Frame(ID, c) // length z
// 4. Bob receives m_2 and extracts c by parsing // length x
// 5. m = dec(k_bob, c) // length x
// 6. DecryptedHandshakeData by parsing

#[cfg(test)]
mod tests {
    use crate::p2p_protocol::messages::p2p_messages::TunnelFrame;
    use protobuf::Message;

    #[test]
    fn unit_test() {
        let mut frame = TunnelFrame::new();
        frame.set_frameId(1);
        println!("{:?}", frame.compute_size());
        println!("{:?}", frame.write_to_bytes().unwrap());
    }
}
