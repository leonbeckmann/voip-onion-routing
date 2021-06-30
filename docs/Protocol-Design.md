# Challenges for Designing an anonymous P2P Protocol

## Security Goals

### Authenticity

To avoid e.g. MITM attacks we have to ensure that the origin of a receiving message is always checked against the
identity of the expected sender. This will be done via a signature based on the identity key pair.
Since a caller receives the pre-shared public identity key of the recipient from the CM/CI layer, we trust 
the identity key.

Using the trusted identity key, we can design a protocol that exchanges a shared secret between the caller and the
recipient in a way that it is ensured that only these two peers will know the secret. From the secret we can then derive
an encryption and MAC key for providing confidentiality and integrity for our communication channel. 

The shared-secret can be exchanged via any type of Diffie-Hellman key-exchange. (We have to use an ephemeral
variant i.e. DHE or ECDHE due to the reasons in 'Further Security Challenges')

Alice must not authenticate herself to the hops, since the hops must not know the caller. However,
Alice should authenticate herself to the call recipient Bob. This can be done by a Challenge-Response. 

### Confidentiality

Confidentiality of the data, routing information and padding length has to be provided via encrypting the messages
and headers using the symmetric encryption keys derived from the shared secret.

Different keys are used per direction, to avoid problems with the IV selection.

Since the packet size must be equal, we cannot simply send IVs with the packets. Therefore,
Instead, the IV is always chosen by the sender and is then encrypted or decrypted at each hop,
similar to the data, using ECB. In this way, the IV is not shared over multiple hops
to avoid packet tracking and since AES is injective, the IVs are always unique.

### Integrity

Integrity of the data has to be provided via MACs using the symmetric MAC keys derived from the shared secrets, or via
AES-GCM.

### Availability

TODO

### Privacy
Given a tunnel Alice -> X -> Y -> Bob is has to be ensured that only Alice and Bob know that they are communicating 
with each other, which means that X is not allowed  to know the successor of Y and Y is not allowed to know the
predecessor of X. In general a intermediate peer is only allowed to know its direct predecessor and successor.

Therefore, we have to ensure that no privacy-leaking information are send unencrypted vom Alice to Bob.
This also holds for the key-agreement between Alice and the intermediate hops: X, Y must not know that they are 
exchanging a key with Alice, but have to think that they are exchanging a key with any previous unknown peer, so
we do not have to use Alice's identity for key-agreements with intermediate hops. We will only single-authentication STS
protocol for key agreement, based on ECDHE. 

## Further Security Challenges

### Key Exchange via partially-established tunnels

Assume Alice wants to connect to Bob via X and Y then Alice needs different shared symmetric keys with X, Y and Bob.
Assume Alice will directly communicate with X, Y and Bob, then there is a non-reputable connection between
Alice an Bob. Since there is no shared secret yet, we cannot encrypt initial tunnel messages via some symmetric keys , 
therefore the format of the message is known, which means that sniffers would know that Alice is doing key-exchanges 
with X, Y and Bob (assumed that there are no other key-exchanges at this time). Assuming that the order of key-agreements
is deterministic, i.e. Alice is first exchanging a key with X, then with Y and finally with Bob. Then a sniffer would 
know that Bob is the recipient and privacy would be broken. To avoid this, we could shuffle the order of key-agreements 
with X,Y and Bob using a non-deterministic CSPRNG. However, a sniffer would then know at least the identity of all the 
tunnel participants and could guess the recipient regarding further analysis.

In contrast, assume firstly Alice is exchanging K1 with X and then the key-exchange between Alice and Y is sent via X, 
encrypted using K1, then a sniffer would have to sniff all the packets at every peer within a tunnel and would
have too identify which packets belong to the corresponding tunnel. This might be much harder then just sniffing packets
at a single peer, but is also possible when all peers are within a single network for example. The idea is to have a lot
of fake traffic and many nodes in the network, such that message tracking is not possible anymore.

### Why we have to use Ephemeral Diffie Hellman
Assuming we would establish the shared secret between two peers Alice and Bob via a static DH using the
long-term identity keys directly, then every time when Alice and Bob are doing a key-exchange, the
resulting shared secret would be the same. This leads to the following problem:

On the one hand side, when one of the private keys gets leaked, the shared secret for all previous session
between Alice and Bob will be known and since the key-derivation function has to be deterministic, this would also
leak the encryption and MAC keys of all previous session (No Perfect Forward Secrecy).

Assume our tunnel consists of **Alice -> X -> Y -> Bob** and the private key of Bob is leaked.
On key-exchange, Alice first crates a shared key to X, then via X to Y and then via X and Y to Bob, to ensure that
Bob is never a direct successor of Alice for this tunnel. Since Alice does only know the public identity key of Bob, the
public ECDH parameter of Alice to Bob can either be send as plaintext or encrypted via Bob's public identity key.
Since Bob is the successor of Y, Y knows that there will be a key-exchange between the caller and Bob and the public ECDH
parameter of Alice will be send via Y to Bob. Assume Y knows Bob's private key since it was leaked, then Y is able to
extract the public ECDH parameter (=pub key) of Alice, combine it with the private key of Bob and derive the ENC and MAC 
keys between Alice and Bob. Since they have used a static ECDH, these keys are valid for all previous session between Alice 
and Bob, either when Alice was the Sender and Bob was the recipient or Bob was an intermediate hop within a tunnel from 
Alice to someone else. When now Y is able to sniff packets located to Bob then Y could try to decrypt all the packets using 
the shared key between Alice and Bob. 
In this way, Y is able to read all the previous session between Alice and Bob or when Bob was just another intermediate
hop within a tunnel from Alice to someone else, Y would be able to decrypt routing header information and could
extract the successor of Bob, which would break privacy in a 2-hop-setup.

### No identity-leaking information within the handshake
Assume Alice is communicating via X and Y to Bob then it has to be ensured that the identity of Alice is not sent 
unencrypted through the tunnel. Otherwise, Y would know that the origin of the message is Alice, which is not X.  
But we want to ensure that each intermediate peer is only allowed to know the predecessor and successor. 

The identity of Alice could also be leaked via Alice's p2p address or a signature of Alice, since this could be verified 
by trying all public keys of known peers. When for example Y knows Alice then Y knows Alice's public key. When now Alice 
sends a signed and unencrypted value to Bob then Y could try to verify the signature of this message by trying out all the 
known keys, including Alice's public key. In this way, Y would also know that Alice is the origin.

However, single we only use single authentication during the handshake and encrypted challenge response for authenticate
Alice to Bob, we will not run into this issue.

### Fixed packet size
To avoid package analyze attacks we have to ensure that each packet is send with the same amount to bytes.
The padding is therefore a secret information, since otherwise an attacker could simply reduce the padding and could
then analyze the packet. There must not be any information added or removed at an intermediate hop since otherwise, the
length of the packet will change and information could be extracted about the position of the node in the tunnel.

### Packet identification while avoiding packet tracking
In the Onion setup, there exists a shared key between the origin Alice and each of the tunnel participants.
In general there is the possibility that two peers are participants of different tunnels, e.g. Bob is a recipient
of tunnel 1 and an intermediate peer of tunnel 2, for which for both Alice is the origin. Therefore, Alice has to
tell Bob which key he has to use. This also holds for the direct successor: There could be multiple tunnels where
X is the direct successor of Alice. Therefore, we have to use any kind of unencrypted tunnel / key identifier and
cannot use the source address for identifying the tunnel.

This leads to the challenge of ensuring that packet tracking is avoided. Of course, the tracking number
must not be sent between more than two intermediate peers to ensure that the packet route cannot be tracked. 

Another question would be if it is okay to leak how many packets with the same tunnel id are sent between two peers.
This could leak information that help to distinguish short calls from longer calls and also real calls from
cover traffic. 

TODO Idea: Ensure dynamic tunnel ID's that only have to be used once. These ID's can be mapped to an internal tunnel ID at
the peer. This requires some additional management overhead and storage overhead

## Onion Handshake Protocol

1. Alice selects an elliptic curve, generator point **G** and a secret **a**
2. Alice calculates the public ECDHE parameter **a * G**
3. Alice sends **{curve, G, aG}** to Bob
4. Bob generates a secret **b** and calculates the public ECDHE parameter **b * G**
5. Bob generates the shared secret **s = b * aG**
6. Bob derives encryption keys and MAC keys from **s** using a KDF   
7. Bob generates a challenge **c** for the challenge response
8. Bob generates a signature **Sig = sign(SHA256({bG, c, curve, G, aG}))** using his private identity key
9. Bob encrypts the signature Sig using the encryption key from Bob to Alice
10. Bob sends {bG, c, Sig_enc} to Alice
11. Alice calculates the shared secret **s = a * bG**
12. Alice derives the keys from **s** using  a KDF
13. Alice decrypts the signature using the encryption key from Bob to Alice
14. Alice checks the signature using the public key of Bob
16. Alice sends encrypted routing information to Bob. If Bob is the target then this contains the
response of the challenge **{sign(c, priv_key_A), pub_key_A}**
17. Bob verifies routing information (and response if Bob is the target)
