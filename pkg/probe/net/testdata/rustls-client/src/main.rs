// Test client: connects to 127.0.0.1:PORT over TLS (accepting any
// certificate), sends a WebSocket upgrade request and one masked text frame,
// then prints what it reads until the server closes.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
struct AnyCert;
impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes() }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = &args[1];
    let msg = args.get(2).cloned().unwrap_or_else(|| "hello".to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .dangerous().with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    let name = ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut sock = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let req = format!("GET /ws?x=1 HTTP/1.1\r\nHost: localhost:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", port);
    tls.write_all(req.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") { tls.read_exact(&mut b).unwrap(); head.push(b[0]); }
    let mask = [1u8, 2, 3, 4];
    let mut frame = vec![0x81u8, 0x80 | msg.len() as u8];
    frame.extend_from_slice(&mask);
    for (i, c) in msg.bytes().enumerate() { frame.push(c ^ mask[i % 4]); }
    tls.write_all(&frame).unwrap();
    let mut rest = Vec::new();
    let _ = tls.read_to_end(&mut rest);
    println!("{} {}", String::from_utf8_lossy(&head).lines().next().unwrap_or(""), rest.len());
}
