use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};

pub fn receive_messages(stream: &mut TcpStream) -> Vec<crate::whisper::Message> {
    let mut messages = Vec::<crate::whisper::Message>::new();
    let mut buffer: [u8; 4096] = [0; 4096];
    while let Ok(bytes_n) = stream.read(&mut buffer) {
        let mut bytes_vector = buffer.to_vec();
        bytes_vector.resize(bytes_n, 0);
        for split in bytes_vector.split(|byte| *byte == 0) {
            if let Ok(packet) = std::str::from_utf8(split) {
                if let Ok(msg) = crate::whisper::Message::from_str(packet) {
                    messages.push(msg);
                }
            }
        }
    }
    messages
}

pub fn receive_greeting(stream: &mut TcpStream) -> Result<crate::whisper::Message, std::io::Error> {
    let mut buffer: [u8; 4096] = [0; 4096];
    let bytes_n = stream.read(&mut buffer)?;
    if let Ok(packet) = std::str::from_utf8(&buffer[..bytes_n - 1]) {
        if let Ok(msg) = crate::whisper::Message::from_str(packet) {
            return Ok(msg);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Something happened",
    ))
}

pub fn send_message(
    stream: &mut TcpStream,
    msg: &crate::whisper::Message,
) -> std::io::Result<usize> {
    let mut packet = msg.to_string().as_bytes().to_vec();
    packet.push(0);
    let bytes_written = stream.write(&packet[..])?;
    stream.flush()?;
    Ok(bytes_written)
}

pub fn init_connection(
    address: &SocketAddr,
    announcement: &crate::whisper::Message,
) -> Result<(crate::neighborhood::Node, TcpStream), std::io::Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_nonblocking(false);
    send_message(&mut stream, &announcement);
    if let Ok(reply) = receive_greeting(&mut stream) {
        stream
            .set_nonblocking(true)
            .expect("Unable to set TCP stream async");
        Ok((reply.sender, stream))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Greeting is invalid",
        ))
    }
}

pub fn initial_connections(
    init_nodes: Vec<String>,
    announcement: &crate::whisper::Message,
) -> Vec<(crate::neighborhood::Node, TcpStream)> {
    let mut connections = Vec::<(crate::neighborhood::Node, TcpStream)>::new();
    connections.reserve(init_nodes.len());
    for i in init_nodes {
        if let Ok(address) = i.parse() {
            if let Ok(node) = init_connection(&address, &announcement) {
                connections.push(node);
            }
        }
    }
    connections
}
