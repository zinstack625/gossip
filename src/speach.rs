use openssl::encrypt::{Decrypter, Encrypter};
use openssl::rsa::Rsa;
use openssl::symm::*;
use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};

use crate::neighborhood;

pub fn receive_messages_enc(
    node: &mut neighborhood::Node,
    cipher: &Cipher,
    key: &[u8],
) -> Vec<crate::whisper::Message> {
    let mut messages = Vec::<crate::whisper::Message>::new();
    if node.stream.is_none() {
        return messages;
    }
    let mut buffer_size = [0u8; 8];
    while let Ok(_) = node.stream.as_mut().unwrap().read_exact(&mut buffer_size) {
        let buffer_size = u64::from_be_bytes(buffer_size);
        let mut buffer = vec![0u8; buffer_size as usize];
        let _ = node.stream.as_mut().unwrap().read_exact(&mut buffer);
        let decrypt = Crypter::new(*cipher, Mode::Decrypt, key, Some(&node.iv));
        if decrypt.is_err() {
            return messages;
        } else {
            let mut decrypt = decrypt.unwrap();
            let decrypt_len = buffer_size as usize + cipher.block_size();
            let mut decrypted = vec![0u8; decrypt_len];
            let count = decrypt.update(&buffer, &mut decrypted).unwrap();
            decrypted.truncate(count);
            if let Ok(packet) = std::str::from_utf8(&decrypted) {
                if let Ok(msg) = crate::whisper::Message::from_str(packet) {
                    node.iv = msg.next_iv.clone();
                    messages.push(msg);
                }
            }
        }
    }
    messages
}

pub fn receive_greeting(stream: &mut TcpStream) -> Result<crate::whisper::Message, std::io::Error> {
    let mut buffer_size = [0u8; 8];
    if let Ok(_) = stream.read_exact(&mut buffer_size) {
        let buffer_size = u64::from_be_bytes(buffer_size);
        let mut buffer = vec![0u8; buffer_size as usize];
        let _ = stream.read_exact(&mut buffer);
        if let Ok(packet) = std::str::from_utf8(&buffer) {
            if let Ok(msg) = crate::whisper::Message::from_str(packet) {
                return Ok(msg);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Invalid greeting",
    ))
}

pub fn send_data(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<usize> {
    let datalen = data.len().to_be_bytes();
    let packet = &[std::io::IoSlice::new(&datalen), std::io::IoSlice::new(data)];
    let count = stream.write_vectored(packet)?;
    Ok(count)
}

pub fn init_connection(
    address: &SocketAddr,
    announcement: &crate::whisper::Message,
) -> Result<crate::neighborhood::Node, std::io::Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_nonblocking(false)?;
    send_data(&mut stream, announcement.to_string().as_bytes())?;
    if let Ok(reply) = receive_greeting(&mut stream) {
        stream
            .set_nonblocking(true)
            .expect("Unable to set TCP stream async");

        Ok(crate::neighborhood::Node::new(
            reply.sender.name,
            reply.sender.uuid,
            Some(stream),
        ))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Greeting is invalid",
        ))
    }
}

pub fn initial_connections(
    init_nodes: Vec<SocketAddr>,
    announcement: &crate::whisper::Message,
) -> Vec<crate::neighborhood::Node> {
    let mut connections = Vec::<crate::neighborhood::Node>::with_capacity(init_nodes.len());
    for i in init_nodes {
        if let Ok(node) = init_connection(&i, &announcement) {
            connections.push(node);
        } // else report that failed to connect to certain node
    }
    connections
}

pub fn get_key(
    peer: &mut crate::neighborhood::Node,
    myself: &crate::neighborhood::Node,
) -> Result<Vec<u8>, std::io::Error> {
    let temporary_rsa = Rsa::generate(2048).unwrap();
    let request = crate::whisper::Message::new(
        crate::whisper::MessageType::EncryptionRequest,
        &myself,
        &String::from_utf8(temporary_rsa.public_key_to_pem().unwrap()).unwrap(),
        Vec::<u32>::new(),
        0,
        &vec![0; 12],
    );
    let pkey = openssl::pkey::PKey::from_rsa(temporary_rsa).unwrap();
    let decrypter = Decrypter::new(&pkey).unwrap();
    if let Some(stream) = peer.stream.as_mut() {
        send_data(stream, request.to_string().as_bytes())?;
        let key = get_encryption_data(stream, &decrypter).unwrap_or_default();
        peer.iv = get_encryption_data(stream, &decrypter).unwrap_or_default();
        Ok(key)
    } else {
        panic!("Tried to get keys from unestablished connection!");
    }
}

fn get_encryption_data(
    stream: &mut TcpStream,
    decrypter: &Decrypter,
) -> Result<Vec<u8>, std::io::Error> {
    stream
        .set_nonblocking(false)
        .expect("Failed to set stream sync");
    let mut block_len = [0u8; 8];
    stream.read_exact(&mut block_len)?;
    let block_len = u64::from_be_bytes(block_len);
    let mut block = vec![0u8; block_len as usize];
    stream.read_exact(&mut block)?;
    stream
        .set_nonblocking(true)
        .expect("Failed to set stream async");
    let decrypt_len = decrypter.decrypt_len(&mut block).unwrap();
    let mut decrypt_block = vec![0u8; decrypt_len];
    let decrypt_len = decrypter.decrypt(&block, &mut decrypt_block).unwrap();
    decrypt_block.truncate(decrypt_len);
    Ok(decrypt_block)
}

pub fn send_encryption_data(
    stream: &mut TcpStream,
    block: &Vec<u8>,
    encrypter: &Encrypter,
) -> std::io::Result<usize> {
    let encrypted_blocklen = encrypter.encrypt_len(&block).unwrap();
    let mut encrypted_block = vec![0u8; encrypted_blocklen];
    let count = encrypter.encrypt(&block, &mut encrypted_block).unwrap();
    encrypted_block.truncate(count);
    let mut bytes_written = stream.write(&(encrypted_block.len() as u64).to_be_bytes())?;
    bytes_written += stream.write(&encrypted_block)?;
    stream.flush()?;
    Ok(bytes_written)
}

pub fn authenticate(node: &crate::neighborhood::Node, stream: &mut TcpStream) -> bool {
    // stub for now
    true
}
