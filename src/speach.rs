use openssl::{
    encrypt::{Decrypter, Encrypter},
    rsa::Rsa,
    symm::*,
};
use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{config, neighborhood, speach, whisper};

fn resend_encryption(ctx: &mut config::State, node: &mut neighborhood::Node) {
     let public_key = encryption_request.contents.as_bytes();
     let pkey_temp = openssl::pkey::PKey::public_key_from_pem(public_key).unwrap();
     let temp_encrypter = openssl::encrypt::Encrypter::new(&pkey_temp).unwrap();
     speach::send_encryption_data(
         node.stream.as_mut().unwrap(),
         &ctx.enc_key,
         &temp_encrypter,
     );
     speach::send_encryption_data(
         node.stream.as_mut().unwrap(),
         &ctx.myself.iv,
         &temp_encrypter,
     );
     node.iv = ctx.myself.iv.clone();
     for i in ctx.connections.iter_mut() {
         if node == *i {
             i.iv = node.iv.clone();
             break;
         }
     }
}

pub fn receive_messages_enc(ctx: Arc<Mutex<config::State>>, mut node: neighborhood::Node) {
    if node.stream.is_none() {
        return;
    }
    let mut buffer_size = [0u8; 8];
    loop {
        let read_result = node.stream.as_mut().unwrap().read_exact(&mut buffer_size);
        {
            let mut ctx = ctx.lock().unwrap();
            if read_result.is_err() {
                continue;
            }
            let buffer_size = u64::from_be_bytes(buffer_size);
            let mut buffer = vec![0u8; buffer_size as usize];
            let _ = node.stream.as_mut().unwrap().read_exact(&mut buffer);
            let mut connection_relevant = false;
            for i in ctx.connections.iter() {
                if node == *i {
                    node.iv = i.iv.clone();
                    connection_relevant = true;
                    break;
                }
            }
            if !connection_relevant {
                return;
            }
            if let Ok(packet) = std::str::from_utf8(&buffer) {
                if let Ok(encryption_request) = whisper::Message::from_str(packet) {
                    resend_encryption(&mut ctx, &mut node);
                }
                continue;
            }
            let decrypt = Crypter::new(ctx.cipher, Mode::Decrypt, &ctx.enc_key, Some(&node.iv));
            if decrypt.is_err() {
                continue;
            } else {
                let mut decrypt = decrypt.unwrap();
                let decrypt_len = buffer_size as usize + ctx.cipher.block_size();
                let mut decrypted = vec![0u8; decrypt_len];
                let count = decrypt.update(&buffer, &mut decrypted).unwrap();
                decrypted.truncate(count);
                if let Ok(packet) = std::str::from_utf8(&decrypted) {
                    if let Ok(msg) = whisper::Message::from_str(packet) {
                        node.iv = msg.next_iv.clone();
                        for i in ctx.connections.iter_mut() {
                            if node == *i {
                                i.iv = node.iv.clone();
                            }
                        }
                        ctx.receiver_tx.send(msg);
                    } else {
                        // need to reestablish encryption
                        let key = get_key(&mut node, &ctx.myself).unwrap_or_default();
                        if key != ctx.enc_key {
                            // other side lost the key, abort
                            return;
                        }
                    }
                } else {
                    let key = get_key(&mut node, &ctx.myself).unwrap_or_default();
                    if key != ctx.enc_key {
                        return;
                    }
                }
            }
        }
    }
}

pub fn receive_greeting(stream: &mut TcpStream) -> Result<whisper::Message, std::io::Error> {
    let mut buffer_size = [0u8; 8];
    stream.set_read_timeout(Some(Duration::new(30, 0)))?;
    if let Ok(_) = stream.read_exact(&mut buffer_size) {
        log::info!("Got greeting!");
        let buffer_size = u64::from_be_bytes(buffer_size);
        let mut buffer = vec![0u8; buffer_size as usize];
        let _ = stream.read_exact(&mut buffer);
        if let Ok(packet) = std::str::from_utf8(&buffer) {
            if let Ok(msg) = whisper::Message::from_str(packet) {
                log::info!("Greeting: {}", msg.to_string());
                return Ok(msg);
            }
        }
    }
    stream.set_read_timeout(None)?;
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
    ctx: Arc<Mutex<config::State>>,
    address: SocketAddr,
    announce_me: bool,
) -> Result<neighborhood::Node, std::io::Error> {
    log::info!("Connecting to {}", address);
    let mut stream = TcpStream::connect(address)?;
    stream.set_nonblocking(false)?;
    let mut announcement = ctx.lock().unwrap().announcement.clone();
    if !announce_me {
        announcement.contents = "gossipless".to_string();
    }
    send_data(&mut stream, announcement.to_string().as_bytes())?;
    if let Ok(reply) = receive_greeting(&mut stream) {
        let mut peer = neighborhood::Node::new(reply.sender.name, reply.sender.uuid, Some(stream));
        if let Ok(mut ctx) = ctx.lock() {
            if let Ok(key) = get_key(&mut peer, &ctx.myself) {
                ctx.enc_key = key;
            }
            ctx.connections.push(peer.clone());
        }
        log::info!("Connection inited");
        Ok(peer)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Greeting is invalid",
        ))
    }
}

pub fn initial_connections(ctx: Arc<Mutex<config::State>>, init_nodes: Vec<SocketAddr>) -> bool {
    let mut at_least_some = false;
    for i in init_nodes {
        if let Ok(node) = init_connection(ctx.clone(), i, true) {
            at_least_some = true;
            ctx.lock().unwrap().network_info.push(node.clone());
            let ctx = ctx.clone();
            std::thread::spawn(move || receive_messages_enc(ctx, node));
        } // else report that failed to connect to certain node
    }
    at_least_some
}

pub fn get_key(
    peer: &mut neighborhood::Node,
    myself: &neighborhood::Node,
) -> Result<Vec<u8>, std::io::Error> {
    let temporary_rsa = Rsa::generate(2048).unwrap();
    let request = whisper::Message::new(
        whisper::MessageType::EncryptionRequest,
        &myself,
        &String::from_utf8(temporary_rsa.public_key_to_pem().unwrap()).unwrap(),
        Vec::<u32>::new(),
        0,
        &vec![0; 12],
        std::time::SystemTime::now(),
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

pub fn get_encryption_data(
    stream: &mut TcpStream,
    decrypter: &Decrypter,
) -> Result<Vec<u8>, std::io::Error> {
    let mut block_len = [0u8; 8];
    stream.read_exact(&mut block_len)?;
    let block_len = u64::from_be_bytes(block_len);
    let mut block = vec![0u8; block_len as usize];
    stream.read_exact(&mut block)?;
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
    send_data(stream, &encrypted_block)
}

pub fn authenticate(node: &neighborhood::Node, stream: &mut TcpStream) -> bool {
    // stub for now
    true
}
