use crate::config;
use crate::speach;
use crate::speach::init_connection;
use crate::whisper;
use std::io::Result;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub fn greet_newcomer(ctx: Arc<Mutex<config::State>>, msg: whisper::Message) {
    let newcomer = msg.sender.clone();
    for i in ctx.lock().unwrap().connections.iter() {
        if newcomer == *i {
            return;
        }
    }
    let address = newcomer.address.as_ref();
    if address.is_some() {
        log::info!("Was told to connect to {}", address.unwrap().to_string());
    }
    let addressv6 = newcomer.addressv6.as_ref();
    if addressv6.is_some() {
        log::info!("Was told to connect to {}", addressv6.unwrap().to_string());
    }
    for i in ctx.lock().unwrap().connections.iter() {
        if i.uuid == newcomer.uuid {
            return;
        }
    }
    let connect_addr = newcomer.address.as_ref();
    let connect_addrv6 = newcomer.addressv6.as_ref();
    if connect_addr.is_some() {
        if let Ok(node) = speach::init_connection(ctx.clone(), newcomer.address.unwrap(), false) {
            let ctx = ctx.clone();
            std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
        }
    } else if connect_addrv6.is_some() {
        if let Ok(node) = speach::init_connection(ctx.clone(), newcomer.addressv6.unwrap(), false) {
            let ctx = ctx.clone();
            std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
        }
    }
}

pub fn client_duty(
    ctx: Arc<Mutex<config::State>>,
    client_rx: std::sync::mpsc::Receiver<whisper::Message>,
) {
    loop {
        if let Ok(mut msg) = client_rx.recv() {
            msg.aquaintance.push(ctx.lock().unwrap().myself.uuid);
            msg.sender = ctx.lock().unwrap().myself.clone();
            msg.next_iv = vec![0u8; ctx.lock().unwrap().cipher.iv_len().unwrap()];
            let send_limit = ctx.lock().unwrap().config.lock().unwrap().max_send_peers;
            let mut to_send = Vec::<u32>::with_capacity(send_limit);
            for i in ctx.lock().unwrap().connections.iter() {
                if to_send.len() < send_limit
                    && i.stream.is_some()
                    && !msg.aquaintance.contains(&i.uuid)
                {
                    to_send.push(i.uuid);
                    msg.aquaintance.push(i.uuid);
                } else {
                    break;
                }
            }
            if let Some(last_recvr) = to_send.last() {
                msg.next_sender = *last_recvr;
            } else {
                continue;
            }
            let mut ctx = ctx.lock().unwrap();
            let cipher = ctx.cipher.clone();
            let enc_key = ctx.enc_key.clone();
            for i in ctx.connections.iter_mut() {
                if !to_send.contains(&i.uuid) || i.stream.is_none() {
                    continue;
                }
                openssl::rand::rand_bytes(&mut msg.next_iv);
                let encrypted = msg.encrypt(&cipher, &enc_key, &i.iv).unwrap();
                i.iv = msg.next_iv.clone();
                speach::send_data(i.stream.as_mut().unwrap(), &encrypted);
            }
        }
    }
}

pub fn process_message(ctx: Arc<Mutex<config::State>>, message: whisper::Message) {
    let myself_uuid = ctx.lock().unwrap().myself.uuid;
    if message.next_sender == myself_uuid {
        // send that to gossiper
        ctx.lock().unwrap().gossiper_tx.send(message.clone());
    }
    match message.msgtype {
        whisper::MessageType::Text => {
            // send the message to a client (in debug form for now)
            ctx.lock()
                .unwrap()
                .tx
                .send(message)
                .expect("Unable to send message to client!");
        }
        // TODO: deprecating
        whisper::MessageType::NewMember => {
            greet_newcomer(ctx, message);
        }
        whisper::MessageType::MissedMessagesRequest => {
            // send missed messages
            // better to get mutex for the whole operation
            let mut ctx = ctx.lock().unwrap();
            let cipher = ctx.cipher.clone();
            let enc_key = ctx.enc_key.clone();
            let myself = ctx.myself.clone();
            let msgs = get_stored_messages(&ctx);
            if msgs.is_err() {
                return;
            }
            let msgs = msgs.unwrap();
            let mut sender = None;
            let mut json_con_array = json::JsonValue::new_array();
            for j in ctx.connections.iter_mut() {
                json_con_array.push(j.to_string());
                if message.sender == *j {
                    sender = Some(j);
                    break;
                }
            }
            if sender.is_none() {
                return;
            }
            let sender = sender.unwrap();
            let mut first_missed = None;
            for j in msgs.iter().enumerate() {
                if j.1.timestamp == message.timestamp {
                    first_missed = Some(j.0);
                    break;
                }
            }
            if first_missed.is_some() {
                let first_missed = first_missed.unwrap();
                for mut j in msgs[first_missed..].to_vec() {
                    openssl::rand::rand_bytes(&mut j.next_iv);
                    let encrypted = j.encrypt(&cipher, &enc_key, &sender.iv).unwrap();
                    speach::send_data(sender.stream.as_mut().unwrap(), &encrypted);
                    sender.iv = j.next_iv.clone();
                }
            }
            // send network info
            let mut network_info = whisper::Message::new(
                whisper::MessageType::NetworkInfo,
                &myself,
                &json_con_array.to_string(),
                vec![myself.uuid],
                0,
                &vec![0u8; cipher.iv_len().unwrap_or_default()],
                std::time::SystemTime::now()
            );
            openssl::rand::rand_bytes(&mut network_info.next_iv);
            let encrypted = network_info.encrypt(&cipher, &enc_key, &sender.iv).unwrap();
            speach::send_data(sender.stream.as_mut().unwrap(), &encrypted);
            sender.iv = network_info.next_iv.clone();
        }
        // cannot happen, as those can only be unencrypted
        // and that is processed elsewhere, don't do anything
        whisper::MessageType::EncryptionRequest => {},
        whisper::MessageType::NetworkInfo => {
            let tree = json::parse(&message.contents);
            if tree.is_err() {
                return;
            }
            let tree = tree.unwrap();
            let myself = ctx.lock().unwrap().myself.clone();
            for i in tree.members() {
                if let Some(field) = i.as_str() {
                    log::info!("Field: {}", field);
                    if let Ok(node) = crate::neighborhood::Node::from_str(field) {
                        for i in ctx.lock().unwrap().connections.iter() {
                            if *i == node {
                                continue;
                            }
                        }
                        if node == myself {
                            continue;
                        }
                        if let Some(ipv4) = node.address {
                            if let Ok(node) = init_connection(ctx.clone(), ipv4, true) {
                                ctx.lock().unwrap().connections.push(node.clone());
                                let ctx = ctx.clone();
                                std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
                                return;
                            }
                        }
                        if let Some(ipv6) = node.addressv6 {
                            if let Ok(node) = init_connection(ctx.clone(), ipv6, true) {
                                ctx.lock().unwrap().connections.push(node.clone());
                                let ctx = ctx.clone();
                                std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn get_stored_messages(ctx: &config::State) -> Result<Vec<whisper::Message>> {
    let db = sled::open(match ctx.config.lock() {
        Ok(cfg) => cfg.stored_messages_filename.clone(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "db poisoned",
            ))
        }
    })
    .expect("Unable to open messages db");

    let mut recvd_msgs = Vec::<whisper::Message>::new();
    for i in db.iter() {
        if i.is_err() {
            continue;
        }
        let i = i.unwrap();
        if let Ok(string) = std::str::from_utf8(&i.1) {
            if let Ok(msg) = whisper::Message::from_str(string) {
                if msg.msgtype == whisper::MessageType::Text {
                    recvd_msgs.push(msg);
                }
            }
        }
    }
    Ok(recvd_msgs)
}

pub fn store_text_messages(
    ctx: Arc<Mutex<config::State>>,
    messages: &Vec<whisper::Message>,
) -> Result<()> {
    let ctx = ctx.lock().unwrap();
    let db = sled::open(match ctx.config.lock() {
        Ok(cfg) => cfg.stored_messages_filename.clone(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "db poisoned",
            ))
        }
    })
    // maybe don't crash here?
    .expect("Unable to open messages db");
    for i in messages {
        db.insert(
            i.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_ne_bytes(),
            i.to_string().as_bytes(),
        );
    }
    Ok(())
}

pub fn store_text_message(
    ctx: Arc<Mutex<config::State>>,
    message: &whisper::Message,
) -> Result<()> {
    let ctx = ctx.lock().unwrap();
    let db = sled::open(match ctx.config.lock() {
        Ok(cfg) => cfg.stored_messages_filename.clone(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "db poisoned",
            ))
        }
    })
    // maybe don't crash here?
    .expect("Unable to open messages db");
    db.insert(
        message
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_ne_bytes(),
        message.to_string().as_bytes(),
    );
    Ok(())
}
