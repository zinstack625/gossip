use crate::config;
use crate::neighborhood;
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
    for i in ctx.lock().unwrap().connections.iter() {
        if i.uuid == newcomer.uuid {
            return;
        }
    }
    let connect_addr = newcomer.address.as_ref();
    if connect_addr.is_some() {
        if let Ok(node) = speach::init_connection(ctx.clone(), newcomer.address.unwrap(), false) {
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
            log::info!("Preparing to send to {} recipients", send_limit);
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
            log::info!("Connections:");
            for i in ctx.connections.iter() {
                log::info!("{}", i.to_string());
            }
            let cipher = ctx.cipher.clone();
            let enc_key = ctx.enc_key.clone();
            for i in ctx.connections.iter_mut() {
                if !to_send.contains(&i.uuid) || i.stream.is_none() {
                    continue;
                }
                log::info!("Sending to {}", i.uuid);
                openssl::rand::rand_bytes(&mut msg.next_iv);
                let encrypted = msg.encrypt(&cipher, &enc_key, &i.iv).unwrap();
                i.iv = msg.next_iv.clone();
                speach::send_data(i.stream.as_mut().unwrap(), &encrypted);
            }
        }
    }
}

fn find_sender<'a>(ctx: &'a mut config::State, msg_sender: &neighborhood::Node) -> Option<&'a mut neighborhood::Node> {
    let mut sender = None;
    for j in ctx.connections.iter_mut() {
        if *msg_sender == *j {
            sender = Some(j);
            break;
        }
    }
    sender
}

fn send_missed_messages(ctx: Arc<Mutex<config::State>>, message: &whisper::Message) {
    let mut ctx = ctx.lock().unwrap();
    let msgs = get_stored_messages(&ctx);
    if msgs.is_err() {
        return;
    }
    let msgs = msgs.unwrap();
    let mut first_missed = None;
    for j in msgs.iter().enumerate() {
        if j.1.timestamp == message.timestamp {
            first_missed = Some(j.0);
            break;
        }
    }
    let cipher = ctx.cipher.clone();
    let enc_key = ctx.enc_key.clone();
    if let Some(sender) = find_sender(&mut ctx, &message.sender) {
        if first_missed.is_some() {
            let first_missed = first_missed.unwrap();
            for mut j in msgs[first_missed..].to_vec() {
                openssl::rand::rand_bytes(&mut j.next_iv);
                let encrypted = j.encrypt(&cipher, &enc_key, &sender.iv).unwrap();
                speach::send_data(sender.stream.as_mut().unwrap(), &encrypted);
                sender.iv = j.next_iv.clone();
            }
        }
    }
}

fn send_network_info(ctx: Arc<Mutex<config::State>>, message: &whisper::Message) {
    let mut ctx = ctx.lock().unwrap();
    let mut json_con_array = json::JsonValue::new_array();
    for i in ctx.network_info.iter() {
        json_con_array.push(i.to_string());
    }
    let mut network_info = whisper::Message::new(
        whisper::MessageType::NetworkInfo,
        &ctx.myself,
        &json_con_array.to_string(),
        vec![ctx.myself.uuid],
        0,
        &vec![0u8; ctx.cipher.iv_len().unwrap_or_default()],
        std::time::SystemTime::now()
    );
    let cipher = ctx.cipher.clone();
    let enc_key = ctx.enc_key.clone();
    if let Some(sender) = find_sender(&mut ctx, &message.sender) {
        openssl::rand::rand_bytes(&mut network_info.next_iv);
        let encrypted = network_info.encrypt(&cipher, &enc_key, &sender.iv).unwrap();
        speach::send_data(sender.stream.as_mut().unwrap(), &encrypted);
        sender.iv = network_info.next_iv.clone();
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
            send_missed_messages(ctx.clone(), &message);
            send_network_info(ctx.clone(), &message);
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
            log::info!("Tree: {}", tree);
            for i in tree.members() {
                log::info!("Pre-parsed: {}", i);
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
                        ctx.lock().unwrap().network_info.push(node.clone());
                        if let Some(ipv4) = node.address {
                            if let Ok(node) = init_connection(ctx.clone(), ipv4, false) {
                                log::info!("Connected to {}", node.to_string());
                                let ctx = ctx.clone();
                                std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
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
