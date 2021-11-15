use crate::config;
use crate::speach;
use crate::whisper;
use std::io::Result;

pub fn greet_newcomers(ctx: &mut config::State, newcomer_mailbox: Vec<whisper::Message>) {
    for i in newcomer_mailbox {
        let newcomer = i.sender.clone();
        let mut announcement = ctx.announcement.clone();
        announcement.contents = String::from("gossipless");
        println!("Was told to connect to {}", newcomer.address.to_string());
        let mut greeted = false;
        for i in ctx.connections.iter() {
            if i.uuid == newcomer.uuid {
                greeted = true;
                break;
            }
        }
        if greeted {
            // already connected
            return;
        }
        if let Ok(node) = speach::init_connection(&newcomer.address, &announcement) {
            ctx.connections.push(node);
        } else {
            // still aknowledge peer's existence
            ctx.connections.push(newcomer);
        }
    }
}

// here it is fine to process streams for each message, because the message will
pub fn client_duty(ctx: &mut config::State) {
    let mut to_send = Vec::<u32>::with_capacity(ctx.connections.len());
    let mut send_limit = ctx.config.try_lock().unwrap().max_send_peers;
    for i in ctx.connections.iter() {
        if send_limit == 0 {
            break;
        }
        if i.stream.is_some() {
            to_send.push(i.uuid);
        }
        send_limit -= 1;
    }
    let mut client_msgs = Vec::<whisper::Message>::new();
    while let Ok(mut client_msg) = ctx.rx.try_recv() {
        client_msg.aquaintance = to_send.clone();
        client_msg.next_sender = match to_send.len() < ctx.connections.len() {
            true => *to_send.last().unwrap(),
            false => 0,
        };
        client_msg.sender = ctx.myself.clone();
        client_msgs.push(client_msg);
    }

    for i in ctx.connections.iter_mut() {
        for j in client_msgs.iter_mut() {
            openssl::rand::rand_bytes(&mut j.next_iv);
            let encrypted = j.encrypt(&ctx.cipher, &ctx.enc_key, &i.iv).unwrap();
            i.iv = j.next_iv.clone();
            speach::send_data(i.stream.as_mut().unwrap(), &encrypted);
        }
    }
}

pub fn process_messages(
    ctx: &mut config::State,
    mailbox: Vec<whisper::Message>,
    gossip: &mut Vec<whisper::Message>,
    newcomer_mailbox: &mut Vec<whisper::Message>,
) {
    for i in mailbox {
        match i.msgtype {
            whisper::MessageType::Text => {
                // send the message to a client (in debug form for now)
                ctx.tx
                    .send(i.clone())
                    .expect("Unable to send message to client!");
            }
            // something about this doesn't seem right
            whisper::MessageType::NewMember => {
                let mut msg = i.clone();
                msg.aquaintance.push(ctx.myself.uuid);
                newcomer_mailbox.push(msg);
            }
            whisper::MessageType::MissedMessagesRequest => {
                let msgs = get_stored_messages(ctx);
                if msgs.is_err() {
                    continue;
                }
                let msgs = msgs.unwrap();
                let mut first_missed = None;
                for j in msgs.iter().enumerate() {
                    if j.1.timestamp == i.timestamp {
                        first_missed = Some(j.0);
                        break;
                    }
                }
                if first_missed.is_none() {
                    continue;
                }
                let first_missed = first_missed.unwrap();
                let mut sender = None;
                for j in ctx.connections.iter_mut() {
                    if i.sender == *j {
                        sender = Some(j);
                        break;
                    }
                }
                if sender.is_none() {
                    continue;
                }
                let sender = sender.unwrap();
                for mut j in msgs[first_missed..].to_vec() {
                    openssl::rand::rand_bytes(&mut j.next_iv);
                    let encrypted = j.encrypt(&ctx.cipher, &ctx.enc_key, &sender.iv).unwrap();
                    speach::send_data(sender.stream.as_mut().unwrap(), &encrypted);
                    sender.iv = j.next_iv.clone();
                }
            }
            whisper::MessageType::EncryptionRequest => {} // cannot happen, as those can only be unencrypted
        }
        if i.next_sender == ctx.myself.uuid {
            gossip.push(i.clone());
        }
    }
}

pub fn get_stored_messages(ctx: &mut config::State) -> Result<Vec<whisper::Message>> {
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
                recvd_msgs.push(msg);
            }
        }
    }
    Ok(recvd_msgs)
}

pub fn store_text_messages(
    ctx: &mut config::State,
    messages: &Vec<whisper::Message>,
) -> Result<()> {
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
