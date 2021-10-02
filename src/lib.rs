use rand::seq::SliceRandom;
use rand::Rng;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub mod config;
pub mod neighborhood;
mod speach;
pub mod whisper;

struct State {
    listener_rx: mpsc::Receiver<TcpStream>,
    cipher: openssl::symm::Cipher,
    myself: neighborhood::Node,
    announcement: whisper::Message,
    // the node should probably contain it's stream, that'll be nice
    connections: Vec<(neighborhood::Node, Option<TcpStream>)>,
    enc_key: Vec<u8>,
    iv: Vec<u8>, // this needs to go
    config: Arc<Mutex<config::Config>>,
    conf_change_sig_rx: mpsc::Receiver<usize>,
    tx: mpsc::Sender<whisper::Message>,
    rx: mpsc::Receiver<whisper::Message>,
}

fn spawn_listener(port: u16) -> (mpsc::Receiver<TcpStream>, SocketAddr) {
    let mut local_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let mut listener = TcpListener::bind(local_address);
    while listener.is_err() {
        local_address.set_port(rand::thread_rng().gen_range(7000..50000));
        listener = TcpListener::bind(local_address);
    }
    let listener = listener.unwrap();
    let (listener_tx, listener_rx) = mpsc::channel();
    let _listener_thread = thread::spawn(move || {
        for i in listener.incoming() {
            if let Ok(new_connection) = i {
                listener_tx
                    .send(new_connection)
                    .expect("Unable to send new connection to server!");
            }
        }
    });
    println!("Listening at {}", local_address);
    (listener_rx, local_address)
}

fn recv_messages(ctx: &mut State) -> Vec<whisper::Message> {
    let mut mailbox = Vec::<whisper::Message>::new();
    for i in ctx.connections.iter_mut() {
        if let Some(stream) = i.1.as_mut() {
            let connection_messages =
                speach::receive_messages_enc(stream, &ctx.cipher, &ctx.enc_key, &ctx.iv);
            mailbox.extend(connection_messages);
        }
    }
    mailbox
}

fn process_messages(
    ctx: &mut State,
    mailbox: /* maybe remove this mut */ &mut Vec<whisper::Message>,
    gossip: &mut Vec<whisper::Message>,
    newcomer_mailbox: &mut Vec<whisper::Message>,
) {
    for i in mailbox.iter_mut() {
        match i.msgtype {
            whisper::MessageType::Text => {
                // send the message to a client (in debug form for now)
                ctx.tx
                    .send(i.clone())
                    .expect("Unable to send message to client!");
            }
            // something about this doesn't seem right
            whisper::MessageType::NewMember => {
                i.aquaintance.push(ctx.myself.uuid);
                newcomer_mailbox.push(i.clone());
            }
            whisper::MessageType::EncryptionRequest => {} // cannot happen, as those can only be unencrypted
        }
        if i.next_sender == ctx.myself.uuid {
            gossip.push(i.clone());
        }
    }
}

fn greet_newcomers(ctx: &mut State, newcomer_mailbox: Vec<whisper::Message>) {
    for i in newcomer_mailbox {
        let newcomer = i.sender.clone();
        let mut announcement = ctx.announcement.clone();
        announcement.contents = String::from("gossipless");
        println!("Was told to connect to {}", newcomer.address);
        let mut greeted = false;
        for i in ctx.connections.iter() {
            if i.0.uuid == newcomer.uuid {
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
            ctx.connections.push((newcomer, None));
        }
    }
}

// here it is fine to process streams for each message, because the message will
fn client_duty(ctx: &mut State) {
    let mut to_send = Vec::<u32>::with_capacity(ctx.connections.len());
    let mut send_limit: usize;
    {
        send_limit = ctx.config.try_lock().unwrap().max_send_peers;
    }
    for i in ctx.connections.iter() {
        if send_limit == 0 {
            break;
        }
        if i.1.is_some() {
            to_send.push(i.0.uuid);
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
        for j in client_msgs.iter() {
            let encrypted = j.encrypt(&ctx.cipher, &ctx.enc_key, &ctx.iv).unwrap();
            speach::send_data(i.1.as_mut().unwrap(), &encrypted);
        }
    }
}

// different in that people connect to us directly here instead of us receiving gossip
fn receive_newcomers(ctx: &mut State) -> Vec<whisper::Message> {
    let mut newcomer_mailbox = Vec::<whisper::Message>::new();
    while let Ok(mut new_connection) = ctx.listener_rx.try_recv() {
        if let Ok(mut message) = speach::receive_greeting(&mut new_connection) {
            println!(
                "New connection from {}",
                new_connection.peer_addr().unwrap()
            );
            if speach::send_data(&mut new_connection, ctx.announcement.to_string().as_bytes())
                .is_err()
            {
                // failed to connect to this peer
                continue;
            }
            // possibly always true
            if !message.contents.contains("gossipless") {
                // sender should ask about encryption now
                let requests = speach::receive_greeting(&mut new_connection);
                new_connection.set_nonblocking(true).unwrap();
                let mut encryption_request: Option<whisper::Message> = None;
                for i in requests {
                    if i.msgtype == whisper::MessageType::EncryptionRequest {
                        encryption_request = Some(i);
                    }
                }
                if let Some(encryption_request) = encryption_request {
                    let public_key = encryption_request.contents.as_bytes();
                    let pkey_temp = openssl::pkey::PKey::public_key_from_pem(public_key).unwrap();
                    let temp_encrypter = openssl::encrypt::Encrypter::new(&pkey_temp).unwrap();
                    if speach::authenticate(&encryption_request.sender, &mut new_connection) {
                        // TODO: think about what to do when this fails
                        speach::send_encryption_data(
                            &mut new_connection,
                            &ctx.enc_key,
                            &temp_encrypter,
                        );
                        // ugly
                        speach::send_encryption_data(&mut new_connection, &ctx.iv, &temp_encrypter);
                    }
                }
            } else {
                new_connection.set_nonblocking(true).unwrap();
            }
            // sender doesn't know it's address, so we tell everyone where from we got the
            // message
            message
                .sender
                .address
                .set_ip(new_connection.peer_addr().unwrap().ip());
            if !message.contents.contains("gossipless") {
                message.aquaintance.push(ctx.myself.uuid);
                newcomer_mailbox.push(message.clone());
            }
            ctx.connections
                .push((message.sender.clone(), Some(new_connection)));
        }
    }
    newcomer_mailbox
}

fn spread_gossip(ctx: &mut State, mailbox: Vec<whisper::Message>) {
    let mut to_send = Vec::<u32>::with_capacity(ctx.connections.len());
    for i in ctx.connections.iter() {
        if i.1.is_some() {
            to_send.push(i.0.uuid);
        }
    }
    // mutex should be dropped right away, as there's no name assigned to mutex handler,
    // meaning it'll get dropped right away
    let mut send_limit = ctx.config.try_lock().unwrap().max_send_peers;
    // it's better to modify the mailbox right here
    for i in ctx.connections.iter_mut() {
        if send_limit == 0 {
            return;
        }
        if i.1.is_none() {
            continue;
        }
        // it is essential to send each and every message here if possible, otherwise data will be lost in the network
        for mut j in mailbox.clone() {
            if !j.aquaintance.contains(&i.0.uuid) {
                // have to let the receiver know who's seen the message already
                for k in to_send.iter() {
                    j.aquaintance.push(*k);
                }
                j.next_sender = *to_send.last().unwrap();
                // every time iv is pulled out of context, a kitten dies
                let encrypted = j.encrypt(&ctx.cipher, &ctx.enc_key, &ctx.iv).unwrap();
                // TODO: ask someone else to deliver this message if this fails
                speach::send_data(i.1.as_mut().unwrap(), &encrypted);
            }
        }
        send_limit -= 1;
    }
}

fn get_stored_messages(ctx: &mut State) -> Result<Vec<whisper::Message>> {
    let file = File::open(&ctx.config.try_lock().unwrap().stored_messages_filename)?;
    let msg_database = BufReader::new(file);
    let mut stored_messages = Vec::<whisper::Message>::new();
    for i in msg_database.lines() {
        if let Ok(line) = i {
            if let Ok(message) = whisper::Message::from_str(line.as_str()) {
                stored_messages.push(message);
            }
        }
    }
    Ok(stored_messages)
}

fn store_text_messages(ctx: &mut State, messages: &Vec<whisper::Message>) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .append(true)
        .open(&ctx.config.try_lock().unwrap().stored_messages_filename)?;
    let mut msg_database = BufWriter::new(file);
    for i in messages.iter() {
        if i.msgtype == whisper::MessageType::Text {
            let mut modified_message = i.to_string();
            modified_message.push('\n');
            msg_database.write(modified_message.as_bytes())?;
        }
    }
    Ok(())
}

fn server_thread(mut state: State) {
    let mut postponed_storage = Vec::<whisper::Message>::new();
    loop {
        let mut mailbox = recv_messages(&mut state);
        if let Err(_) = store_text_messages(&mut state, &mailbox) {
            postponed_storage.extend_from_slice(&mailbox[..]);
        }
        let mut gossip = Vec::<whisper::Message>::new();
        let mut newcomer_mailbox = Vec::<whisper::Message>::new();
        process_messages(&mut state, &mut mailbox, &mut gossip, &mut newcomer_mailbox);
        greet_newcomers(&mut state, newcomer_mailbox);
        let send_limit = {
            let config = state.config.lock().unwrap();
            config.max_send_peers
        };
        // input from client
        client_duty(&mut state);
        // direct connections
        // create gossip
        let mut newcomer_mailbox = receive_newcomers(&mut state);
        //if newcomer_mailbox.is_ok() {
        gossip.append(&mut newcomer_mailbox);
        //}
        spread_gossip(&mut state, gossip);
        if let Ok(_) = state.conf_change_sig_rx.try_recv() {
            if let Ok(stored_messages) = get_stored_messages(&mut state) {
                for i in stored_messages {
                    match i.msgtype {
                        whisper::MessageType::Text => {
                            state.tx.send(i).expect("Unable to send message to client!");
                        }
                        _ => {}
                    }
                }
            }
        }
        thread::sleep(std::time::Duration::from_millis(200));
    }
}

pub fn spawn_server(
    client_name: String,
    init_nodes: Vec<SocketAddr>,
    config_rx: mpsc::Receiver<config::Config>,
) -> (
    mpsc::Sender<whisper::Message>,
    mpsc::Receiver<whisper::Message>,
) {
    // initializing stuff
    let (listener_rx, local_address) = spawn_listener(42378);
    let uuid: u32 = rand::thread_rng().gen();
    println!("I am {}", uuid);
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let myself = neighborhood::Node::new(&client_name, uuid, &local_address);
    let announcement = whisper::Message::new(
        whisper::MessageType::NewMember,
        &myself,
        &String::from(""),
        vec![uuid],
        0,
    );
    let mut connections = speach::initial_connections(init_nodes, &announcement);
    let (enc_key, iv) = match connections.is_empty() {
        true => {
            let mut iv = vec![0u8; cipher.iv_len().unwrap()];
            let mut key = vec![0u8; cipher.key_len()];
            openssl::rand::rand_bytes(&mut key).expect("Unable to set up main key");
            openssl::rand::rand_bytes(&mut iv).expect("Unable to set up iv");
            (key, iv)
        }
        false => speach::get_key_and_iv(
            connections.choose_mut(&mut rand::thread_rng()).unwrap(),
            &myself,
        )
        .unwrap(),
    };
    let (conf_change_sig_tx, conf_change_sig_rx) = mpsc::channel();
    let config = Arc::new(Mutex::new(config::Config::new()));
    let receiver_config = config.clone();
    let _configurator_thread = thread::spawn(move || loop {
        if let Ok(new_config) = config_rx.recv() {
            let mut config = receiver_config.lock().unwrap();
            *config = new_config;
            conf_change_sig_tx.send(1).expect("Server must have died");
        }
    });
    let (tx, client_rx) = mpsc::channel();
    let (client_tx, rx) = mpsc::channel();
    let init_state = State {
        listener_rx,
        cipher,
        myself,
        announcement,
        connections,
        enc_key,
        iv,
        config,
        conf_change_sig_rx,
        tx,
        rx,
    };
    let _server_thread = thread::spawn(move || server_thread(init_state));
    (client_tx, client_rx)
}
