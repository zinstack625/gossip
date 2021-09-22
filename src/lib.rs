use rand::seq::SliceRandom;
use rand::Rng;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub mod config;
pub mod neighborhood;
pub mod speach;
pub mod whisper;

struct State {
    listener_rx: mpsc::Receiver<TcpStream>,
    cipher: openssl::symm::Cipher, // this
    myself: neighborhood::Node,
    announcement: whisper::Message,
    connections: Vec<(neighborhood::Node, Option<TcpStream>)>,
    enc_key: Vec<u8>, // this
    iv: Vec<u8>,      // and this needs to go
    config: Arc<Mutex<config::Config>>,
    conf_change_sig_rx: mpsc::Receiver<usize>,
    tx: mpsc::Sender<whisper::Message>,
    rx: mpsc::Receiver<whisper::Message>,
}

fn spawn_listener() -> (mpsc::Receiver<TcpStream>, SocketAddr) {
    let port: u16 = rand::thread_rng().gen_range(7000..50000);
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

fn recv_messages(
    streams: &mut Vec<(neighborhood::Node, Option<TcpStream>)>,
    // absolute awfulness, each stream should have it's own cipher, enc_key and iv. Strong
    // reformatting material
    cipher: &openssl::symm::Cipher,
    enc_key: &[u8],
    iv: &[u8],
) -> Vec<whisper::Message> {
    let mut mailbox = Vec::<whisper::Message>::new();
    for i in streams.iter_mut() {
        if let Some(stream) = i.1.as_mut() {
            let connection_messages = speach::receive_messages_enc(stream, &cipher, &enc_key, &iv);
            mailbox.extend(connection_messages);
        }
    }
    mailbox
}

fn process_messages(
    mailbox: /* maybe remove this mut */ &mut Vec<whisper::Message>,
    client_tx: &mut mpsc::Sender<whisper::Message>,
    gossip: &mut Vec<whisper::Message>,
    newcomer_mailbox: &mut Vec<whisper::Message>,
    myself: &neighborhood::Node,
) {
    for i in mailbox.iter_mut() {
        match i.msgtype {
            whisper::MessageType::Text => {
                // send the message to a client (in debug form for now)
                client_tx
                    .send(i.clone())
                    .expect("Unable to send message to client!");
            }
            // something about this doesn't seem right
            whisper::MessageType::NewMember => {
                i.aquaintance.push(myself.uuid);
                newcomer_mailbox.push(i.clone());
            }
            whisper::MessageType::EncryptionRequest => {} // cannot happen, as those can only be unencrypted
        }
        if i.next_sender == myself.uuid {
            gossip.push(i.clone());
        }
    }
}

fn greet_newcomers(
    newcomer_mailbox: Vec<whisper::Message>,
    connections: &mut Vec<(neighborhood::Node, Option<TcpStream>)>,
    announcement: &whisper::Message,
) {
    for i in newcomer_mailbox {
        let newcomer = i.sender.clone();
        let mut announcement = announcement.clone();
        announcement.contents = String::from("gossipless");
        println!("Was told to connect to {}", newcomer.address);
        let mut greeted = false;
        for i in connections.iter() {
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
            connections.push(node);
        } else {
            // still aknowledge peer's existence
            connections.push((newcomer, None));
        }
    }
}

fn client_duty(
    client_rx: &mut mpsc::Receiver<whisper::Message>,
    config: &config::Config,
    connections: &mut Vec<(neighborhood::Node, Option<TcpStream>)>,
    myself: &neighborhood::Node,
    // absolute awfulness, each stream should have it's own cipher, enc_key and iv. Strong
    // reformatting material
    cipher: &openssl::symm::Cipher,
    enc_key: &[u8],
    iv: &[u8],
) {
    let mut messages_to_store = Vec::<whisper::Message>::new();
    let send_limit = config.max_send_peers;
    while let Ok(client_msg) = client_rx.try_recv() {
        let mut to_send =
            Vec::<&mut (neighborhood::Node, Option<TcpStream>)>::with_capacity(send_limit);
        let mut cnt = 0;
        let connection_len = connections.len();
        for i in connections.iter_mut() {
            if let Some(_) = i.1 {
                to_send.push(i);
                cnt += 1;
            }
            if cnt >= send_limit {
                break;
            }
        }
        let mut aquaintance = Vec::<u32>::with_capacity(send_limit);
        for i in to_send.iter() {
            aquaintance.push(i.0.uuid);
        }
        let need_duty_shift = aquaintance.len() < connection_len;
        let msg = crate::whisper::Message::new(
            crate::whisper::MessageType::Text,
            &myself,
            &client_msg.contents,
            aquaintance,
            match need_duty_shift {
                true => to_send.last().unwrap().0.uuid,
                false => 0,
            },
        );
        let encrypted = msg.encrypt(&cipher, &enc_key, &iv).unwrap();
        for i in to_send.iter_mut() {
            if let Some(mut stream) = i.1.as_mut() {
                speach::send_data(&mut stream, &encrypted);
            }
        }
        messages_to_store.push(msg);
    }
    store_text_messages(&config, &messages_to_store);
}

// different in that people connect to us directly here instead of us receiving gossip
fn receive_newcomers(
    listener_rx: &mut mpsc::Receiver<TcpStream>,
    announcement: &whisper::Message,
    connections: &mut Vec<(neighborhood::Node, Option<TcpStream>)>,
    myself: &neighborhood::Node,
    enc_key: &Vec<u8>,
    iv: &Vec<u8>,
) -> Vec<whisper::Message> {
    let mut newcomer_mailbox = Vec::<whisper::Message>::new();
    while let Ok(mut new_connection) = listener_rx.try_recv() {
        if let Ok(mut message) = speach::receive_greeting(&mut new_connection) {
            println!(
                "New connection from {}",
                new_connection.peer_addr().unwrap()
            );
            speach::send_data(&mut new_connection, announcement.to_string().as_bytes());
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
                        speach::send_encryption_data(
                            &mut new_connection,
                            &enc_key,
                            &temp_encrypter,
                        );
                        // ugly
                        speach::send_encryption_data(&mut new_connection, &iv, &temp_encrypter);
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
                message.aquaintance.push(myself.uuid);
                newcomer_mailbox.push(message.clone());
            }
            connections.push((message.sender.clone(), Some(new_connection)));
        }
    }
    newcomer_mailbox
}

fn spread_gossip(
    newcomer_mailbox: Vec<whisper::Message>,
    gossip: &mut Vec<whisper::Message>,
    connections: &mut Vec<(neighborhood::Node, Option<TcpStream>)>,
    send_limit: usize,
    cipher: &openssl::symm::Cipher,
    enc_key: &[u8],
    iv: &[u8],
) {
    // direct connections
    for i in newcomer_mailbox {
        let encrypted = i.encrypt(&cipher, &enc_key, &iv).unwrap();
        for j in connections.iter_mut() {
            println!(
                "Greeting from {} is aquainted with {:?}",
                i.sender.name, i.aquaintance
            );

            if !i.aquaintance.contains(&j.0.uuid) && j.1.is_some() {
                if let Some(stream) = j.1.as_mut() {
                    println!(
                        "Sending greeting to uuid {}, address {}",
                        j.0.uuid,
                        stream.peer_addr().unwrap()
                    );
                    speach::send_data(stream, &encrypted);
                }
            }
        }
    }
    // network reported
    for i in gossip.iter_mut() {
        let mut to_send =
            Vec::<&mut (neighborhood::Node, Option<TcpStream>)>::with_capacity(send_limit);
        let mut cnt = 0;
        let connection_len = connections.len();
        for j in connections.iter_mut() {
            if !i.aquaintance.contains(&j.0.uuid) {
                if let Some(_) = j.1 {
                    to_send.push(j);
                    cnt += 1;
                }
                if cnt >= send_limit {
                    break;
                }
            }
        }
        let mut aquaintance = Vec::<u32>::with_capacity(send_limit + i.aquaintance.len());
        aquaintance.append(&mut i.aquaintance);
        for i in to_send.iter() {
            aquaintance.push(i.0.uuid);
        }
        let need_duty_shift = aquaintance.len() < connection_len;
        let msg = whisper::Message::new(
            i.msgtype,
            &i.sender,
            &i.contents,
            aquaintance,
            match need_duty_shift {
                true => to_send.last().unwrap().0.uuid,
                false => 0,
            },
        );
        let encrypted = msg.encrypt(&cipher, &enc_key, &iv).unwrap();
        for i in to_send.iter_mut() {
            if let Some(mut stream) = i.1.as_mut() {
                speach::send_data(&mut stream, &encrypted);
            }
        }
    }
}

fn get_stored_messages(config: &config::Config) -> Result<Vec<whisper::Message>, std::io::Error> {
    let file = File::open(&config.stored_messages_filename)?;
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

fn store_text_messages(
    config: &config::Config,
    messages: &Vec<whisper::Message>,
) -> Result<(), std::io::Error> {
    let file = std::fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .append(true)
        .open(&config.stored_messages_filename)?;
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
        let mut mailbox = recv_messages(
            &mut state.connections,
            &state.cipher,
            &state.enc_key,
            &state.iv,
        );
        if let Ok(config) = state.config.try_lock() {
            if let Err(_) = store_text_messages(&config, &mailbox) {
                postponed_storage.extend_from_slice(&mailbox[..]);
            }
        } else {
            postponed_storage.extend_from_slice(&mailbox[..]);
        }
        let mut gossip = Vec::<whisper::Message>::new();
        let mut newcomer_mailbox = Vec::<whisper::Message>::new();
        process_messages(
            &mut mailbox,
            &mut state.tx,
            &mut gossip,
            &mut newcomer_mailbox,
            &state.myself,
        );
        greet_newcomers(
            newcomer_mailbox,
            &mut state.connections,
            &state.announcement,
        );
        let send_limit = {
            let config = state.config.lock().unwrap();
            config.max_send_peers
        };
        // input from client
        if let Ok(config) = state.config.try_lock() {
            client_duty(
                &mut state.rx,
                &config,
                &mut state.connections,
                &state.myself,
                &state.cipher,
                &state.enc_key,
                &state.iv,
            );
        }
        // direct connections
        // create gossip
        let newcomer_mailbox = receive_newcomers(
            &mut state.listener_rx,
            &state.announcement,
            &mut state.connections,
            &state.myself,
            &state.enc_key,
            &state.iv,
        );
        spread_gossip(
            newcomer_mailbox,
            &mut gossip,
            &mut state.connections,
            send_limit,
            &state.cipher,
            &state.enc_key,
            &state.iv,
        );
        if let Ok(_) = state.conf_change_sig_rx.try_recv() {
            let config = state.config.lock().unwrap();
            if let Ok(stored_messages) = get_stored_messages(&config) {
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
    let (listener_rx, local_address) = spawn_listener();
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
            openssl::rand::rand_bytes(&mut key);
            openssl::rand::rand_bytes(&mut iv);
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
