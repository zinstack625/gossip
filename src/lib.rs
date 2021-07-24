use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

pub mod config;
pub mod neighborhood;
pub mod speach;
pub mod whisper;

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

pub fn spawn_server(
    client_name: String,
    init_nodes: Vec<SocketAddr>,
    config: config::Config,
) -> (mpsc::Sender<String>, mpsc::Receiver<String>) {
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
    let (tx, client_rx) = mpsc::channel();
    let (client_tx, rx) = mpsc::channel();
    let _server_thread = thread::spawn(move || {
        loop {
            // mailbox
            let mut newcomer_mailbox: Vec<crate::whisper::Message> = Vec::new();
            let mut mailbox = Vec::<crate::whisper::Message>::new();
            for i in connections.iter_mut() {
                if let Some(stream) = i.1.as_mut() {
                    let connection_messages =
                        speach::receive_messages_enc(stream, &cipher, &enc_key, &iv);
                    mailbox.extend(connection_messages);
                }
            }
            // process received messages
            for i in mailbox.iter_mut() {
                match i.msgtype {
                    crate::whisper::MessageType::Text => {
                        // send the message to a client (in debug form for now)
                        tx.send(i.format())
                            .expect("Unable to send message to client!");
                    }
                    crate::whisper::MessageType::NewMember => {
                        i.aquaintance.push(uuid);
                        newcomer_mailbox.push(i.clone());
                    }
                    whisper::MessageType::EncryptionRequest => {} // cannot happen, as those can only be unencrypted
                }
            }
            // greet the spoken and tell him not to worry introducing me
            for i in newcomer_mailbox.iter() {
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
                    // aknowledge peer's existence
                    connections.push((newcomer, None));
                }
            }
            // don't propagate the gossip (for now)
            newcomer_mailbox.clear();
            // input from client
            while let Ok(msg_text) = rx.try_recv() {
                let msg = crate::whisper::Message::new(
                    crate::whisper::MessageType::Text,
                    &myself,
                    &msg_text,
                    vec![myself.uuid],
                );
                let encrypted = msg.encrypt(&cipher, &enc_key, &iv).unwrap();
                for i in connections.iter_mut() {
                    if let Some(stream) = i.1.as_mut() {
                        speach::send_data(stream, &encrypted);
                    }
                }
            }
            // direct connections
            // create gossip
            let mut newcomer_mailbox = Vec::<crate::whisper::Message>::new();
            while let Ok(mut new_connection) = listener_rx.try_recv() {
                if let Ok(mut message) = speach::receive_greeting(&mut new_connection) {
                    println!(
                        "New connection from {}",
                        new_connection.peer_addr().unwrap()
                    );
                    speach::send_data(&mut new_connection, announcement.to_string().as_bytes());
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
                            let pkey_temp =
                                openssl::pkey::PKey::public_key_from_pem(public_key).unwrap();
                            let temp_encrypter =
                                openssl::encrypt::Encrypter::new(&pkey_temp).unwrap();
                            if speach::authenticate(&encryption_request.sender, &mut new_connection)
                            {
                                speach::send_encryption_data(
                                    &mut new_connection,
                                    &enc_key,
                                    &temp_encrypter,
                                );
                                speach::send_encryption_data(
                                    &mut new_connection,
                                    &iv,
                                    &temp_encrypter,
                                );
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
                        message.aquaintance.push(uuid);
                        newcomer_mailbox.push(message.clone());
                    }
                    connections.push((message.sender.clone(), Some(new_connection)));
                }
            }
            // spread the gossip (for now to everyone)
            for i in newcomer_mailbox.iter() {
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
            thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    (client_tx, client_rx)
}
