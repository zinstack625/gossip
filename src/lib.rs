use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub mod config;
pub mod neighborhood;
mod politeness;
mod speach;
pub mod whisper;

use neighborhood::*;

fn spawn_listener(local_ip: IpAddr, port: u16) -> (mpsc::Receiver<TcpStream>, SocketAddr) {
    let mut local_address = SocketAddr::new(local_ip, port);
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

fn server_thread(mut state: config::State) {
    //TODO: make it client side
    let missed_msgs = request_missed(&mut state);
    if missed_msgs.is_ok() {
        let missed_msgs = missed_msgs.unwrap();
        for i in missed_msgs {
            match i.msgtype {
                whisper::MessageType::Text => {
                    state.tx.send(i).expect("Unable to send message to client!");
                }
                _ => {}
            }
        }
    }
    let mut postponed_storage = Vec::<whisper::Message>::new();
    loop {
        let mailbox = speach::recv_messages(&mut state);
        if let Ok(_) = politeness::store_text_messages(&mut state, &postponed_storage) {
            postponed_storage.clear();
        }
        if let Err(_) = politeness::store_text_messages(&mut state, &mailbox) {
            postponed_storage.extend_from_slice(&mailbox[..]);
        }
        let mut gossip = Vec::<whisper::Message>::new();
        let mut newcomer_mailbox = Vec::<whisper::Message>::new();
        politeness::process_messages(&mut state, mailbox, &mut gossip, &mut newcomer_mailbox);
        politeness::greet_newcomers(&mut state, newcomer_mailbox);
        // input from client
        politeness::client_duty(&mut state);
        // direct connections
        // create gossip
        let mut newcomer_mailbox = receive_newcomers(&mut state);
        gossip.append(&mut newcomer_mailbox);
        speach::spread_gossip(&mut state, gossip);
        if let Ok(_) = state.conf_change_sig_rx.try_recv() {
            if let Ok(stored_messages) = politeness::get_stored_messages(&mut state) {
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
    let (listener_rx, local_address) = spawn_listener("127.0.0.1".parse().unwrap(), 42378);
    let (listener_rxv6, local_addressv6) = spawn_listener("::".parse().unwrap(), 42378);
    let uuid: u32 = rand::thread_rng().gen();
    println!("I am {}", uuid);
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let mut myself =
        neighborhood::Node::with_address(client_name.clone(), uuid, local_address.clone());
    let announcement = whisper::Message::new(
        whisper::MessageType::NewMember,
        &myself,
        &String::from(""),
        vec![uuid],
        0,
        &vec![0; 12],
        std::time::SystemTime::now(),
    );
    let mut connections = speach::initial_connections(init_nodes, &announcement);
    let enc_key = match connections.is_empty() {
        true => {
            myself.iv.resize(cipher.iv_len().unwrap_or_default(), 0);
            let mut key = vec![0u8; cipher.key_len()];
            openssl::rand::rand_bytes(&mut key).expect("Unable to set up main key");
            openssl::rand::rand_bytes(&mut myself.iv).expect("Unable to set up iv");
            key
        }
        false => speach::get_key(
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
    let init_state = config::State {
        listener_rx: vec![listener_rx, listener_rxv6],
        cipher,
        myself,
        announcement,
        connections,
        enc_key,
        config,
        conf_change_sig_rx,
        tx,
        rx,
    };
    let _server_thread = thread::spawn(move || server_thread(init_state));
    (client_tx, client_rx)
}
