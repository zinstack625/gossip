use rand::Rng;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub mod config;
pub mod neighborhood;
mod politeness;
mod speach;
pub mod whisper;
pub mod error;

use neighborhood::*;

fn spawn_listener(ctx: Arc<Mutex<config::State>>, local_ip: IpAddr, port: u16) -> u16 {
    let mut local_address = SocketAddr::new(local_ip, port);
    let mut listener = TcpListener::bind(local_address);
    while listener.is_err() {
        local_address.set_port(rand::thread_rng().gen_range(7000..50000));
        listener = TcpListener::bind(local_address);
    }
    let listener = listener.unwrap();
    let _listener_thread = thread::spawn(move || {
        for i in listener.incoming() {
            if let Ok(new_connection) = i {
                let node = neighborhood::receive_newcomer(ctx.clone(), new_connection);
                if node.is_err() {
                    continue;
                }
                let node = node.unwrap();
                ctx.lock().unwrap().connections.push(node.clone());
                let ctx = ctx.clone();
                std::thread::spawn(move || speach::receive_messages_enc(ctx, node));
            }
        }
    });
    log::info!("Listening at {}", local_address);
    local_address.port()
}

fn server_thread(state: Arc<Mutex<config::State>>, receiver_rx: mpsc::Receiver<whisper::Message>) {
    //TODO: make it client side
    request_missed(&mut state.lock().unwrap());
    let mut postponed_storage = Vec::<whisper::Message>::new();
    loop {
        let mut msg = receiver_rx.recv().expect("MPSC queue broken");
        msg.next_iv.resize(state.lock().unwrap().cipher.iv_len().unwrap(), 0u8);
        if let Ok(_) = politeness::store_text_messages(state.clone(), &postponed_storage) {
            postponed_storage.clear();
        }
        if let Err(_) = politeness::store_text_message(state.clone(), &msg) {
            postponed_storage.push(msg.clone());
        }
        let processor_ctx = state.clone();
        std::thread::spawn(move || politeness::process_message(processor_ctx, msg));
    }
}

fn configurator_thread(ctx: Arc<Mutex<config::State>>, config_rx: mpsc::Receiver<config::Config>) {
    loop {
        if let Ok(new_config) = config_rx.recv() {
            let ctx = ctx.lock().unwrap();
            {
                let mut config = ctx.config.lock().unwrap();
                *config = new_config;
            }
            if let Ok(stored_messages) = politeness::get_stored_messages(&ctx) {
                for i in stored_messages {
                    match i.msgtype {
                        whisper::MessageType::Text => {
                            ctx.tx.send(i).expect("Unable to send message to client!");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn gossiper_thread(ctx: Arc<Mutex<config::State>>, gossiper_rx: mpsc::Receiver<whisper::Message>) {
    loop {
        let msg = gossiper_rx.recv();
        if msg.is_err() {
            continue;
        }
        let mut msg = msg.unwrap();
        let mut ctx = ctx.lock().unwrap();
        let mut to_send = Vec::<u32>::with_capacity(ctx.connections.len());
        for i in ctx.connections.iter() {
            if i.stream.is_some() && !msg.aquaintance.contains(&i.uuid) {
                to_send.push(i.uuid);
                msg.aquaintance.push(i.uuid);
            }
        }
        if to_send.is_empty() {
            continue;
        }
        msg.next_sender = *to_send.last().unwrap();
        msg.next_iv = vec![0u8; ctx.cipher.iv_len().unwrap()];
        let mut send_limit = ctx.config.lock().unwrap().max_send_peers;
        let cipher = ctx.cipher.clone();
        let enc_key = ctx.enc_key.clone();
        for i in ctx.connections.iter_mut() {
            if send_limit == 0 {
                return;
            }
            if i.stream.is_none() {
                continue;
            }
            // it is essential to send each and every message here if possible, otherwise data will be lost in the network
            // have to let the receiver know who's seen the message already
            openssl::rand::rand_bytes(&mut msg.next_iv);
            let encrypted = msg.encrypt(&cipher, &enc_key, &i.iv).unwrap();
            i.iv = msg.next_iv.clone();
            // TODO: ask someone else to deliver this message if this fails
            speach::send_data(i.stream.as_mut().unwrap(), &encrypted);

            send_limit -= 1;
        }
    }
}

pub fn spawn_server(
    client_name: String,
    init_nodes: Vec<SocketAddr>,
) -> config::ClientHandle {
    // initializing stuff
    let uuid: u32 = rand::thread_rng().gen();
    log::info!("I am {}", uuid);
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let mut myself = neighborhood::Node::with_address(
        client_name.clone(),
        uuid,
        "0.0.0.0:0".parse().unwrap(),
        "[::]:0".parse().unwrap(),
    );
    let announcement = whisper::Message::new(
        whisper::MessageType::NewMember,
        &myself,
        &String::from(""),
        vec![uuid],
        0,
        &vec![0; 12],
        std::time::SystemTime::now(),
    );
    let config = Arc::new(Mutex::new(config::Config::new()));
    let (tx, client_rx) = mpsc::channel();
    let (client_tx, rx) = mpsc::channel();
    let (receiver_tx, receiver_rx) = mpsc::channel();
    let (gossiper_tx, gossiper_rx) = mpsc::channel();
    let (config_tx, config_rx) = mpsc::channel();
    let init_state = Arc::new(Mutex::new(config::State {
        receiver_tx,
        gossiper_tx,
        cipher,
        myself,
        announcement,
        connections: vec![],
        enc_key: vec![],
        config,
        tx,
    }));
    let port = spawn_listener(init_state.clone(), "127.0.0.1".parse().unwrap(), 42378);
    let portv6 = spawn_listener(init_state.clone(), "::".parse().unwrap(), 42378);
    {
        let mut ctx = init_state.lock().unwrap();
        let my_addr = ctx.myself.address.as_mut();
        if my_addr.is_some() {
            log::info!("Setting IPV4 port: {}", port);
            my_addr.unwrap().set_port(port);
        }
        let my_addrv6 = ctx.myself.addressv6.as_mut();
        if my_addrv6.is_some() {
            log::info!("Setting IPV6 port: {}", portv6);
            my_addrv6.unwrap().set_port(portv6);
        }
        let my_ann_addr = ctx.announcement.sender.address.as_mut();
        if my_ann_addr.is_some() {
            log::info!("Setting IPV4 port in announcement: {}", port);
            my_ann_addr.unwrap().set_port(port);
        }
        let my_ann_addrv6 = ctx.announcement.sender.addressv6.as_mut();
        if my_ann_addrv6.is_some() {
            log::info!("Setting IPV6 port in announcement: {}", portv6);
            my_ann_addrv6.unwrap().set_port(portv6);
        }
    }
    log::info!(
        "Ready announcement: {}",
        init_state.lock().unwrap().announcement.to_string()
    );
    // first node in the network
    if !speach::initial_connections(init_state.clone(), init_nodes) {
        let mut ctx = init_state.lock().unwrap();
        ctx.myself.iv.resize(cipher.iv_len().unwrap_or_default(), 0);
        ctx.enc_key = vec![0u8; cipher.key_len()];
        openssl::rand::rand_bytes(&mut ctx.enc_key).expect("Unable to set up main key");
        openssl::rand::rand_bytes(&mut ctx.myself.iv).expect("Unable to set up iv");
    }
    let client_handle_ctx = init_state.clone();
    std::thread::spawn(move || politeness::client_duty(client_handle_ctx, rx));
    let receiver_ctx = init_state.clone();
    let _configurator_thread = thread::spawn(move || configurator_thread(receiver_ctx, config_rx));
    let gossiper_ctx = init_state.clone();
    let _gossiper_thread = thread::spawn(move || gossiper_thread(gossiper_ctx, gossiper_rx));
    let _server_thread = thread::spawn(move || server_thread(init_state, receiver_rx));

    config::ClientHandle::new(
        client_tx,
        Some(client_rx),
        config_tx,
    )
}
