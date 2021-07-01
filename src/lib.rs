use rand::Rng;
use std::io::prelude::*;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

pub mod neighborhood;
pub mod whisper;

// TODO: prob throw these functions in a separate file
// and give their placement some meaning

fn receive_messages(stream: &mut TcpStream) -> Vec<whisper::Message> {
    let mut messages = Vec::<whisper::Message>::new();
    let mut buffer: [u8; 4096] = [0; 4096];
    while let Ok(bytes_n) = stream.read(&mut buffer) {
        let mut bytes_vector = buffer.to_vec();
        bytes_vector.resize(bytes_n, 0);
        for split in bytes_vector.split(|byte| *byte == 0) {
            if let Ok(packet) = std::str::from_utf8(split) {
                if let Ok(msg) = whisper::Message::from_str(packet) {
                    messages.push(msg);
                }
            }
        }
    }
    messages
}

fn receive_greeting(stream: &mut TcpStream) -> Result<whisper::Message, std::io::Error> {
    let mut buffer: [u8; 4096] = [0; 4096];
    let bytes_n = stream.read(&mut buffer)?;
    if let Ok(packet) = std::str::from_utf8(&buffer[..bytes_n - 1]) {
        if let Ok(msg) = whisper::Message::from_str(packet) {
            return Ok(msg);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Something happened",
    ))
}

fn send_message(stream: &mut TcpStream, msg: &whisper::Message) -> std::io::Result<usize> {
    let mut packet = msg.to_string().as_bytes().to_vec();
    packet.push(0);
    let bytes_written = stream.write(&packet[..])?;
    stream.flush()?;
    Ok(bytes_written)
}

fn spawn_listener() -> (mpsc::Receiver<TcpStream>, SocketAddr) {
    let mut local_address = local_ipaddress::get().unwrap();
    //let mut local_address = String::from("127.0.0.1");
    let port: u16 = rand::thread_rng().gen_range(7000..50000);
    local_address.push(':');
    local_address.push_str(port.to_string().as_str());
    let mut local_address: SocketAddr = local_address.parse().unwrap();
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

fn init_connection(
    address: &SocketAddr,
    announcement: &whisper::Message,
) -> Result<(neighborhood::Node, TcpStream), std::io::Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_nonblocking(false);
    send_message(&mut stream, &announcement);
    if let Ok(reply) = receive_greeting(&mut stream) {
        stream
            .set_nonblocking(true)
            .expect("Unable to set TCP stream async");
        Ok((reply.sender, stream))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Greeting is invalid",
        ))
    }
}

fn initial_connections(
    init_nodes: Vec<String>,
    announcement: &whisper::Message,
) -> Vec<(neighborhood::Node, TcpStream)> {
    let mut connections = Vec::<(neighborhood::Node, TcpStream)>::new();
    connections.reserve(init_nodes.len());
    for i in init_nodes {
        if let Ok(address) = i.parse() {
            if let Ok(node) = init_connection(&address, &announcement) {
                connections.push(node);
            }
        }
    }
    connections
}

pub fn spawn_server(
    client_name: String,
    init_nodes: Vec<String>,
) -> (mpsc::Sender<String>, mpsc::Receiver<String>) {
    let (listener_rx, local_address) = spawn_listener();
    let uuid: u32 = rand::thread_rng().gen();
    println!("I am {}", uuid);
    let myself = neighborhood::Node::new(&client_name, uuid, &local_address);
    let announcement = whisper::Message::new(
        whisper::MessageType::NewMember,
        &myself,
        &json::stringify(json::object! {
            aquaintance: [ uuid ],
        }),
        whisper::Encryption::None,
    );
    let mut connections = initial_connections(init_nodes, &announcement);
    let (tx, client_rx) = mpsc::channel();
    let (client_tx, rx) = mpsc::channel();
    let _server_thread = thread::spawn(move || loop {
        // mailbox
        let mut newcomer_mailbox: Vec<whisper::Message> = Vec::new();
        let mut mailbox = Vec::<whisper::Message>::new();
        for i in connections.iter_mut() {
            let connection_messages = receive_messages(&mut i.1);
            mailbox.extend(connection_messages);
        }
        for i in mailbox {
            match i.msgtype {
                whisper::MessageType::Text => {
                    tx.send(i.format())
                        .expect("Unable to send message to client!");
                }
                whisper::MessageType::NewMember => {
                    let mut message_contents = json::parse(i.contents.as_str()).unwrap();
                    message_contents["aquaintance"].push(myself.uuid).unwrap();
                    newcomer_mailbox.push(whisper::Message::new(
                        i.msgtype,
                        &i.sender,
                        &json::stringify(message_contents),
                        i.encryption,
                    ));
                }
            }
        }

        // greet the spoken and tell him not to worry introducing me
        for i in newcomer_mailbox.iter() {
            let newcomer = i.sender.clone();
            let mut announcement = announcement.clone();
            let mut contents = json::parse(announcement.contents.as_str()).unwrap();
            contents.insert("gossipless", true);
            announcement.contents = json::stringify(contents);
            if let Ok(node) = init_connection(&newcomer.address, &announcement) {
                connections.push(node);
            }
        }
        // don't propagate the gossip (for now)
        newcomer_mailbox.clear();
        // mailman
        while let Ok(msg_text) = rx.try_recv() {
            let msg = whisper::Message::new(
                whisper::MessageType::Text,
                &myself,
                &msg_text,
                whisper::Encryption::None,
            );
            for i in connections.iter_mut() {
                send_message(&mut i.1, &msg);
            }
        }
        // direct connections
        // create gossip
        let mut newcomer_mailbox: Vec<whisper::Message> = Vec::new();
        while let Ok(mut new_connection) = listener_rx.try_recv() {
            if let Ok(message) = receive_greeting(&mut new_connection) {
                println!(
                    "New connection from {}",
                    new_connection.peer_addr().unwrap()
                );
                new_connection.set_nonblocking(true).unwrap();
                send_message(&mut new_connection, &announcement);
                let mut message_contents = json::parse(message.contents.as_str()).unwrap();
                if !message_contents.has_key("gossipless") {
                    message_contents["aquaintance"].push(uuid).unwrap();
                    newcomer_mailbox.push(whisper::Message::new(
                        message.msgtype,
                        &message.sender,
                        &json::stringify(message_contents),
                        message.encryption,
                    ));
                }
                connections.push((message.sender.clone(), new_connection));
            }
        }
        // spread the gossip (for now to everyone)
        for i in newcomer_mailbox.iter() {
            let message_contents = json::parse(i.contents.as_str()).unwrap();
            for j in connections.iter_mut().enumerate() {
                println!(
                    "Greeting from {} is aquainted with {}",
                    i.sender.name, message_contents["aquaintance"]
                );

                if !message_contents["aquaintance"].contains(j.1 .0.uuid) {
                    println!(
                        "Sending greeting to uuid {}, address {}",
                        j.1 .0.uuid,
                        j.1 .1.peer_addr().unwrap()
                    );
                    send_message(&mut j.1 .1, i);
                }
            }
        }
        thread::sleep(std::time::Duration::from_millis(200));
    });
    (client_tx, client_rx)
}
