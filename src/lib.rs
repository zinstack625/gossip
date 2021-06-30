use rand::Rng;
use std::io::prelude::*;
use std::net;
use std::sync::mpsc;
use std::thread;

fn receive_messages(
    stream: &mut std::net::TcpStream,
    client_tx: &mpsc::Sender<String>,
    newcomer_mailbox: &mut Vec<whisper::Message>,
    myself: &network::Node,
) {
    let mut buffer: [u8; 4096] = [0; 4096];
    while let Ok(bytes_n) = stream.read(&mut buffer) {
        let mut bytes_vector = buffer.to_vec();
        bytes_vector.resize(bytes_n, 0);
        for split in bytes_vector.split(|byte| *byte == 0) {
            if let Ok(packet) = std::str::from_utf8(split) {
                if let Ok(msg) = whisper::Message::from_str(packet) {
                    match msg.msgtype {
                        whisper::MessageType::Text => {
                            client_tx
                                .send(msg.format())
                                .expect("Unable to send message to client!");
                        }
                        whisper::MessageType::NewMember => {
                            let mut message_contents = json::parse(msg.contents.as_str()).unwrap();
                            message_contents["aquaintance"].push(myself.uuid).unwrap();
                            newcomer_mailbox.push(whisper::Message::new(
                                msg.msgtype,
                                &msg.sender,
                                &json::stringify(message_contents),
                                msg.encryption,
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn receive_greeting(stream: &mut std::net::TcpStream) -> Result<whisper::Message, std::io::Error> {
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

fn send_message(
    stream: &mut std::net::TcpStream,
    msg: &whisper::Message,
) -> std::io::Result<usize> {
    let mut packet = msg.to_string().as_bytes().to_vec();
    packet.push(0);
    let bytes_written = stream.write(&packet[..])?;
    stream.flush()?;
    Ok(bytes_written)
}
fn spawn_listener() -> (mpsc::Receiver<std::net::TcpStream>, std::net::SocketAddr) {
    let mut local_address = local_ipaddress::get().unwrap();
    let port: u16 = rand::thread_rng().gen_range(7000..50000);
    local_address.push(':');
    local_address.push_str(port.to_string().as_str());
    let mut local_address: std::net::SocketAddr = local_address.parse().unwrap();
    let mut listener = std::net::TcpListener::bind(local_address);
    while listener.is_err() {
        local_address.set_port(rand::thread_rng().gen_range(7000..50000));
        listener = std::net::TcpListener::bind(local_address);
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
    address: &std::net::SocketAddr,
    announcement: &whisper::Message,
) -> Result<(network::Node, std::net::TcpStream), std::io::Error> {
    let mut stream = net::TcpStream::connect(address)?;
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

fn initial_connection(
    init_nodes: Vec<String>,
    announcement: &whisper::Message,
) -> Vec<(network::Node, std::net::TcpStream)> {
    let mut connections = Vec::<(network::Node, std::net::TcpStream)>::new();
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
    let myself = network::Node::new(&client_name, uuid, &local_address);
    let announcement = whisper::Message::new(
        whisper::MessageType::NewMember,
        &myself,
        &json::stringify(json::object! {
            aquaintance: [ uuid ],
        }),
        whisper::Encryption::None,
    );
    let mut connections = initial_connection(init_nodes, &announcement);
    let (tx, client_rx) = mpsc::channel();
    let (client_tx, rx) = mpsc::channel();
    let _server_thread = thread::spawn(move || loop {
        // mailbox
        let mut newcomer_mailbox: Vec<whisper::Message> = Vec::new();
        for i in connections.iter_mut() {
            receive_messages(&mut i.1, &tx, &mut newcomer_mailbox, &myself);
        }
        // greet the spoken and tell him not to worry introducing me
        for i in newcomer_mailbox.iter() {
            let newcomer = i.sender.clone();
            let mut announcement = announcement.clone();
            let mut contents = json::parse(announcement.contents.as_str()).unwrap();
            contents.insert("gossipless", true);
            announcement.contents = json::stringify(contents);
            if let Ok(node) = init_connection(&newcomer.adress, &announcement) {
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

pub mod network {
    #[derive(Clone)]
    pub struct Node {
        pub name: String,
        pub uuid: u32,
        pub adress: std::net::SocketAddr,
    }
    impl PartialEq for Node {
        fn eq(&self, other: &Node) -> bool {
            self.uuid == other.uuid
        }
    }
    impl Eq for Node {}
    impl Node {
        pub fn to_string(&self) -> String {
            let mut adress_string = self.adress.ip().to_string();
            adress_string.push(':');
            adress_string.push_str(self.adress.port().to_string().as_str());
            let node = json::object! {
                name: self.name.clone(),
                uuid: self.uuid,
                adress: adress_string,
            };
            json::stringify(node)
        }
        pub fn from_str(json_node: &str) -> Result<Node, json::Error> {
            let parse_try = json::parse(json_node);
            match parse_try {
                Err(parse_error) => Err(parse_error),
                Ok(mut json_tree) => Ok(Node {
                    name: json_tree["name"].take_string().unwrap(),
                    uuid: match std::convert::TryFrom::try_from(
                        json_tree["uuid"].as_number().unwrap(),
                    ) {
                        Ok(num) => num,
                        _ => 0,
                    },
                    adress: json_tree["adress"].take_string().unwrap().parse().unwrap(),
                }),
            }
        }
        pub fn new(name: &String, uuid: u32, adress: &std::net::SocketAddr) -> Node {
            Node {
                name: name.clone(),
                uuid,
                adress: adress.clone(),
            }
        }
    }
}

pub mod whisper {
    #[derive(Copy, Clone)]
    pub enum Encryption {
        AES256,
        None,
    }
    #[derive(Copy, Clone)]
    pub enum MessageType {
        Text,
        NewMember,
    }
    #[derive(Clone)]
    pub struct Message {
        pub msgtype: MessageType,
        pub sender: crate::network::Node,
        pub contents: String,
        pub encryption: Encryption,
    }
    impl Message {
        pub fn new(
            msgtype: MessageType,
            sender: &crate::network::Node,
            contents: &String,
            encryption: Encryption,
        ) -> Message {
            Message {
                msgtype,
                sender: sender.clone(),
                contents: contents.clone(),
                encryption,
            }
        }
        pub fn format(&self) -> String {
            let mut formatted_message = String::new();
            formatted_message.push_str(self.sender.to_string().as_str());
            formatted_message.push_str(": ");
            formatted_message.push_str(self.contents.as_str());
            formatted_message
        }
        pub fn to_string(&self) -> String {
            let message = json::object! {
                msgtype: match self.msgtype {
                    MessageType::NewMember => "NewMember",
                    MessageType::Text => "Text",
                },
                sender: self.sender.to_string(),
                contents: self.contents.clone(),
                encryption: match self.encryption {
                    Encryption::AES256 => "AES256",
                    Encryption::None => "None",
                },
            };
            json::stringify(message)
        }
        pub fn from_str(json_string: &str) -> Result<Message, json::Error> {
            let parse_try = json::parse(json_string);
            match parse_try {
                Err(parse_error) => Err(parse_error),
                Ok(mut json_node) => {
                    let parsed_msg = Message {
                        msgtype: match json_node["msgtype"].take_string().unwrap().as_str() {
                            "NewMember" => MessageType::NewMember,
                            _ => MessageType::Text,
                        },
                        sender: crate::network::Node::from_str(
                            json_node["sender"].take_string().unwrap().as_str(),
                        )
                        .unwrap(),
                        contents: json_node["contents"].take_string().unwrap(),
                        encryption: match json_node["encryption"].take_string().unwrap().as_str() {
                            "AES256" => Encryption::AES256,
                            _ => Encryption::None,
                        },
                    };
                    Ok(parsed_msg)
                }
            }
        }
    }
}
