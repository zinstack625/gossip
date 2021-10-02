use std::net::{SocketAddr, TcpStream};

pub struct Node {
    pub name: String,
    pub uuid: u32,
    pub stream: Option<TcpStream>,
    pub address: SocketAddr,
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            uuid: self.uuid.clone(),
            stream: match &self.stream {
                Some(stream) => {
                    if let Ok(copy) = stream.try_clone() {
                        Some(copy)
                    } else {
                        None
                    }
                }
                None => None,
            },
            address: self.address.clone(),
        }
    }
}
impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        self.uuid == other.uuid
    }
}
impl Eq for Node {}
impl Node {
    pub fn to_string(&self) -> String {
        let node = json::object! {
            name: self.name.clone(),
            uuid: self.uuid,
            address: self.address.to_string(),
        };
        json::stringify(node)
    }
    pub fn from_str(json_node: &str) -> Result<Node, json::Error> {
        let parse_try = json::parse(json_node);
        match parse_try {
            Err(parse_error) => Err(parse_error),
            Ok(mut json_tree) => Ok(Node {
                // TODO: this is obviously very bug prone and needs error handling instead of unwrapping
                name: json_tree["name"].take_string().unwrap(),
                uuid: match std::convert::TryFrom::try_from(json_tree["uuid"].as_number().unwrap())
                {
                    Ok(num) => num,
                    _ => 0,
                },
                stream: None,
                address: json_tree["address"].take_string().unwrap().parse().unwrap(),
            }),
        }
    }
    pub fn with_address(name: String, uuid: u32, address: SocketAddr) -> Node {
        Node {
            name,
            uuid,
            stream: None,
            address,
        }
    }
    pub fn new(name: String, uuid: u32, stream: Option<TcpStream>) -> Node {
        Node {
            name,
            uuid,
            address: match &stream {
                Some(stream) => stream.peer_addr().unwrap(),
                None => "0.0.0.0:0".parse().unwrap(),
            },
            stream,
        }
    }
}
