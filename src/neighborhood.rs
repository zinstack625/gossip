#[derive(Clone)]
pub struct Node {
    pub name: String,
    pub uuid: u32,
    pub address: std::net::SocketAddr,
}
impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        self.uuid == other.uuid
    }
}
impl Eq for Node {}
impl Node {
    pub fn to_string(&self) -> String {
        let mut address_string = self.address.ip().to_string();
        address_string.push(':');
        address_string.push_str(self.address.port().to_string().as_str());
        let node = json::object! {
            name: self.name.clone(),
            uuid: self.uuid,
            address: address_string,
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
                address: json_tree["address"].take_string().unwrap().parse().unwrap(),
            }),
        }
    }
    pub fn new(name: &String, uuid: u32, address: &std::net::SocketAddr) -> Node {
        Node {
            name: name.clone(),
            uuid,
            address: address.clone(),
        }
    }
}
