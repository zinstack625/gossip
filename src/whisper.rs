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
    pub sender: crate::neighborhood::Node,
    pub contents: String,
    pub encryption: Encryption,
}
impl Message {
    pub fn new(
        msgtype: MessageType,
        sender: &crate::neighborhood::Node,
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
                    sender: crate::neighborhood::Node::from_str(
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
