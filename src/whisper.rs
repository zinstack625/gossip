use openssl::symm::*;

#[derive(Copy, Clone, PartialEq)]
pub enum MessageType {
    Text,
    NewMember,
    EncryptionRequest,
}
#[derive(Clone)]
pub struct Message {
    pub msgtype: MessageType,
    pub sender: crate::neighborhood::Node,
    pub contents: String,
}
impl Message {
    pub fn new(
        msgtype: MessageType,
        sender: &crate::neighborhood::Node,
        contents: &String,
    ) -> Message {
        Message {
            msgtype,
            sender: sender.clone(),
            contents: contents.clone(),
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
                MessageType::EncryptionRequest => "EncryptionRequest",
            },
            sender: self.sender.to_string(),
            contents: self.contents.clone(),
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
                        "EncryptionRequest" => MessageType::EncryptionRequest,
                        _ => MessageType::Text,
                    },
                    sender: crate::neighborhood::Node::from_str(
                        json_node["sender"].take_string().unwrap().as_str(),
                    )
                    .unwrap(),
                    contents: json_node["contents"].take_string().unwrap(),
                };
                Ok(parsed_msg)
            }
        }
    }
    pub fn encrypt(&self, cipher: &Cipher, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let bytes = self.to_string().as_bytes().to_vec();
        let buffer_len = bytes.len() + cipher.block_size();
        let mut encrypter = Crypter::new(*cipher, Mode::Encrypt, key, Some(iv))?;
        let mut encrypted = vec![0u8; buffer_len];
        let mut count = encrypter.update(&bytes, &mut encrypted)?;
        count += encrypter.finalize(&mut encrypted)?;
        encrypted.truncate(count);
        Ok(encrypted)
    }
}
