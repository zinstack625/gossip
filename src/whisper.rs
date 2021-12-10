use openssl::symm::*;
use std::{time::{Duration, UNIX_EPOCH}, fmt::Display, str::FromStr};

use crate::neighborhood;

#[derive(Copy, Clone, PartialEq)]
pub enum MessageType {
    Text,
    NewMember,
    EncryptionRequest,
    MissedMessagesRequest,
    NetworkInfo,
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stringified = match self {
            &MessageType::Text =>                     "Text",
            &MessageType::NewMember =>                "NewMember",
            &MessageType::EncryptionRequest =>        "EncryptionRequest",
            &MessageType::MissedMessagesRequest =>    "MissedMessagesRequest",
            &MessageType::NetworkInfo =>              "NetworkInfo",
        };
        write!(f, "{}", stringified)
    }
}

impl FromStr for MessageType {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = match s {
            "Text" =>                   Ok(MessageType::Text),
            "NewMember" =>              Ok(MessageType::NewMember),
            "EncryptionRequest" =>      Ok(MessageType::EncryptionRequest),
            "MissedMessagesRequest" =>  Ok(MessageType::MissedMessagesRequest),
            "NetworkInfo" =>            Ok(MessageType::NetworkInfo),
            _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unsupported message type"))
        };
        result
    }
}
#[derive(Clone)]
pub struct Message {
    pub msgtype: MessageType,
    pub sender: crate::neighborhood::Node,
    pub contents: String,
    pub aquaintance: Vec<u32>,
    pub next_sender: u32,
    pub next_iv: Vec<u8>,
    pub timestamp: std::time::SystemTime,
}
impl Message {
    pub fn new(
        msgtype: MessageType,
        sender: &crate::neighborhood::Node,
        contents: &String,
        aquaintance: Vec<u32>,
        next_sender: u32,
        next_iv: &[u8],
        timestamp: std::time::SystemTime,
    ) -> Message {
        Message {
            msgtype,
            sender: sender.clone(),
            contents: contents.clone(),
            aquaintance,
            next_sender,
            next_iv: next_iv.to_vec(),
            timestamp,
        }
    }
    pub fn from_client(
        msgtype: MessageType,
        self_name: &String,
        contents: &String,
        ) -> Message {
        Message {
            msgtype,
            sender: neighborhood::Node::new(self_name.clone(), 0, None),
            contents: contents.clone(),
            aquaintance: vec![],
            next_sender: 0,
            next_iv: vec![],
            timestamp: std::time::SystemTime::now(),
        }
    }
    pub fn format(&self) -> String {
        let mut formatted_message = String::new();
        formatted_message.push_str(self.sender.to_string().as_str());
        formatted_message.push_str(" :: ");
        formatted_message.push_str(
            &self
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        );
        formatted_message.push_str(" secs :: ");
        formatted_message.push_str(": ");
        formatted_message.push_str(self.contents.as_str());
        formatted_message
    }
    pub fn to_string(&self) -> String {
        let message = json::object! {
            msgtype: self.msgtype.to_string(),
            sender: self.sender.to_string(),
            contents: self.contents.clone(),
            aquaintance: self.aquaintance.clone(),
            next_sender: self.next_sender,
            next_iv: self.next_iv.clone(),
            timestamp: self.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        };
        json::stringify(message)
    }
    pub fn from_str(json_string: &str) -> Result<Message, json::Error> {
        let parse_try = json::parse(json_string);
        match parse_try {
            Err(parse_error) => Err(parse_error),
            Ok(mut json_node) => {
                let parsed_msg = Message {
                    msgtype: {
                        if let Some(obj) = json_node["msgtype"].take_string() {
                            if let Ok(msgtype) = MessageType::from_str(&obj) {
                                msgtype
                            } else {
                                return Err(json::Error::UnexpectedEndOfJson);
                            }
                        } else {
                            return Err(json::Error::UnexpectedEndOfJson);
                        }
                    },
                    sender: {
                        let mut result = Err(json::Error::UnexpectedEndOfJson);
                        if let Some(obj) = json_node["sender"].take_string() {
                            if let Ok(node) = neighborhood::Node::from_str(&obj) {
                                result = Ok(node);
                            }
                        }
                        if result.is_ok() {
                            result.unwrap()
                        } else {
                            return Err(json::Error::UnexpectedEndOfJson);
                        }
                    },
                    contents: if let Some(cont) = json_node["contents"].take_string() {
                        cont
                    } else {
                        return Err(json::Error::UnexpectedEndOfJson);
                    },
                    aquaintance: {
                        let mut aquaintance_vec =
                            Vec::<u32>::with_capacity(json_node["aquaintance"].len());
                        for i in json_node["aquaintance"].members() {
                            aquaintance_vec.push(i.as_u32().unwrap_or_default());
                        }
                        aquaintance_vec
                    },
                    next_sender: json_node["next_sender"].as_u32().unwrap_or_default(),
                    next_iv: {
                        let mut iv = Vec::<u8>::with_capacity(json_node["next_iv"].len());
                        json_node["next_iv"].members().enumerate().for_each(|i| {
                            iv.push(i.1.as_u8().unwrap_or_default());
                        });
                        iv
                    },
                    timestamp: UNIX_EPOCH
                        + Duration::from_secs(json_node["timestamp"].as_u64().unwrap_or_default()),
                };
                Ok(parsed_msg)
            }
        }
    }
    pub fn encrypt(
        &self,
        cipher: &Cipher,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, openssl::error::ErrorStack> {
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
