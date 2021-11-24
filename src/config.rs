use crate::neighborhood;
use crate::whisper;
use std::sync::{mpsc, Arc, Mutex};

pub struct Config {
    pub max_send_peers: usize,
    pub stored_messages_filename: String,
}
impl Config {
    pub fn new() -> Config {
        Config {
            max_send_peers: 5,
            stored_messages_filename: String::from(""),
        }
    }
}

pub struct State {
    pub receiver_tx: mpsc::Sender<whisper::Message>,
    pub gossiper_tx: mpsc::Sender<whisper::Message>,
    pub cipher: openssl::symm::Cipher,
    pub myself: neighborhood::Node,
    pub announcement: whisper::Message,
    pub connections: Vec<neighborhood::Node>,
    pub enc_key: Vec<u8>,
    pub config: Arc<Mutex<Config>>,
    pub tx: mpsc::Sender<whisper::Message>,
}
