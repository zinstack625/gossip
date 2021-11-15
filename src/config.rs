use crate::neighborhood;
use crate::whisper;
use std::net::TcpStream;
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
    pub listener_rx: Vec<mpsc::Receiver<TcpStream>>,
    pub cipher: openssl::symm::Cipher,
    pub myself: neighborhood::Node,
    pub announcement: whisper::Message,
    pub connections: Vec<neighborhood::Node>,
    pub enc_key: Vec<u8>,
    pub config: Arc<Mutex<Config>>,
    pub conf_change_sig_rx: mpsc::Receiver<usize>,
    pub tx: mpsc::Sender<whisper::Message>,
    pub rx: mpsc::Receiver<whisper::Message>,
}
