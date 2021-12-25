use crate::neighborhood;
use crate::whisper;
use std::sync::mpsc::SendError;
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

pub struct ClientHandle {
    client_tx: mpsc::Sender<whisper::Message>,
    client_rx: Option<mpsc::Receiver<whisper::Message>>,
    config_tx: mpsc::Sender<Config>,
}

impl ClientHandle {
    pub fn send_msg(&mut self, msg: whisper::Message) -> Result<(), SendError<whisper::Message>> {
        self.client_tx.send(msg)?;
        Ok(())
    }
    pub fn get_msg(&mut self) -> Result<whisper::Message, crate::error::GossipError> {
        let rx = self.client_rx.as_mut();
        if rx.is_none() {
            return Err(crate::error::GossipError::ClonedHandleError);
        }
        let recv_result = rx.unwrap().recv();
        if recv_result.is_err() {
            return Err(crate::error::GossipError::BrokenQueueError);
        }
        Ok(recv_result.unwrap())
    }
    pub fn update_config(&mut self, cfg: Config) -> Result<(), SendError<Config>> {
        self.config_tx.send(cfg)
    }
    pub fn new(client_tx: mpsc::Sender<whisper::Message>, client_rx: Option<mpsc::Receiver<whisper::Message>>, config_tx: mpsc::Sender<Config>) -> ClientHandle {
        ClientHandle {
            client_tx,
            client_rx,
            config_tx,
        }
    }
}

impl Clone for ClientHandle {
    fn clone(&self) -> ClientHandle {
        ClientHandle { client_tx: self.client_tx.clone(), client_rx: None, config_tx: self.config_tx.clone() }
    }
}

pub struct State {
    pub receiver_tx: mpsc::Sender<whisper::Message>,
    pub gossiper_tx: mpsc::Sender<whisper::Message>,
    pub cipher: openssl::symm::Cipher,
    pub myself: neighborhood::Node,
    pub announcement: whisper::Message,
    pub connections: Vec<neighborhood::Node>,
    pub network_info: Vec<neighborhood::Node>,
    pub enc_key: Vec<u8>,
    pub config: Arc<Mutex<Config>>,
    pub tx: mpsc::Sender<whisper::Message>,
}
