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
