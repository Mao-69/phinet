// phinet-core/src/board.rs
//! Anonymous distributed message board.
//!
//! Posts use per-post ephemeral X25519 keys — not linkable to node identity.
//! Channels are arbitrary strings or φ-cluster IDs.
//! Gossip deduplication by msg_id = SHA-256(ephem_pub ‖ channel ‖ text ‖ ts).

use crate::{crypto::sha256, wire::BoardPost};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

pub const BOARD_MAX_POSTS: usize = 1000;

pub struct MessageBoard {
    channels: RwLock<HashMap<String, VecDeque<BoardPost>>>,
    seen:     RwLock<HashSet<String>>,
}

impl MessageBoard {
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            seen:     RwLock::new(HashSet::new()),
        }
    }

    /// Create and store a new post. Returns the post.
    pub fn post(
        &self,
        channel: &str,
        text:    &str,
        cluster: Option<[u8; 32]>,
    ) -> BoardPost {
        // Ephemeral key — not linked to node identity
        let ephem_secret = StaticSecret::random_from_rng(OsRng);
        let ephem_pub    = PublicKey::from(&ephem_secret);
        let ephem_bytes  = ephem_pub.as_bytes();

        let ts = unix_now();

        // msg_id = SHA-256(ephem_pub ‖ channel ‖ text ‖ ts_le)
        let mut id_input = Vec::new();
        id_input.extend_from_slice(ephem_bytes);
        id_input.extend_from_slice(channel.as_bytes());
        id_input.extend_from_slice(text.as_bytes());
        id_input.extend_from_slice(&ts.to_le_bytes());
        let msg_id = hex::encode(sha256(&id_input));

        // MAC = SHA-256(ephem_pub ‖ "channel:text:ts")
        let mac_data = format!("{}:{}:{}", channel, text, ts);
        let mut mac_input = ephem_bytes.to_vec();
        mac_input.extend_from_slice(mac_data.as_bytes());
        let mac = hex::encode(sha256(&mac_input));

        let post = BoardPost {
            msg_id:    msg_id.clone(),
            channel:   channel.to_string(),
            text:      text.to_string(),
            ts,
            ephem_pub: hex::encode(ephem_bytes),
            mac,
            cluster:   cluster.map(|c| hex::encode(c)),
        };

        self.insert(&post, &msg_id);
        post
    }

    /// Merge an incoming post. Returns `true` if it was new (gossip it).
    pub fn merge(&self, post: &BoardPost) -> bool {
        if self.seen.read().unwrap().contains(&post.msg_id) {
            return false;
        }
        self.insert(post, &post.msg_id);
        true
    }

    fn insert(&self, post: &BoardPost, msg_id: &str) {
        {
            let mut seen = self.seen.write().unwrap();
            seen.insert(msg_id.to_string());
            if seen.len() > BOARD_MAX_POSTS * 10 {
                // Keep the newest half
                let v: Vec<_> = seen.iter().skip(seen.len() / 2).cloned().collect();
                *seen = v.into_iter().collect();
            }
        }
        let mut ch = self.channels.write().unwrap();
        let board  = ch.entry(post.channel.clone()).or_default();
        board.push_back(post.clone());
        if board.len() > BOARD_MAX_POSTS {
            board.pop_front();
        }
    }

    pub fn get(&self, channel: &str, limit: usize) -> Vec<BoardPost> {
        let ch = self.channels.read().unwrap();
        ch.get(channel).map(|b| {
            let skip = b.len().saturating_sub(limit);
            b.iter().skip(skip).cloned().collect()
        }).unwrap_or_default()
    }

    pub fn all_channels(&self) -> Vec<String> {
        self.channels.read().unwrap().keys().cloned().collect()
    }

    /// Verify the MAC on a post.
    pub fn verify(post: &BoardPost) -> bool {
        let Ok(eb) = hex::decode(&post.ephem_pub) else { return false };
        let mac_data = format!("{}:{}:{}", post.channel, post.text, post.ts);
        let mut input = eb;
        input.extend_from_slice(mac_data.as_bytes());
        hex::encode(sha256(&input)) == post.mac
    }
}

impl Default for MessageBoard {
    fn default() -> Self { Self::new() }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_and_get() {
        let b = MessageBoard::new();
        let p = b.post("general", "hello", None);
        assert_eq!(p.msg_id.len(), 64);
        let posts = b.get("general", 10);
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].text, "hello");
    }

    #[test]
    fn verify_mac() {
        let b = MessageBoard::new();
        let p = b.post("t", "msg", None);
        assert!(MessageBoard::verify(&p));
        let mut bad = p.clone(); bad.text = "tampered".into();
        assert!(!MessageBoard::verify(&bad));
    }

    #[test]
    fn dedup() {
        let b = MessageBoard::new();
        let p = b.post("c", "x", None);
        assert!(!b.merge(&p));
        assert_eq!(b.get("c", 100).len(), 1);
    }

    #[test]
    fn merge_new() {
        let b1 = MessageBoard::new();
        let b2 = MessageBoard::new();
        let p  = b2.post("news", "item", None);
        assert!(b1.merge(&p));
        assert_eq!(b1.get("news", 10).len(), 1);
    }

    #[test]
    fn cap() {
        let b = MessageBoard::new();
        for i in 0..BOARD_MAX_POSTS + 5 { b.post("s", &format!("{}", i), None); }
        assert_eq!(b.get("s", BOARD_MAX_POSTS + 100).len(), BOARD_MAX_POSTS);
    }
}
