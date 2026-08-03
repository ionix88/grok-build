//! Capture protocol types shared with the TypeScript renderer (JSON shapes).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Semantic screen regions extracted after xterm write + font readiness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSnapshot {
    pub fixture_id: String,
    pub cols: u16,
    pub rows: u16,
    /// Ordered (region_id, normalized_text) pairs.
    pub regions: Vec<(String, String)>,
    pub raw_pty_sha256: String,
    /// Readiness barrier events that fired (never "sleep").
    pub readiness: Vec<String>,
}

impl SemanticSnapshot {
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex_sha256(&bytes)
    }
}

/// Which evidence files a capture produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureArtifacts {
    pub screenshot_present: bool,
    /// True when browser was skipped and only semantic/PTY evidence was written.
    pub semantic_only: bool,
    pub raw_pty_present: bool,
    pub process_tree_present: bool,
    pub readiness_event_present: bool,
    pub cleanup_present: bool,
}

/// Cleanup receipt after capture teardown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReceipt {
    pub clean: bool,
    pub leaked_pids: Vec<u32>,
    pub notes: String,
}

/// Full capture result written under `--out`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureResult {
    pub semantic: SemanticSnapshot,
    pub artifacts: CaptureArtifacts,
    pub cleanup: CleanupReceipt,
    pub mode: CaptureMode,
}

impl CaptureResult {
    pub fn semantic_digest(&self) -> String {
        self.semantic.digest()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureMode {
    SemanticOnly,
    Browser,
}

/// Fixture file shape (`fixtures/native-startup.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeStartupFixture {
    pub id: String,
    pub cols: u16,
    pub rows: u16,
    /// Raw PTY byte stream (may contain ANSI). Stored as JSON string.
    pub pty_bytes: String,
    /// Expected semantic regions after render.
    pub expected_regions: Vec<ExpectedRegion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectedRegion {
    pub id: String,
    pub text: String,
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let dig = h.finalize();
    let mut out = String::with_capacity(64);
    for b in dig {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// sha2 may not be a direct dep — use a tiny pure implementation if needed.
// Prefer std-only via a local hasher when sha2 is unavailable.
mod sha2 {
    pub use self::imp::{Digest, Sha256};

    mod imp {
        pub trait Digest {
            fn update(&mut self, data: impl AsRef<[u8]>);
            fn finalize(self) -> [u8; 32];
        }

        /// Minimal SHA-256 (public domain style) so the harness crate needs no new dep.
        pub struct Sha256 {
            state: [u32; 8],
            buffer: [u8; 64],
            buffer_len: usize,
            bit_len: u64,
        }

        impl Sha256 {
            pub fn new() -> Self {
                Self {
                    state: [
                        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                        0x1f83d9ab, 0x5be0cd19,
                    ],
                    buffer: [0; 64],
                    buffer_len: 0,
                    bit_len: 0,
                }
            }

            fn process_block(&mut self, block: &[u8; 64]) {
                const K: [u32; 64] = [
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
                    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
                    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
                    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
                ];
                let mut w = [0u32; 64];
                for i in 0..16 {
                    let j = i * 4;
                    w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
                }
                for i in 16..64 {
                    let s0 = w[i - 15].rotate_right(7)
                        ^ w[i - 15].rotate_right(18)
                        ^ (w[i - 15] >> 3);
                    let s1 = w[i - 2].rotate_right(17)
                        ^ w[i - 2].rotate_right(19)
                        ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[i - 7])
                        .wrapping_add(s1);
                }
                let mut a = self.state[0];
                let mut b = self.state[1];
                let mut c = self.state[2];
                let mut d = self.state[3];
                let mut e = self.state[4];
                let mut f = self.state[5];
                let mut g = self.state[6];
                let mut h = self.state[7];
                for i in 0..64 {
                    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                    let ch = (e & f) ^ ((!e) & g);
                    let t1 = h
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(K[i])
                        .wrapping_add(w[i]);
                    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let t2 = s0.wrapping_add(maj);
                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(t1);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);
                }
                self.state[0] = self.state[0].wrapping_add(a);
                self.state[1] = self.state[1].wrapping_add(b);
                self.state[2] = self.state[2].wrapping_add(c);
                self.state[3] = self.state[3].wrapping_add(d);
                self.state[4] = self.state[4].wrapping_add(e);
                self.state[5] = self.state[5].wrapping_add(f);
                self.state[6] = self.state[6].wrapping_add(g);
                self.state[7] = self.state[7].wrapping_add(h);
            }
        }

        impl Digest for Sha256 {
            fn update(&mut self, data: impl AsRef<[u8]>) {
                let data = data.as_ref();
                self.bit_len = self.bit_len.wrapping_add((data.len() as u64).wrapping_mul(8));
                let mut offset = 0;
                while offset < data.len() {
                    let space = 64 - self.buffer_len;
                    let take = (data.len() - offset).min(space);
                    self.buffer[self.buffer_len..self.buffer_len + take]
                        .copy_from_slice(&data[offset..offset + take]);
                    self.buffer_len += take;
                    offset += take;
                    if self.buffer_len == 64 {
                        let block = self.buffer;
                        self.process_block(&block);
                        self.buffer_len = 0;
                    }
                }
            }

            fn finalize(mut self) -> [u8; 32] {
                let mut block = [0u8; 64];
                block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
                block[self.buffer_len] = 0x80;
                if self.buffer_len >= 56 {
                    self.process_block(&block);
                    block = [0u8; 64];
                }
                block[56..].copy_from_slice(&self.bit_len.to_be_bytes());
                self.process_block(&block);
                let mut out = [0u8; 32];
                for (i, word) in self.state.iter().enumerate() {
                    out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
                }
                out
            }
        }
    }
}
