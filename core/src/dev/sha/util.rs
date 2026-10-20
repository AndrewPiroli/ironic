#![allow(clippy::needless_range_loop)]
//! Minimal implementation of the SHA-1 algorithm.
//!
//! Apart from the fact that you shoud **not** use SHA-1, this is **not** an 
//! implementation that is suitable for, or otherwise intended for any kind of
//! practical cryptographic use outside of this particular application. 
//!
//! Do not even think about using this code somewhere else.
//!
//! For right now, we just assert that message size is a multiple of 64. I'm 
//! not sure what the hardware behavior is (either the SHA engine disregards 
//! messages which aren't a multiple of 64-bytes long, or it always performs 
//! DMA reads in 64-byte chunks).

use std::{sync::atomic::{AtomicU8, Ordering::{Acquire, Release, AcqRel}}};

pub(super) const K: [u32; 4] = [ 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6, ];

// Rust is annoying re: fn pointers.
// Technically this entire thing could be an AtomicPtr<unsafe fn(&mut Sha1State)>
// But no, that breaks everything.
const STATE_UNTOUCHED: u8 = 0;
const STATE_IN_MODIFICATION: u8 = 1;
const STATE_STEADY: u8 = 2;
static FN_PTR_STATE: AtomicU8 = AtomicU8::new(STATE_UNTOUCHED);
static mut PROCESS_MSG_FN: unsafe fn(&mut Sha1State) = Sha1State::process_message_scalar;

pub struct Sha1State {
    pub digest: [u32; 5],
    pub buf: [u8; 64],
}

impl Default for Sha1State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1State {
    pub fn new() -> Self {
        init_process_msg_fn_ptr();
        while FN_PTR_STATE.load(Acquire) != STATE_STEADY {
            std::hint::spin_loop();
        }
        Sha1State { digest: [0; 5], buf: [0; 64] }
    }
    pub fn reset(&mut self) {
        self.digest = [0; 5];
        self.buf = [0; 64];
    }
}

impl Sha1State {
    pub fn update(&mut self, input: &[u8]) {
        debug_assert!(input.len() & 63 == 0);
        for chunk in input.chunks_exact(64) {
            self.buf.copy_from_slice(chunk);
            self.process_message();
        }
    }

    fn process_message(&mut self) {
        // SAFETY:
        // Accessing a static mut
        //   The static is only ever written one time by Self::new, protected by an atomic flag
        //   since we have &mut self, the state must be STATE_STEADY so we are good
        // Calling the unsafe fn
        //   due to the use of #[target_feature] to enable optimizations, the initialization
        //   of the fn ptr does the proper feature checks to ensure the target_feature is present
        //   on the current CPU
        unsafe { PROCESS_MSG_FN(self) };
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    #[target_feature(enable = "sha2")]
    unsafe fn process_message_aarch_sha2(&mut self) {
        // SAFETY: This function is unsafe because it relies on the sha2 CPU extension, which isn’t
        // present on every ARMv8 CPU, but we are inside a function enabling this target feature so
        // it’s already checked.
        unsafe { super::aarch64::compress(&mut self.digest, &[self.buf]) }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    #[target_feature(enable = "sve2")]
    unsafe fn process_message_aarch_neon_sve2(&mut self) {
        self.process_message_scalar()
    }


    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn process_message_aarch_neon(&mut self) {
        self.process_message_scalar()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "fma")]
    unsafe fn process_message_ia_avx2_and_fma(&mut self) {
        self.process_message_scalar()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse4.2")]
    unsafe fn process_message_ia_sse42(&mut self) {
        self.process_message_scalar()
    }

    #[inline(always)]
    fn process_message_scalar(&mut self) {
        let mut a = self.digest[0];
        let mut b = self.digest[1];
        let mut c = self.digest[2];
        let mut d = self.digest[3];
        let mut e = self.digest[4];

        let mut w = [0u32; 80];
        for (idx, wb) in self.buf.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word.copy_from_slice(wb);
            let word = u32::from_be_bytes(word);
            w[idx] = word;
        }

        for t in 16..80 {
            let word = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
            w[t] = word.rotate_left(1);
        }

        for t in 0..20 {
            let temp = a.rotate_left(5)
                .wrapping_add((b & c) | ((!b) & d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K[0]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 20..40 {
            let temp = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K[1]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 40..60 {
            let temp = a.rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K[2]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for t in 60..80 {
            let temp = a.rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(K[3]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.digest[0] = self.digest[0].wrapping_add(a);
        self.digest[1] = self.digest[1].wrapping_add(b);
        self.digest[2] = self.digest[2].wrapping_add(c);
        self.digest[3] = self.digest[3].wrapping_add(d);
        self.digest[4] = self.digest[4].wrapping_add(e);

    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn init_process_msg_fn_ptr() {
    if FN_PTR_STATE.compare_exchange(STATE_UNTOUCHED, STATE_IN_MODIFICATION, AcqRel, Acquire).is_ok() {
        unsafe {
            if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
                PROCESS_MSG_FN = Sha1State::process_message_ia_avx2_and_fma;
            }
            else if is_x86_feature_detected!("sse4.2") {
                PROCESS_MSG_FN = Sha1State::process_message_ia_sse42;
            }
            else {
                PROCESS_MSG_FN = Sha1State::process_message_scalar;
            }
        }
        FN_PTR_STATE.store(STATE_STEADY, Release);
    }
}


#[cfg(target_arch = "aarch64")]
fn init_process_msg_fn_ptr() {
    use std::arch::is_aarch64_feature_detected;
    if FN_PTR_STATE.compare_exchange(STATE_UNTOUCHED, STATE_IN_MODIFICATION, AcqRel, Acquire).is_ok() {
        unsafe {
            if is_aarch64_feature_detected!("sha2") {
                PROCESS_MSG_FN = Sha1State::process_message_aarch_sha2;
            }
            else if is_aarch64_feature_detected!("sve2") {
                PROCESS_MSG_FN = Sha1State::process_message_aarch_neon_sve2;
            }
            else if is_aarch64_feature_detected!("neon") {
                PROCESS_MSG_FN = Sha1State::process_message_aarch_neon;
            }
            else {
                PROCESS_MSG_FN = Sha1State::process_message_scalar;
            }
        }
        FN_PTR_STATE.store(STATE_STEADY, Release);
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn init_process_msg_fn_ptr() {
    if FN_PTR_STATE.compare_exchange(STATE_UNTOUCHED, STATE_IN_MODIFICATION, AcqRel, Acquire).is_ok() {
        unsafe {
            PROCESS_MSG_FN = Sha1State::process_message_scalar;
        }
        FN_PTR_STATE.store(STATE_STEADY, Release);
    }
}
