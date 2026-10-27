use anyhow::{ensure, Result};
use std::ffi::c_void;
use zeroize::Zeroizing;
#[link(name = "sodium")]
extern "C" {
    fn sodium_init() -> i32;
    fn randombytes_buf(p: *mut c_void, n: usize);
    fn crypto_pwhash(
        o: *mut u8,
        n: u64,
        p: *const u8,
        pn: u64,
        s: *const u8,
        ops: u64,
        mem: usize,
        alg: i32,
    ) -> i32;
    fn crypto_aead_xchacha20poly1305_ietf_encrypt(
        c: *mut u8,
        cn: *mut u64,
        m: *const u8,
        mn: u64,
        a: *const u8,
        an: u64,
        s: *const u8,
        n: *const u8,
        k: *const u8,
    ) -> i32;
    fn crypto_aead_xchacha20poly1305_ietf_decrypt(
        m: *mut u8,
        mn: *mut u64,
        s: *mut u8,
        c: *const u8,
        cn: u64,
        a: *const u8,
        an: u64,
        n: *const u8,
        k: *const u8,
    ) -> i32;
    fn crypto_secretstream_xchacha20poly1305_statebytes() -> usize;
    fn crypto_secretstream_xchacha20poly1305_init_push(
        s: *mut c_void,
        h: *mut u8,
        k: *const u8,
    ) -> i32;
    fn crypto_secretstream_xchacha20poly1305_init_pull(
        s: *mut c_void,
        h: *const u8,
        k: *const u8,
    ) -> i32;
    fn crypto_secretstream_xchacha20poly1305_push(
        s: *mut c_void,
        c: *mut u8,
        cn: *mut u64,
        m: *const u8,
        mn: u64,
        a: *const u8,
        an: u64,
        t: u8,
    ) -> i32;
    fn crypto_secretstream_xchacha20poly1305_pull(
        s: *mut c_void,
        m: *mut u8,
        mn: *mut u64,
        t: *mut u8,
        c: *const u8,
        cn: u64,
        a: *const u8,
        an: u64,
    ) -> i32;
    fn crypto_sign_keypair(p: *mut u8, s: *mut u8) -> i32;
    fn crypto_sign_detached(sig: *mut u8, n: *mut u64, m: *const u8, mn: u64, k: *const u8) -> i32;
    fn crypto_sign_verify_detached(sig: *const u8, m: *const u8, mn: u64, k: *const u8) -> i32;
}
pub fn init() -> Result<()> {
    ensure!(
        unsafe { sodium_init() } >= 0,
        "Sodium initialization failed"
    );
    Ok(())
}
pub fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    unsafe { randombytes_buf(b.as_mut_ptr().cast(), n) };
    b
}
pub fn derive(p: &str, s: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(s.len() == 16, "Invalid salt");
    let mut k = Zeroizing::new(vec![0; 32]);
    ensure!(
        unsafe {
            crypto_pwhash(
                k.as_mut_ptr(),
                32,
                p.as_ptr(),
                p.len() as u64,
                s.as_ptr(),
                3,
                64 * 1024 * 1024,
                2,
            )
        } == 0,
        "Argon2id failed"
    );
    Ok(k)
}
pub fn seal(m: &[u8], k: &[u8], n: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    ensure!(k.len() == 32 && n.len() == 24, "Invalid AEAD parameters");
    let mut c = vec![0; m.len() + 16];
    let mut len = 0;
    ensure!(
        unsafe {
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                c.as_mut_ptr(),
                &mut len,
                m.as_ptr(),
                m.len() as u64,
                ad.as_ptr(),
                ad.len() as u64,
                std::ptr::null(),
                n.as_ptr(),
                k.as_ptr(),
            )
        } == 0,
        "Encryption failed"
    );
    Ok(c)
}
pub fn open(c: &[u8], k: &[u8], n: &[u8], ad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        k.len() == 32 && n.len() == 24 && c.len() >= 16,
        "Invalid AEAD parameters"
    );
    let mut m = Zeroizing::new(vec![0; c.len() - 16]);
    let mut len = 0;
    ensure!(
        unsafe {
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                m.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                c.as_ptr(),
                c.len() as u64,
                ad.as_ptr(),
                ad.len() as u64,
                n.as_ptr(),
                k.as_ptr(),
            )
        } == 0,
        "Wrong password or damaged protected record"
    );
    Ok(m)
}
pub struct Stream {
    state: Zeroizing<Vec<u64>>,
}
impl Stream {
    fn new() -> Self {
        Self {
            state: Zeroizing::new(vec![
                0;
                (unsafe {
                    crypto_secretstream_xchacha20poly1305_statebytes()
                } + 7)
                    / 8
            ]),
        }
    }
    pub fn push_init(k: &[u8]) -> Result<(Self, Vec<u8>)> {
        ensure!(k.len() == 32, "Invalid key");
        let mut s = Self::new();
        let mut h = vec![0; 24];
        ensure!(
            unsafe {
                crypto_secretstream_xchacha20poly1305_init_push(
                    s.state.as_mut_ptr().cast(),
                    h.as_mut_ptr(),
                    k.as_ptr(),
                )
            } == 0,
            "Stream initialization failed"
        );
        Ok((s, h))
    }
    pub fn pull_init(k: &[u8], h: &[u8]) -> Result<Self> {
        ensure!(k.len() == 32 && h.len() == 24, "Invalid stream header");
        let mut s = Self::new();
        ensure!(
            unsafe {
                crypto_secretstream_xchacha20poly1305_init_pull(
                    s.state.as_mut_ptr().cast(),
                    h.as_ptr(),
                    k.as_ptr(),
                )
            } == 0,
            "Invalid stream"
        );
        Ok(s)
    }
    pub fn push(&mut self, m: &[u8], last: bool) -> Result<Vec<u8>> {
        let mut c = vec![0; m.len() + 17];
        let mut n = 0;
        ensure!(
            unsafe {
                crypto_secretstream_xchacha20poly1305_push(
                    self.state.as_mut_ptr().cast(),
                    c.as_mut_ptr(),
                    &mut n,
                    m.as_ptr(),
                    m.len() as u64,
                    std::ptr::null(),
                    0,
                    if last { 3 } else { 0 },
                )
            } == 0,
            "Stream encryption failed"
        );
        Ok(c)
    }
    pub fn pull(&mut self, c: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        ensure!(c.len() >= 17, "Short record");
        let mut m = Zeroizing::new(vec![0; c.len() - 17]);
        let mut n = 0;
        let mut tag = 0;
        ensure!(
            unsafe {
                crypto_secretstream_xchacha20poly1305_pull(
                    self.state.as_mut_ptr().cast(),
                    m.as_mut_ptr(),
                    &mut n,
                    &mut tag,
                    c.as_ptr(),
                    c.len() as u64,
                    std::ptr::null(),
                    0,
                )
            } == 0,
            "Data authentication failed"
        );
        ensure!(tag == 0 || tag == 3, "Unsupported stream tag");
        Ok((m, tag == 3))
    }
}
pub fn keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut p = vec![0; 32];
    let mut s = Zeroizing::new(vec![0; 64]);
    unsafe { crypto_sign_keypair(p.as_mut_ptr(), s.as_mut_ptr()) };
    (p, s)
}
pub fn sign(m: &[u8], k: &[u8]) -> Result<Vec<u8>> {
    ensure!(k.len() == 64, "Invalid signing key");
    let mut s = vec![0; 64];
    let mut n = 0;
    ensure!(
        unsafe {
            crypto_sign_detached(
                s.as_mut_ptr(),
                &mut n,
                m.as_ptr(),
                m.len() as u64,
                k.as_ptr(),
            )
        } == 0,
        "Signing failed"
    );
    Ok(s)
}
pub fn verify(m: &[u8], s: &[u8], p: &[u8]) -> Result<()> {
    ensure!(s.len() == 64 && p.len() == 32, "Invalid signature size");
    ensure!(
        unsafe { crypto_sign_verify_detached(s.as_ptr(), m.as_ptr(), m.len() as u64, p.as_ptr()) }
            == 0,
        "Signature verification failed"
    );
    Ok(())
}
