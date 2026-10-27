pub mod crypto;
pub mod ecp;
pub mod events;
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use tempfile::{NamedTempFile, TempDir};
use zeroize::Zeroizing;
static CANCELLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn cancel_signal(_: i32) {
    CANCELLED.store(true, std::sync::atomic::Ordering::Relaxed);
}
fn check_cancel() -> Result<()> {
    ensure!(
        !CANCELLED.load(std::sync::atomic::Ordering::Relaxed),
        "Operation cancelled"
    );
    Ok(())
}
const CHUNK: usize = 1024 * 1024;
const LIMIT: u64 = 1024 * 1024;
const MAN: &str = "files/manifest.xml";
const PUB: &str = "files/signer.pub";
const SIG: &str = "files/signature.ed25519";
const DOMAIN: &[u8] = b"ESCrypter content signature v1\0";
fn xml(fields: &[(&str, String)]) -> Vec<u8> {
    let mut s = String::from("<escrypter>");
    for (k, v) in fields {
        s += &format!("<{k}>{v}</{k}>");
    }
    s += "</escrypter>";
    s.into_bytes()
}
// Only a deliberately small canonical XML subset is accepted: fixed field names,
// hexadecimal/numeric values. No entities, DTDs, namespaces, comments or attributes.
fn parse(b: &[u8], names: &[&str]) -> Result<BTreeMap<String, String>> {
    ensure!(b.len() <= LIMIT as usize, "Metadata too large");
    let s = std::str::from_utf8(b)?;
    let mut rest = s
        .strip_prefix("<escrypter>")
        .and_then(|x| x.strip_suffix("</escrypter>"))
        .context("Invalid XML envelope")?;
    let mut m = BTreeMap::new();
    for name in names {
        let start = format!("<{name}>");
        let end = format!("</{name}>");
        rest = rest.strip_prefix(&start).context("Unexpected XML field")?;
        let at = rest.find(&end).context("Missing XML end tag")?;
        let v = &rest[..at];
        ensure!(
            v.bytes().all(|c| c.is_ascii_hexdigit()),
            "Invalid XML value"
        );
        m.insert(name.to_string(), v.to_string());
        rest = &rest[at + end.len()..];
    }
    ensure!(rest.is_empty(), "Extra XML fields");
    Ok(m)
}
fn protect(m: &[u8], password: &str, context: &str) -> Result<Vec<u8>> {
    let salt = crypto::random(16);
    let nonce = crypto::random(24);
    let key = crypto::derive(password, &salt)?;
    let ad = format!(
        "ESCrypter/{context}/v1/argon2id13/m65536/t3/p1/{}",
        hex::encode(&salt)
    );
    let c = crypto::seal(m, &key, &nonce, ad.as_bytes())?;
    Ok(xml(&[
        ("version", "1".into()),
        ("memory", "65536".into()),
        ("iterations", "3".into()),
        ("salt", hex::encode(salt)),
        ("nonce", hex::encode(nonce)),
        ("ciphertext", hex::encode(c)),
    ]))
}
fn unprotect(b: &[u8], password: &str, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let m = parse(
        b,
        &[
            "version",
            "memory",
            "iterations",
            "salt",
            "nonce",
            "ciphertext",
        ],
    )?;
    ensure!(
        m["version"] == "1" && m["memory"] == "65536" && m["iterations"] == "3",
        "Unsupported KDF/version"
    );
    let salt = hex::decode(&m["salt"])?;
    let key = crypto::derive(password, &salt)?;
    let ad = format!(
        "ESCrypter/{context}/v1/argon2id13/m65536/t3/p1/{}",
        m["salt"]
    );
    crypto::open(
        &hex::decode(&m["ciphertext"])?,
        &key,
        &hex::decode(&m["nonce"])?,
        ad.as_bytes(),
    )
}
fn read_small(p: &Path) -> Result<Vec<u8>> {
    ensure!(fs::metadata(p)?.len() <= LIMIT, "Metadata too large");
    Ok(fs::read(p)?)
}
fn private_work(parent: Option<&Path>) -> Result<TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".escrypter-work-");
    let dir = match parent {
        Some(p) => builder.tempdir_in(p)?,
        None => builder.tempdir()?,
    };
    fs::write(
        dir.path().join("owner.json"),
        serde_json::to_vec(
            &serde_json::json!({"app":"ESCrypter","version":1,"pid":std::process::id(),"uid":unsafe{libc::getuid()}}),
        )?,
    )?;
    Ok(dir)
}
fn parent(p: &Path) -> &Path {
    p.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn publish(mut f: NamedTempFile, p: &Path) -> Result<()> {
    check_cancel()?;
    f.flush()?;
    f.as_file().sync_all()?;
    f.persist_noclobber(p).map_err(|e| e.error)?;
    File::open(parent(p))?.sync_all()?;
    Ok(())
}
fn keygen(path: &Path, pw: &str) -> Result<()> {
    ensure!(pw.chars().count() >= 12, "Use at least 12 characters");
    let (p, s) = crypto::keypair();
    let m = Zeroizing::new(xml(&[
        ("public", hex::encode(p)),
        ("secret", hex::encode(&*s)),
    ]));
    let mut f = NamedTempFile::new_in(parent(path))?;
    f.write_all(&protect(&m, pw, "signing-key")?)?;
    publish(f, path)
}
fn signer(path: &Path, pw: &str) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let m = unprotect(&read_small(path)?, pw, "signing-key")?;
    let m = parse(&m, &["public", "secret"])?;
    let p = hex::decode(&m["public"])?;
    let s = Zeroizing::new(hex::decode(&m["secret"])?);
    crypto::verify(b"key check", &crypto::sign(b"key check", &s)?, &p)?;
    Ok((p, s))
}
fn rand_index(n: usize) -> usize {
    let zone = u32::MAX - (u32::MAX % n as u32);
    loop {
        let v = u32::from_le_bytes(crypto::random(4).try_into().unwrap());
        if v < zone {
            return v as usize % n;
        }
    }
}
fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = rand_index(i + 1);
        v.swap(i, j)
    }
}
struct Enc {
    out: File,
    s: crypto::Stream,
    plain: u64,
}
impl Enc {
    fn new(mut out: File, key: &[u8]) -> Result<Self> {
        let (s, h) = crypto::Stream::push_init(key)?;
        out.write_all(&h)?;
        Ok(Self { out, s, plain: 0 })
    }
    fn record(&mut self, b: &[u8], last: bool) -> Result<()> {
        check_cancel()?;
        let c = self.s.push(b, last)?;
        self.out.write_all(&(c.len() as u32).to_le_bytes())?;
        self.out.write_all(&c)?;
        Ok(())
    }
    fn finish(mut self) -> Result<File> {
        while self.out.stream_position()? < 4_000_000 {
            self.record(&crypto::random(65536), false)?;
        }
        self.record(&[], true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}
impl Write for Enc {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        for b in b.chunks(CHUNK) {
            self.record(b, false).map_err(ioerr)?;
            self.plain += b.len() as u64;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
fn ioerr(e: anyhow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
fn append_input<W: Write>(
    tar: &mut tar::Builder<W>,
    p: &Path,
    name: &Path,
    total: &mut u64,
) -> Result<()> {
    check_cancel()?;
    let meta = fs::symlink_metadata(p)?;
    ensure!(
        meta.is_file() || meta.is_dir(),
        "Links and special files are not supported: {}",
        p.display()
    );
    if meta.is_dir() {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_mode(0o700);
        h.set_mtime(meta.mtime().max(0) as u64);
        h.set_cksum();
        tar.append_data(&mut h, name, io::empty())?;
        let mut children = fs::read_dir(p)?.collect::<io::Result<Vec<_>>>()?;
        children.sort_by_key(|e| e.file_name());
        for e in children {
            append_input(tar, &e.path(), &name.join(e.file_name()), total)?;
        }
    } else {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000)
            .open(p)?; // Linux O_NOFOLLOW
        let before = f.metadata()?;
        ensure!(before.is_file(), "Input changed type");
        let mut h = tar::Header::new_gnu();
        h.set_size(before.len());
        h.set_mode(0o600);
        h.set_mtime(before.mtime().max(0) as u64);
        h.set_cksum();
        tar.append_data(&mut h, name, &mut f)?;
        let after = f.metadata()?;
        ensure!(
            before.len() == after.len()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "Input changed while reading"
        );
        *total += before.len();
        events::emit(
            "progress",
            serde_json::json!({"phase":"encrypt","bytes":*total}),
        );
    }
    Ok(())
}
fn add<W: Write, R: Read>(t: &mut tar::Builder<W>, name: &str, size: u64, r: R) -> Result<()> {
    let mut h = tar::Header::new_ustar();
    h.set_size(size);
    h.set_mode(0o600);
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h.set_cksum();
    t.append_data(&mut h, name, r)?;
    Ok(())
}
fn hash_file(p: &Path) -> Result<Vec<u8>> {
    let mut h = Sha256::new();
    let mut f = File::open(p)?;
    let mut b = vec![0; CHUNK];
    loop {
        check_cancel()?;
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(h.finalize().to_vec())
}
fn transcript(items: &BTreeMap<String, PathBuf>) -> Result<Vec<u8>> {
    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update((items.len() as u32).to_le_bytes());
    for (name, p) in items {
        h.update((name.len() as u32).to_le_bytes());
        h.update(name.as_bytes());
        h.update(fs::metadata(p)?.len().to_le_bytes());
        h.update(hash_file(p)?);
    }
    Ok(h.finalize().to_vec())
}
fn input_size(p: &Path) -> Result<u64> {
    check_cancel()?;
    let m = fs::symlink_metadata(p)?;
    ensure!(m.is_file() || m.is_dir(), "Links/special files unsupported");
    let mut n = 4096u64;
    if m.is_dir() {
        for c in fs::read_dir(p)? {
            n = n
                .checked_add(input_size(&c?.path())?)
                .context("Size overflow")?;
        }
    } else {
        n = n.checked_add(m.len()).context("Size overflow")?;
    }
    Ok(n)
}
fn available(p: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), v.as_mut_ptr()) } == 0,
        "Cannot check free space"
    );
    let v = unsafe { v.assume_init() };
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}
fn encrypt(
    out: &Path,
    keypath: &Path,
    profile: u32,
    inputs: &[String],
    pw: &str,
    spw: &str,
    recovery: Option<&Path>,
) -> Result<()> {
    ensure!(!out.exists(), "Output already exists");
    ensure!(!inputs.is_empty(), "Select at least one input");
    ensure!(pw.chars().count() >= 12, "Use at least 12 characters");
    let (pubkey, secret) = signer(keypath, spw)?;
    let mut roots = HashSet::new();
    let mut checked = Vec::new();
    let outabs =
        fs::canonicalize(parent(out))?.join(out.file_name().context("Output filename required")?);
    for input in inputs {
        let p = Path::new(input);
        ensure!(
            !fs::symlink_metadata(p)?.file_type().is_symlink(),
            "Input links not supported"
        );
        let real = fs::canonicalize(p)?;
        ensure!(
            !outabs.starts_with(&real),
            "Output must be outside selected inputs"
        );
        let name = real
            .file_name()
            .context("Cannot archive filesystem root")?
            .to_os_string();
        ensure!(roots.insert(name.clone()), "Duplicate top-level filename");
        checked.push((real, PathBuf::from(name)));
    }
    let mut estimated = 0u64;
    for (p, _) in &checked {
        estimated = estimated
            .checked_add(input_size(p)?)
            .context("Size overflow")?;
    }
    let required = estimated
        .saturating_add(estimated / 100)
        .max(4_200_000)
        .saturating_mul(2)
        .saturating_add(16 * 1024 * 1024);
    ensure!(
        available(parent(out))? >= required,
        "Insufficient free space (conservative requirement: {} bytes)",
        required
    );
    events::emit(
        "total",
        serde_json::json!({"bytes":estimated,"phase":"encrypt"}),
    );
    let work = private_work(Some(parent(out)))?;
    let encrypted = work.path().join("stream");
    let key = Zeroizing::new(crypto::random(32));
    let enc = Enc::new(File::create(&encrypted)?, &key)?;
    let xz = xz2::write::XzEncoder::new(enc, profile);
    let mut tar = tar::Builder::new(xz);
    let mut total = 0;
    for (p, name) in checked {
        append_input(&mut tar, &p, &name, &mut total)?;
    }
    let xz = tar.into_inner()?;
    let enc = xz.finish()?;
    let compressed = enc.plain;
    let f = enc.finish()?;
    let cipher_len = f.metadata()?.len();
    drop(f);
    let mut codes: Vec<_> = (1000..10000).collect();
    shuffle(&mut codes);
    let mut paths = Vec::new();
    for (i, c) in codes[..100].iter().enumerate() {
        paths.push(format!("escs/esc{}/{c}.esc", (i / 10 + 1) * 10));
    }
    shuffle(&mut paths);
    events::emit("phase", serde_json::json!({"phase":"split"}));
    let mut source = File::open(&encrypted)?;
    let mut items = BTreeMap::new();
    for (i, name) in paths.iter().enumerate() {
        let n = cipher_len / 100 + if (i as u64) < cipher_len % 100 { 1 } else { 0 };
        let p = work.path().join(format!("piece{i}"));
        let mut f = File::create(&p)?;
        ensure!(
            io::copy(&mut (&mut source).take(n), &mut f)? == n,
            "Short stream"
        );
        items.insert(name.clone(), p);
    }
    drop(source);
    fs::remove_file(&encrypted)?;
    let manifest = Zeroizing::new(xml(&[
        ("version", "1".into()),
        ("key", hex::encode(&*key)),
        ("compressed", compressed.to_string()),
        ("cipherbytes", cipher_len.to_string()),
        ("unpacked", total.to_string()),
        ("order", hex::encode(paths.join("\n"))),
    ]));
    let protected = protect(&manifest, pw, "manifest")?;
    let mp = work.path().join("manifest");
    fs::write(&mp, protected)?;
    items.insert(MAN.into(), mp);
    if let Some(rp) = recovery {
        ensure!(!rp.exists(), "Recovery file exists");
        let rk = Zeroizing::new(crypto::random(32));
        let n = crypto::random(24);
        let c = crypto::seal(&manifest, &rk, &n, b"ESCrypter/recovery/v1")?;
        let p = work.path().join("recovery");
        fs::write(
            &p,
            xml(&[("nonce", hex::encode(n)), ("ciphertext", hex::encode(c))]),
        )?;
        items.insert("files/recovery.xml".into(), p);
        let mut rf = NamedTempFile::new_in(parent(rp))?;
        writeln!(rf, "{}", hex::encode(&*rk))?;
        publish(rf, rp)?;
    }
    let pp = work.path().join("pub");
    fs::write(&pp, &pubkey)?;
    items.insert(PUB.into(), pp);
    events::emit("phase", serde_json::json!({"phase":"sign"}));
    let sig = crypto::sign(&transcript(&items)?, &secret)?;
    let sp = work.path().join("sig");
    fs::write(&sp, sig)?;
    items.insert(SIG.into(), sp);
    let mut order: Vec<_> = items.iter().collect();
    shuffle(&mut order);
    events::emit("phase", serde_json::json!({"phase":"package"}));
    let mut dest = NamedTempFile::new_in(parent(out))?;
    {
        let mut tar = tar::Builder::new(&mut dest);
        for (name, p) in order {
            add(&mut tar, name, fs::metadata(p)?.len(), File::open(p)?)?;
        }
        tar.finish()?;
    }
    ensure!(
        dest.as_file().metadata()?.len() >= 4_000_000,
        "Internal minimum size error"
    );
    publish(dest, out)?;
    println!(
        "OK encrypted; signer {}",
        hex::encode(Sha256::digest(&pubkey))
    );
    Ok(())
}
fn piece_name(n: &str) -> bool {
    let p: Vec<_> = n.split('/').collect();
    p.len() == 3
        && p[0] == "escs"
        && (10..=100).step_by(10).any(|i| p[1] == format!("esc{i}"))
        && p[2].len() == 8
        && p[2].ends_with(".esc")
        && p[2][..4].bytes().all(|b| b.is_ascii_digit())
        && p[2].as_bytes()[0] != b'0'
}
struct Package {
    _work: TempDir,
    items: BTreeMap<String, PathBuf>,
    fingerprint: String,
}
fn inspect(path: &Path) -> Result<Package> {
    let work = private_work(None)?;
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.len() >= 4_000_000,
        "Package below minimum size"
    );
    ensure!(
        available(&std::env::temp_dir())? > file.metadata()?.len(),
        "Not enough temporary space"
    );
    let mut t = tar::Archive::new(file);
    let mut items = BTreeMap::new();
    let mut folders = BTreeMap::new();
    let mut codes = HashSet::new();
    for e in t.entries()? {
        check_cancel()?;
        let mut e = e?;
        ensure!(
            e.header().entry_type().is_file(),
            "Unexpected TAR entry type"
        );
        let name = e.path()?.to_str().context("Non UTF-8 entry")?.to_string();
        ensure!(
            piece_name(&name) || [MAN, PUB, SIG, "files/recovery.xml"].contains(&name.as_str()),
            "Unexpected package entry"
        );
        ensure!(
            !items.contains_key(&name) && items.len() < 104,
            "Duplicate/excess entries"
        );
        if piece_name(&name) {
            let p: Vec<_> = name.split('/').collect();
            *folders.entry(p[1].to_string()).or_insert(0) += 1;
            ensure!(codes.insert(p[2].to_string()), "Duplicate piece code");
        } else {
            ensure!(e.size() <= LIMIT, "Metadata too large");
        }
        let p = work.path().join(items.len().to_string());
        let mut f = File::create(&p)?;
        io::copy(&mut e, &mut f)?;
        items.insert(name, p);
    }
    let mut tail = t.into_inner();
    let mut buf = [0; 8192];
    let mut tail_len = 0;
    loop {
        let n = tail.read(&mut buf)?;
        if n == 0 {
            break;
        }
        tail_len += n;
        ensure!(
            tail_len <= 10240 && buf[..n].iter().all(|b| *b == 0),
            "Unexpected trailing TAR content"
        );
    }
    ensure!(
        folders.len() == 10 && folders.values().all(|n| *n == 10),
        "Expected 10 folders with 10 parts each"
    );
    ensure!(
        items.contains_key(MAN) && items.contains_key(PUB) && items.contains_key(SIG),
        "Missing metadata"
    );
    let sig = read_small(&items[SIG])?;
    items.remove(SIG);
    let pk = read_small(&items[PUB])?;
    crypto::verify(&transcript(&items)?, &sig, &pk)?;
    events::emit(
        "signer",
        serde_json::json!({"fingerprint":hex::encode(Sha256::digest(&pk)),"trusted":false}),
    );
    Ok(Package {
        _work: work,
        items,
        fingerprint: hex::encode(Sha256::digest(&pk)),
    })
}
struct Joined {
    files: Vec<PathBuf>,
    index: usize,
    current: Option<File>,
}
impl Read for Joined {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(f) = &mut self.current {
                let n = f.read(b)?;
                if n > 0 {
                    return Ok(n);
                }
            }
            if self.index == self.files.len() {
                return Ok(0);
            }
            self.current = Some(File::open(&self.files[self.index])?);
            self.index += 1;
        }
    }
}
struct Dec {
    r: Joined,
    s: crypto::Stream,
    remaining: u64,
    buf: Zeroizing<Vec<u8>>,
    at: usize,
    done: bool,
}
impl Dec {
    fn new(mut r: Joined, k: &[u8], n: u64) -> Result<Self> {
        let mut h = [0; 24];
        r.read_exact(&mut h)?;
        Ok(Self {
            r,
            s: crypto::Stream::pull_init(k, &h)?,
            remaining: n,
            buf: Zeroizing::new(Vec::new()),
            at: 0,
            done: false,
        })
    }
    fn next(&mut self) -> Result<()> {
        check_cancel()?;
        let mut len = [0; 4];
        self.r.read_exact(&mut len)?;
        let n = u32::from_le_bytes(len) as usize;
        ensure!((17..=CHUNK + 17).contains(&n), "Invalid record length");
        let mut c = vec![0; n];
        self.r.read_exact(&mut c)?;
        let (m, last) = self.s.pull(&c)?;
        let keep = (self.remaining.min(m.len() as u64)) as usize;
        self.remaining -= keep as u64;
        self.buf = m;
        self.buf.truncate(keep);
        self.at = 0;
        if last {
            ensure!(self.remaining == 0 && keep == 0, "Premature final record");
            let mut b = [0];
            ensure!(self.r.read(&mut b)? == 0, "Trailing encrypted data");
            self.done = true;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        while !self.done {
            self.next()?;
        }
        Ok(())
    }
}
impl Read for Dec {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        loop {
            if self.at < self.buf.len() {
                let n = b.len().min(self.buf.len() - self.at);
                b[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.remaining == 0 || self.done {
                return Ok(0);
            }
            self.next().map_err(ioerr)?;
        }
    }
}
fn get_manifest(p: &Package, pw: &str, recovery: bool) -> Result<Zeroizing<Vec<u8>>> {
    if recovery {
        let path = p
            .items
            .get("files/recovery.xml")
            .context("No recovery slot")?;
        let m = parse(&read_small(path)?, &["nonce", "ciphertext"])?;
        let key = Zeroizing::new(hex::decode(pw.trim())?);
        crypto::open(
            &hex::decode(&m["ciphertext"])?,
            &key,
            &hex::decode(&m["nonce"])?,
            b"ESCrypter/recovery/v1",
        )
    } else {
        unprotect(&read_small(&p.items[MAN])?, pw, "manifest")
    }
}
fn decrypt(input: &Path, out: &Path, pw: &str, recovery: bool, trust: Option<&str>) -> Result<()> {
    ensure!(!out.exists(), "Destination must not already exist");
    let p = inspect(input)?;
    if let Some(t) = trust {
        ensure!(
            t == p.fingerprint,
            "Signer does not match trusted fingerprint"
        );
    } else {
        events::emit(
            "signer",
            serde_json::json!({"fingerprint":p.fingerprint,"trusted":false}),
        );
    }
    let plain = get_manifest(&p, pw, recovery)?;
    let m = parse(
        &plain,
        &[
            "version",
            "key",
            "compressed",
            "cipherbytes",
            "unpacked",
            "order",
        ],
    )?;
    ensure!(m["version"] == "1", "Unsupported manifest");
    let order = String::from_utf8(hex::decode(&m["order"])?)?;
    let names: Vec<_> = order.split('\n').collect();
    ensure!(
        names.len() == 100 && names.iter().collect::<HashSet<_>>().len() == 100,
        "Invalid part order"
    );
    let mut files = Vec::new();
    let mut bytes = 0;
    for n in names {
        ensure!(piece_name(n), "Invalid piece path");
        let f = p.items.get(n).context("Missing piece")?;
        bytes += fs::metadata(f)?.len();
        files.push(f.clone());
    }
    ensure!(
        bytes == m["cipherbytes"].parse::<u64>()?,
        "Cipher size mismatch"
    );
    let declared = m["unpacked"].parse::<u64>()?;
    ensure!(
        available(parent(out))? > declared.saturating_add(16 * 1024 * 1024),
        "Insufficient extraction space"
    );
    events::emit(
        "total",
        serde_json::json!({"bytes":declared,"phase":"extract"}),
    );
    let key = Zeroizing::new(hex::decode(&m["key"])?);
    let dec = Dec::new(
        Joined {
            files,
            index: 0,
            current: None,
        },
        &key,
        m["compressed"].parse()?,
    )?;
    let stream = xz2::stream::Stream::new_stream_decoder(256 * 1024 * 1024, 0)?;
    let xz = xz2::read::XzDecoder::new_stream(dec, stream);
    let mut tar = tar::Archive::new(xz);
    let work = private_work(Some(parent(out)))?;
    let stage = work.path().join("result");
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut dir_times = Vec::new();
    for e in tar.entries()? {
        let mut e = e?;
        let path = e.path()?.into_owned();
        ensure!(
            !path.as_os_str().is_empty()
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "Unsafe archive path"
        );
        ensure!(
            seen.insert(path.clone()) && seen.len() <= 1_000_000,
            "Duplicate/excess inner entries"
        );
        let target = stage.join(&path);
        let ty = e.header().entry_type();
        ensure!(
            ty.is_file() || ty.is_dir(),
            "Links/special entries forbidden"
        );
        if ty.is_dir() {
            fs::create_dir_all(&target)?;
            dir_times.push((target, e.header().mtime()?));
        } else {
            total = total.checked_add(e.size()).context("Size overflow")?;
            ensure!(total <= declared, "Expanded size exceeds manifest");
            if let Some(d) = target.parent() {
                fs::create_dir_all(d)?;
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)?;
            ensure!(io::copy(&mut e, &mut f)? == e.size(), "Truncated file");
            f.sync_all()?;
            let mtime = e.header().mtime()?;
            filetime::set_file_mtime(
                &target,
                filetime::FileTime::from_unix_time(mtime.try_into()?, 0),
            )?;
            events::emit(
                "progress",
                serde_json::json!({"phase":"extract","bytes":total}),
            );
        }
    }
    ensure!(total == declared, "Expanded size mismatch");
    let mut xz = tar.into_inner();
    let mut tail = [0; 8192];
    let mut tailcount = 0;
    loop {
        let n = xz.read(&mut tail)?;
        if n == 0 {
            break;
        }
        tailcount += n;
        ensure!(
            tailcount <= 1024 * 1024 && tail[..n].iter().all(|b| *b == 0),
            "Unexpected data after inner TAR"
        );
    }
    let mut dec = xz.into_inner();
    ensure!(
        dec.remaining == 0 && dec.at == dec.buf.len(),
        "Unexpected data after XZ"
    );
    dec.finish()?;
    for (d, t) in dir_times.into_iter().rev() {
        filetime::set_file_mtime(d, filetime::FileTime::from_unix_time(t.try_into()?, 0))?;
    }
    // renameat2(RENAME_NOREPLACE) prevents races overwriting a destination.
    use std::os::unix::ffi::OsStrExt;
    let src = std::ffi::CString::new(stage.as_os_str().as_bytes())?;
    let dst = std::ffi::CString::new(out.as_os_str().as_bytes())?;
    extern "C" {
        fn renameat2(a: i32, b: *const i8, c: i32, d: *const i8, f: u32) -> i32;
    }
    check_cancel()?;
    ensure!(
        unsafe { renameat2(-100, src.as_ptr(), -100, dst.as_ptr(), 1) } == 0,
        "Cannot publish output: {}",
        io::Error::last_os_error()
    );
    File::open(parent(out))?.sync_all()?;
    println!("OK decrypted; signer {}", p.fingerprint);
    Ok(())
}
fn rekey(
    input: &Path,
    out: &Path,
    keypath: &Path,
    old: &str,
    new: &str,
    signpw: &str,
) -> Result<()> {
    ensure!(new.chars().count() >= 12, "Use at least 12 characters");
    ensure!(!out.exists(), "Output already exists");
    let mut p = inspect(input)?;
    let manifest = get_manifest(&p, old, false)?;
    let (public, secret) = signer(keypath, signpw)?;
    ensure!(
        read_small(&p.items[PUB])? == public,
        "Use the original signer key for password changes"
    );
    fs::write(&p.items[MAN], protect(&manifest, new, "manifest")?)?;
    let signature = crypto::sign(&transcript(&p.items)?, &secret)?;
    let sp = p._work.path().join("new-signature");
    fs::write(&sp, signature)?;
    p.items.insert(SIG.into(), sp);
    events::emit("phase", serde_json::json!({"phase":"package"}));
    let mut dest = NamedTempFile::new_in(parent(out))?;
    {
        let mut tar = tar::Builder::new(&mut dest);
        let mut order: Vec<_> = p.items.iter().collect();
        shuffle(&mut order);
        for (n, f) in order {
            add(&mut tar, n, fs::metadata(f)?.len(), File::open(f)?)?;
        }
        tar.finish()?;
    }
    publish(dest, out)?;
    println!("OK password changed; old copies remain accessible with old password");
    Ok(())
}
fn list_contents(input: &Path, pw: &str) -> Result<()> {
    let package = inspect(input)?;
    let plain = get_manifest(&package, pw, false)?;
    let m = parse(
        &plain,
        &[
            "version",
            "key",
            "compressed",
            "cipherbytes",
            "unpacked",
            "order",
        ],
    )?;
    ensure!(m["version"] == "1", "Unsupported manifest");
    let order = String::from_utf8(hex::decode(&m["order"])?)?;
    let names: Vec<_> = order.split('\n').collect();
    ensure!(
        names.len() == 100 && names.iter().collect::<HashSet<_>>().len() == 100,
        "Invalid order"
    );
    let mut files = Vec::new();
    let mut size = 0;
    for name in names {
        ensure!(piece_name(name), "Invalid piece path");
        let path = package.items.get(name).context("Missing part")?;
        size += fs::metadata(path)?.len();
        files.push(path.clone());
    }
    ensure!(size == m["cipherbytes"].parse::<u64>()?, "Size mismatch");
    let key = Zeroizing::new(hex::decode(&m["key"])?);
    let dec = Dec::new(
        Joined {
            files,
            index: 0,
            current: None,
        },
        &key,
        m["compressed"].parse()?,
    )?;
    let stream = xz2::stream::Stream::new_stream_decoder(256 * 1024 * 1024, 0)?;
    let xz = xz2::read::XzDecoder::new_stream(dec, stream);
    let mut tar = tar::Archive::new(xz);
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let declared = m["unpacked"].parse::<u64>()?;
    let mut total = 0u64;
    let mut json_size = 0;
    for entry in tar.entries()? {
        check_cancel()?;
        let entry = entry?;
        let path = entry.path()?.into_owned();
        ensure!(
            path.components().all(|c| matches!(c, Component::Normal(_)))
                && !path.as_os_str().is_empty(),
            "Unsafe inner path"
        );
        ensure!(seen.insert(path.clone()), "Duplicate inner path");
        let ty = entry.header().entry_type();
        ensure!(ty.is_dir() || ty.is_file(), "Unsupported inner type");
        if ty.is_file() {
            total = total.checked_add(entry.size()).context("Size overflow")?;
            ensure!(total <= declared, "Expanded size exceeds manifest");
        }
        let value = serde_json::json!({"name":path.to_string_lossy(),"directory":ty.is_dir(),"bytes":entry.size()});
        json_size += serde_json::to_vec(&value)?.len();
        ensure!(
            entries.len() < 10000 && json_size < 512 * 1024,
            "Contents preview limit exceeded; decrypt into a new folder instead"
        );
        entries.push(value);
    }
    ensure!(total == declared, "Expanded size mismatch");
    let mut xz = tar.into_inner();
    let mut tail = [0; 8192];
    let mut count = 0;
    loop {
        let n = xz.read(&mut tail)?;
        if n == 0 {
            break;
        }
        count += n;
        ensure!(
            count <= 1024 * 1024 && tail[..n].iter().all(|b| *b == 0),
            "Unexpected inner tail"
        );
    }
    let mut dec = xz.into_inner();
    ensure!(
        dec.remaining == 0 && dec.at == dec.buf.len(),
        "Unexpected compressed tail"
    );
    dec.finish()?;
    events::emit(
        "content",
        serde_json::json!({"entries":entries,"fingerprint":package.fingerprint}),
    );
    Ok(())
}
struct EchoGuard(Option<libc::termios>);
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, t);
            }
        }
    }
}
fn password(prompt: &str) -> Result<Zeroizing<String>> {
    let mut guard = EchoGuard(None);
    if unsafe { libc::isatty(0) } == 1 {
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        ensure!(
            unsafe { libc::tcgetattr(0, t.as_mut_ptr()) } == 0,
            "Cannot read terminal settings"
        );
        let old = unsafe { t.assume_init() };
        let mut new = old;
        new.c_lflag &= !libc::ECHO;
        ensure!(
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &new) } == 0,
            "Cannot hide password"
        );
        guard.0 = Some(old);
    }
    if !events::enabled() {
        eprintln!("PASSWORD {prompt}");
    }
    let mut s = Zeroizing::new(String::new());
    io::stdin().lock().take(4098).read_line(&mut s)?;
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    ensure!(s.len() <= 4096, "Password too long");
    Ok(s)
}
pub fn run_cli() -> Result<()> {
    crypto::init()?;
    if let Ok(value) = std::env::var("ESCRYPTER_MEMORY_MIB") {
        let mib = value.parse::<u64>()?;
        ensure!((256..=4096).contains(&mib), "Invalid memory limit");
        let limit = libc::rlimit {
            rlim_cur: mib * 1024 * 1024,
            rlim_max: mib * 1024 * 1024,
        };
        ensure!(
            unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } == 0,
            "Cannot apply worker memory limit"
        );
    }
    let mut a: Vec<String> = std::env::args().collect();
    let structured = a.get(1).map(String::as_str) == Some("--events");
    if structured {
        a.remove(1);
    }
    events::enable(structured);
    events::emit("started", serde_json::json!({"version":"0.2.0"}));
    match a.get(1).map(String::as_str) {
        Some("list-content") if a.len() == 3 => {
            list_contents(Path::new(&a[2]), &password("archive")?)
        }
        Some("public-key") if a.len() == 4 => {
            let (public, _) = signer(Path::new(&a[2]), &password("signing")?)?;
            let mut f = NamedTempFile::new_in(parent(Path::new(&a[3])))?;
            f.write_all(&public)?;
            publish(f, Path::new(&a[3]))
        }
        Some("key-password") if a.len() == 4 => {
            let old = password("old signing")?;
            let new = password("new signing")?;
            ensure!(new.chars().count() >= 12, "Use at least 12 characters");
            let m = unprotect(&read_small(Path::new(&a[2]))?, &old, "signing-key")?;
            let mut f = NamedTempFile::new_in(parent(Path::new(&a[3])))?;
            f.write_all(&protect(&m, &new, "signing-key")?)?;
            publish(f, Path::new(&a[3]))
        }
        Some("info") if a.len() == 3 => {
            let p = inspect(Path::new(&a[2]))?;
            events::emit(
                "package",
                serde_json::json!({"parts":100,"bytes":fs::metadata(&a[2])?.len(),"fingerprint":p.fingerprint,"recovery":p.items.contains_key("files/recovery.xml"),"format":1}),
            );
            Ok(())
        }
        Some("keygen") if a.len() == 3 => keygen(Path::new(&a[2]), &password("signing")?),
        Some("rekey") if a.len() == 5 => {
            let old = password("old archive")?;
            let new = password("new archive")?;
            let sp = password("signing")?;
            rekey(
                Path::new(&a[2]),
                Path::new(&a[3]),
                Path::new(&a[4]),
                &old,
                &new,
                &sp,
            )
        }
        Some("verify") if a.len() == 3 || a.len() == 4 => {
            let p = inspect(Path::new(&a[2]))?;
            if a.len() == 4 {
                ensure!(a[3] == p.fingerprint, "Signer mismatch");
                events::emit(
                    "signer",
                    serde_json::json!({"fingerprint":p.fingerprint,"trusted":true}),
                );
                println!("OK trusted {}", p.fingerprint)
            } else {
                println!("OK valid signature; UNKNOWN SIGNER {}", p.fingerprint)
            }
            Ok(())
        }
        Some("encrypt") if a.len() >= 7 => {
            let pw = password("archive")?;
            let spw = password("signing")?;
            let level = match a[4].as_str() {
                "fast" => 1,
                "balanced" => 6,
                "high" => 7,
                _ => bail!("Unknown profile"),
            };
            let recovery = if a[5] == "-" {
                None
            } else {
                Some(Path::new(&a[5]))
            };
            encrypt(
                Path::new(&a[2]),
                Path::new(&a[3]),
                level,
                &a[6..],
                &pw,
                &spw,
                recovery,
            )
        }
        Some("decrypt") | Some("recover") if a.len() == 4 || a.len() == 5 => {
            let pw = password("archive/recovery")?;
            decrypt(
                Path::new(&a[2]),
                Path::new(&a[3]),
                &pw,
                a[1] == "recover",
                a.get(4).map(String::as_str),
            )
        }
        _ => {
            ensure!(
                a.len() == 1 || (a.len() == 2 && matches!(a[1].as_str(), "--help" | "-h")),
                "Unknown command or invalid arguments; use --help"
            );
            println!("ESCrypter 0.2.0\nkeygen KEYFILE\nencrypt OUTPUT KEYFILE fast|balanced|high RECOVERY_FILE_OR_- INPUT...\ndecrypt INPUT NEW_DIRECTORY [TRUSTED_SHA256]\nrecover INPUT NEW_DIRECTORY [TRUSTED_SHA256]\nverify INPUT [TRUSTED_SHA256]\nPasswords are read from stdin, one line each; use the GUI for hidden password entry.");
            Ok(())
        }
    }
}
pub fn cli_main() {
    // Private files and directories, including plaintext extraction staging.
    extern "C" {
        fn umask(m: u32) -> u32;
    }
    extern "C" {
        fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    }
    unsafe {
        umask(0o077);
        signal(2, cancel_signal);
        signal(15, cancel_signal);
    }
    if let Err(e) = run_cli() {
        events::emit(
            "failed",
            serde_json::json!({"code":if CANCELLED.load(std::sync::atomic::Ordering::Relaxed){"cancelled"}else{"operation_failed"},"message":e.to_string()}),
        );
        eprintln!("ERROR {e:#}");
        std::process::exit(1)
    }
    events::emit("completed", serde_json::json!({}));
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crypto_authentication() {
        crypto::init().unwrap();
        let k = crypto::random(32);
        let n = crypto::random(24);
        let c = crypto::seal(b"test", &k, &n, b"domain").unwrap();
        assert!(crypto::open(&c, &k, &n, b"other").is_err());
        let mut bad = c;
        bad[0] ^= 1;
        assert!(crypto::open(&bad, &k, &n, b"domain").is_err());
    }
    #[test]
    fn bounded_xml() {
        assert!(parse(b"<!DOCTYPE x><escrypter></escrypter>", &[]).is_err());
        assert!(parse(b"<escrypter><a>1</a><a>2</a></escrypter>", &["a"]).is_err());
        assert!(parse(b"<escrypter><a>&xx;</a></escrypter>", &["a"]).is_err());
    }
    #[test]
    fn secretstream_final_and_mac() {
        crypto::init().unwrap();
        let k = crypto::random(32);
        let (mut enc, h) = crypto::Stream::push_init(&k).unwrap();
        let a = enc.push(b"abc", false).unwrap();
        let z = enc.push(&[], true).unwrap();
        let mut dec = crypto::Stream::pull_init(&k, &h).unwrap();
        assert_eq!(&*dec.pull(&a).unwrap().0, b"abc");
        assert!(dec.pull(&z).unwrap().1);
        let mut dec = crypto::Stream::pull_init(&k, &h).unwrap();
        let mut a = a;
        a[5] ^= 1;
        assert!(dec.pull(&a).is_err());
    }
    #[test]
    fn signed_but_bad_cipher_rejected() {
        crypto::init().unwrap();
        let d = TempDir::new().unwrap();
        let key = d.path().join("key");
        let input = d.path().join("input");
        let pkg = d.path().join("a.esc");
        let bad = d.path().join("bad.esc");
        let out = d.path().join("out");
        let pw = "long test password";
        keygen(&key, pw).unwrap();
        fs::write(&input, b"hello").unwrap();
        encrypt(
            &pkg,
            &key,
            1,
            &[input.to_string_lossy().into()],
            pw,
            pw,
            None,
        )
        .unwrap();
        let mut p = inspect(&pkg).unwrap();
        let manifest = get_manifest(&p, pw, false).unwrap();
        let m = parse(
            &manifest,
            &[
                "version",
                "key",
                "compressed",
                "cipherbytes",
                "unpacked",
                "order",
            ],
        )
        .unwrap();
        let order = String::from_utf8(hex::decode(&m["order"]).unwrap()).unwrap();
        let part = &p.items[order.lines().next().unwrap()];
        let mut bytes = fs::read(part).unwrap();
        bytes[40] ^= 1;
        fs::write(part, bytes).unwrap();
        let (_, sk) = signer(&key, pw).unwrap();
        let sig = crypto::sign(&transcript(&p.items).unwrap(), &sk).unwrap();
        let sp = d.path().join("sig");
        fs::write(&sp, sig).unwrap();
        p.items.insert(SIG.into(), sp);
        let mut tar = tar::Builder::new(File::create(&bad).unwrap());
        for (n, f) in &p.items {
            add(
                &mut tar,
                n,
                fs::metadata(f).unwrap().len(),
                File::open(f).unwrap(),
            )
            .unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        inspect(&bad).unwrap();
        assert!(decrypt(&bad, &out, pw, false, None).is_err());
        assert!(!out.exists());
    }
}
