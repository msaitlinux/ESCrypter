//! ECP/1 over an authenticated SSH stdio bridge and a private Unix socket.
//! The OS account is the isolation boundary. Paths are confined by policy;
//! this is not a sandbox against another process running as that same account.
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;
const MAX_FRAME: usize = 262144;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub root: PathBuf,
    pub key_root: PathBuf,
    pub max_jobs: usize,
    pub memory_bytes: u64,
    pub max_file_bytes: u64,
    pub max_upload_bytes: u64,
    pub history_limit: usize,
}
#[derive(Clone, Deserialize, Serialize)]
struct Job {
    id: String,
    request_hash: String,
    operation: String,
    status: String,
    created: u64,
    seq: u64,
    events: VecDeque<Value>,
    output: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Upload {
    id: String,
    temp: PathBuf,
    destination: PathBuf,
    sha256: String,
    size: u64,
    created: u64,
    finished: bool,
    #[serde(default)]
    finalizing: bool,
    receipt: Option<Value>,
}
struct Service {
    cfg: Config,
    dir: PathBuf,
    jobs: Mutex<BTreeMap<String, Job>>,
    children: Mutex<BTreeMap<String, Child>>,
    uploads: Mutex<BTreeMap<String, Upload>>,
    receipt: zeroize::Zeroizing<Vec<u8>>,
    receipt_pub: Vec<u8>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn data_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"))
        .join("escrypter")
}
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}
fn config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("escrypter/agent.json")
}
fn socket_path() -> Result<PathBuf> {
    let uid = unsafe { libc::getuid() };
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    ensure!(
        base.is_dir(),
        "User runtime directory unavailable; start a user session/service"
    );
    Ok(base.join("escrypter/agent.sock"))
}
fn private_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink(),
        "Invalid state directory"
    );
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn save<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    let mut f = tempfile::NamedTempFile::new_in(p.parent().context("No parent")?)?;
    serde_json::to_writer(&mut f, v)?;
    f.flush()?;
    f.as_file().sync_all()?;
    f.persist(p).map_err(|e| e.error)?;
    File::open(p.parent().context("No parent")?)?.sync_all()?;
    Ok(())
}
fn read_json<T: for<'a> Deserialize<'a>>(p: &Path) -> Result<T> {
    ensure!(
        fs::metadata(p)?.len() <= 16 * 1024 * 1024,
        "State file too large"
    );
    Ok(serde_json::from_reader(File::open(p)?)?)
}
fn id(s: &str) -> Result<()> {
    ensure!(
        (16..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "Invalid request/job ID"
    );
    Ok(())
}
fn field<'a>(v: &'a Value, n: &str) -> Result<&'a str> {
    v.get(n)
        .and_then(Value::as_str)
        .with_context(|| format!("Missing field: {n}"))
}
fn frame_read(r: &mut impl Read) -> Result<Option<Value>> {
    let mut size = [0u8; 4];
    match r.read(&mut size[..1])? {
        0 => return Ok(None),
        _ => {}
    }
    r.read_exact(&mut size[1..])?;
    let n = u32::from_be_bytes(size) as usize;
    ensure!(n > 0 && n <= MAX_FRAME, "Frame exceeds protocol limit");
    let mut bytes = zeroize::Zeroizing::new(vec![0; n]);
    r.read_exact(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn frame_write(w: &mut impl Write, v: &Value) -> Result<()> {
    let b = serde_json::to_vec(v)?;
    ensure!(b.len() <= MAX_FRAME, "Response too large");
    w.write_all(&(b.len() as u32).to_be_bytes())?;
    w.write_all(&b)?;
    w.flush()?;
    Ok(())
}
fn confined(root: &Path, s: &str, output: bool) -> Result<PathBuf> {
    let rel = Path::new(s);
    ensure!(
        !rel.is_absolute() && rel.components().all(|c| matches!(c, Component::Normal(_))),
        "Only relative normal paths are accepted"
    );
    let root = fs::canonicalize(root)?;
    let candidate = root.join(rel);
    let mut cursor = root.clone();
    for c in rel.components() {
        cursor.push(c.as_os_str());
        if cursor.exists() {
            ensure!(
                !fs::symlink_metadata(&cursor)?.file_type().is_symlink(),
                "Symlinks are forbidden"
            );
        }
    }
    if output {
        ensure!(!candidate.exists(), "Output already exists");
        let p = fs::canonicalize(candidate.parent().context("Invalid output")?)?;
        ensure!(p.starts_with(&root), "Path outside root");
    } else {
        ensure!(
            fs::canonicalize(&candidate)?.starts_with(&root),
            "Path outside root"
        );
    }
    Ok(candidate)
}
fn hash(p: &Path, limit: Option<u64>) -> Result<String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    ensure!(f.metadata()?.is_file(), "Not a regular file");
    let mut r = f.take(limit.unwrap_or(u64::MAX));
    let mut h = Sha256::new();
    let mut b = vec![0; 1024 * 1024];
    loop {
        let n = r.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
impl Service {
    fn record(&self, jid: &str, event: Value) -> Result<()> {
        let mut jobs = self.jobs.lock().unwrap();
        let j = jobs.get_mut(jid).context("Unknown job")?;
        j.seq += 1;
        let event = json!({"seq":j.seq,"event":event});
        j.events.push_back(event);
        while j.events.len() > 512 {
            j.events.pop_front();
        }
        save(&self.dir.join("jobs.json"), &*jobs)
    }
    fn status(&self, jid: &str, status: &str) -> Result<()> {
        let mut jobs = self.jobs.lock().unwrap();
        jobs.get_mut(jid).context("Unknown job")?.status = status.to_string();
        save(&self.dir.join("jobs.json"), &*jobs)
    }
    fn arguments(&self, v: &Value) -> Result<(Vec<String>, Option<String>, usize)> {
        let op = field(v, "operation")?;
        let mut a = vec![op.to_string()];
        let mut output = None;
        let secret_count;
        match op {
            "verify" | "info" => {
                a.push(
                    confined(&self.cfg.root, field(v, "input")?, false)?
                        .to_string_lossy()
                        .into(),
                );
                secret_count = 0;
            }
            "decrypt" | "recover" => {
                a.push(
                    confined(&self.cfg.root, field(v, "input")?, false)?
                        .to_string_lossy()
                        .into(),
                );
                let o = field(v, "output")?;
                a.push(confined(&self.cfg.root, o, true)?.to_string_lossy().into());
                output = Some(o.into());
                secret_count = 1;
            }
            "encrypt" => {
                let o = field(v, "output")?;
                a.push(confined(&self.cfg.root, o, true)?.to_string_lossy().into());
                output = Some(o.into());
                a.push(
                    confined(&self.cfg.key_root, field(v, "key")?, false)?
                        .to_string_lossy()
                        .into(),
                );
                let profile = field(v, "profile")?;
                ensure!(
                    ["fast", "balanced", "high"].contains(&profile),
                    "Invalid profile"
                );
                a.push(profile.into());
                a.push("-".into());
                let inputs = v["inputs"].as_array().context("Missing inputs")?;
                ensure!(
                    !inputs.is_empty() && inputs.len() <= 256,
                    "Invalid input count"
                );
                for p in inputs {
                    a.push(
                        confined(&self.cfg.root, p.as_str().context("Invalid input")?, false)?
                            .to_string_lossy()
                            .into(),
                    );
                }
                secret_count = 2;
            }
            "rekey" => {
                a.push(
                    confined(&self.cfg.root, field(v, "input")?, false)?
                        .to_string_lossy()
                        .into(),
                );
                let o = field(v, "output")?;
                a.push(confined(&self.cfg.root, o, true)?.to_string_lossy().into());
                output = Some(o.into());
                a.push(
                    confined(&self.cfg.key_root, field(v, "key")?, false)?
                        .to_string_lossy()
                        .into(),
                );
                secret_count = 3;
            }
            _ => bail!("Unsupported operation"),
        }
        if matches!(op, "decrypt" | "recover" | "verify") {
            if let Some(fp) = v["trusted_signer"].as_str() {
                ensure!(
                    fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Invalid fingerprint"
                );
                a.push(fp.to_string());
            }
        }
        Ok((a, output, secret_count))
    }
    fn submit(self: &Arc<Self>, request: &Value) -> Result<Value> {
        let jid = field(request, "job_id")?;
        id(jid)?;
        let spec = &request["spec"];
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(spec)?));
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(j) = jobs.get(jid) {
            ensure!(
                j.request_hash == digest,
                "ID already used for a different request"
            );
            return Ok(json!({"job":j,"replayed":true}));
        }
        ensure!(
            jobs.values()
                .filter(|j| j.status == "running" || j.status == "starting")
                .count()
                < self.cfg.max_jobs,
            "Server concurrency limit reached"
        );
        ensure!(
            jobs.len() < self.cfg.history_limit,
            "History limit reached; forget completed jobs first"
        );
        let (args, output, count) = self.arguments(spec)?;
        let empty = Vec::new();
        let secrets = request["secrets"].as_array().unwrap_or(&empty);
        ensure!(secrets.len() == count, "Incorrect secret count");
        let mut input = zeroize::Zeroizing::new(Vec::new());
        for s in secrets {
            let s = s.as_str().context("Invalid secret")?;
            ensure!(
                s.len() <= 4096 && !s.contains(['\n', '\r']),
                "Invalid secret"
            );
            input.extend_from_slice(s.as_bytes());
            input.push(b'\n');
        }
        let j = Job {
            id: jid.into(),
            request_hash: digest,
            operation: field(spec, "operation")?.into(),
            status: "starting".into(),
            created: now(),
            seq: 0,
            events: VecDeque::new(),
            output,
        };
        jobs.insert(jid.into(), j);
        save(&self.dir.join("jobs.json"), &*jobs)?;
        drop(jobs);
        let binary = std::env::current_exe()?.with_file_name("escrypter");
        let mut cmd = Command::new(binary);
        cmd.arg("--events")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home())
            .env("TMPDIR", self.dir.join("tmp"));
        let mem = self.cfg.memory_bytes;
        let size = self.cfg.max_file_bytes;
        unsafe {
            cmd.pre_exec(move || {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let memory = libc::rlimit {
                    rlim_cur: mem,
                    rlim_max: mem,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let file = libc::rlimit {
                    rlim_cur: size,
                    rlim_max: size,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &file) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.status(jid, "failed")?;
                return Err(e.into());
            }
        };
        let stderr = child.stderr.take().context("Worker stderr")?;
        let write = child
            .stdin
            .take()
            .context("Worker stdin")?
            .write_all(&input);
        if let Err(e) = write {
            let _ = child.kill();
            let _ = child.wait();
            self.status(jid, "failed")?;
            return Err(e.into());
        }
        self.children.lock().unwrap().insert(jid.into(), child);
        self.status(jid, "running")?;
        let service = self.clone();
        let jobid = jid.to_string();
        thread::spawn(move || {
            let mut r = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                match (&mut r).take(65537).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) if n <= 65536 => {
                        if let Ok(v) = serde_json::from_str::<Value>(&line) {
                            let _ = service.record(&jobid, v);
                        }
                    }
                    _ => break,
                }
            }
            loop {
                let mut children = service.children.lock().unwrap();
                let ended = match children.get_mut(&jobid) {
                    Some(c) => c.try_wait(),
                    None => break,
                };
                match ended {
                    Ok(Some(status)) => {
                        children.remove(&jobid);
                        drop(children);
                        let _ = service.status(
                            &jobid,
                            if status.success() {
                                "completed"
                            } else {
                                "failed"
                            },
                        );
                        break;
                    }
                    Err(_) => {
                        children.remove(&jobid);
                        drop(children);
                        let _ = service.status(&jobid, "failed");
                        break;
                    }
                    _ => {
                        drop(children);
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });
        Ok(json!({"job_id":jid,"status":"running"}))
    }
    fn handle(self: &Arc<Self>, v: &Value) -> Result<Value> {
        ensure!(v["v"] == 1, "Unsupported ECP version");
        match field(v, "method")? {
            "hello" => Ok(
                json!({"protocol":"ECP","version":1,"app_version":"0.2.0","root":self.cfg.root,"capabilities":["list","submit","jobs","events","cancel","hash","upload_prepare","upload_finish","receipts"],"max_jobs":self.cfg.max_jobs,"memory_limit_bytes":self.cfg.memory_bytes,"max_file_bytes":self.cfg.max_file_bytes,"receipt_public_key":hex::encode(&self.receipt_pub)}),
            ),
            "list" => {
                let rel = v["path"].as_str().unwrap_or("");
                let p = if rel.is_empty() {
                    fs::canonicalize(&self.cfg.root)?
                } else {
                    confined(&self.cfg.root, rel, false)?
                };
                ensure!(p.is_dir(), "Not a directory");
                let offset = v["offset"].as_u64().unwrap_or(0) as usize;
                let mut entries = fs::read_dir(p)?.collect::<io::Result<Vec<_>>>()?;
                entries.sort_by_key(|x| x.file_name());
                let count = entries.len();
                let rows=entries.into_iter().skip(offset).take(100).map(|e|{let m=fs::symlink_metadata(e.path())?;Ok(json!({"name":e.file_name().to_string_lossy(),"directory":m.is_dir(),"symlink":m.file_type().is_symlink(),"bytes":m.len()}))}).collect::<Result<Vec<_>>>()?;
                Ok(
                    json!({"entries":rows,"next":if offset+100<count{Some(offset+100)}else{None},"total":count}),
                )
            }
            "jobs" => {
                let jobs = self.jobs.lock().unwrap();
                let list:Vec<_>=jobs.values().map(|j|json!({"id":j.id,"status":j.status,"operation":j.operation,"created":j.created,"output":j.output,"seq":j.seq})).collect();
                Ok(
                    json!({"jobs":list,"resources":{"free_disk_bytes":crate::available(&self.cfg.root)?,"running":self.children.lock().unwrap().len(),"max_jobs":self.cfg.max_jobs}}),
                )
            }
            "events" => {
                let jobs = self.jobs.lock().unwrap();
                let j = jobs.get(field(v, "job_id")?).context("Unknown job")?;
                let after = v["after"].as_u64().unwrap_or(0);
                let events: Vec<_> = j
                    .events
                    .iter()
                    .filter(|e| e["seq"].as_u64().unwrap_or(0) > after)
                    .take(64)
                    .cloned()
                    .collect();
                Ok(
                    json!({"events":events,"status":j.status,"latest":j.seq,"gap":j.events.front().map(|e|after+1<e["seq"].as_u64().unwrap_or(0)).unwrap_or(false)}),
                )
            }
            "submit" => self.submit(v),
            "cancel" => {
                let jid = field(v, "job_id")?;
                let mut children = self.children.lock().unwrap();
                let c = children.get_mut(jid).context("Job is not running")?;
                ensure!(c.try_wait()?.is_none(), "Job already ended");
                ensure!(
                    unsafe { libc::kill(c.id() as i32, libc::SIGTERM) } == 0,
                    "Could not request cancellation"
                );
                Ok(json!({"cancellation_requested":true}))
            }
            "forget" => {
                let jid = field(v, "job_id")?;
                ensure!(
                    !self.children.lock().unwrap().contains_key(jid),
                    "Cannot forget an active job"
                );
                let mut jobs = self.jobs.lock().unwrap();
                jobs.remove(jid);
                save(&self.dir.join("jobs.json"), &*jobs)?;
                Ok(json!({"forgotten":true}))
            }
            "hash" => {
                let p = confined(&self.cfg.root, field(v, "path")?, false)?;
                Ok(
                    json!({"sha256":hash(&p,v["prefix_bytes"].as_u64())?,"bytes":fs::metadata(p)?.len()}),
                )
            }
            "upload_prepare" => self.upload_prepare(v),
            "upload_finish" => self.upload_finish(v),
            _ => bail!("Unknown ECP method"),
        }
    }
    fn upload_prepare(&self, v: &Value) -> Result<Value> {
        let uid = field(v, "upload_id")?;
        id(uid)?;
        let size = v["size"].as_u64().context("Missing size")?;
        ensure!(size <= self.cfg.max_file_bytes, "File exceeds server limit");
        let expected = field(v, "sha256")?;
        ensure!(
            expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid digest"
        );
        let mut uploads = self.uploads.lock().unwrap();
        if let Some(u) = uploads.get(uid) {
            ensure!(
                u.sha256 == expected
                    && u.size == size
                    && u.destination == self.cfg.root.join(field(v, "path")?),
                "Upload ID belongs to different content"
            );
            if u.finalizing && !u.finished {
                drop(uploads);
                let done = self.upload_finish(v)?;
                return Ok(json!({"finished":true,"receipt":done["receipt"]}));
            }
            if u.finished {
                return Ok(json!({"finished":true,"receipt":u.receipt}));
            }
            let m = fs::metadata(&u.temp)?;
            ensure!(m.len() <= u.size, "Partial file too large");
            return Ok(
                json!({"temporary_path":u.temp,"offset":m.len(),"prefix_sha256":hash(&u.temp,None)?}),
            );
        }
        ensure!(
            uploads.len() < self.cfg.history_limit,
            "Upload history limit reached"
        );
        let reserved = uploads
            .values()
            .filter(|u| !u.finished)
            .try_fold(0u64, |a, u| a.checked_add(u.size).context("Quota overflow"))?;
        ensure!(
            reserved.saturating_add(size) <= self.cfg.max_upload_bytes,
            "Upload quota exceeded"
        );
        ensure!(
            crate::available(&self.cfg.root)? > size.saturating_add(16 * 1024 * 1024),
            "Insufficient server disk space"
        );
        let dst = confined(&self.cfg.root, field(v, "path")?, true)?;
        let temp = dst
            .parent()
            .unwrap()
            .join(format!(".escrypter-upload-{uid}"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let u = Upload {
            id: uid.into(),
            temp: temp.clone(),
            destination: dst,
            sha256: expected.into(),
            size,
            created: now(),
            finished: false,
            finalizing: false,
            receipt: None,
        };
        uploads.insert(uid.into(), u);
        save(&self.dir.join("uploads.json"), &*uploads)?;
        Ok(
            json!({"temporary_path":temp,"offset":0,"prefix_sha256":hex::encode(Sha256::digest([]))}),
        )
    }
    fn upload_finish(&self, v: &Value) -> Result<Value> {
        let mut uploads = self.uploads.lock().unwrap();
        let uid = field(v, "upload_id")?;
        let mut u = uploads.get(uid).context("Unknown upload")?.clone();
        if u.finished {
            return Ok(json!({"receipt":u.receipt}));
        }
        if u.temp.exists() {
            ensure!(
                fs::metadata(&u.temp)?.len() == u.size && hash(&u.temp, None)? == u.sha256,
                "Upload size/hash mismatch"
            );
            File::open(&u.temp)?.sync_all()?;
            if !u.finalizing {
                let payload = json!({"v":1,"upload_id":u.id,"sha256":u.sha256,"bytes":u.size,"received_at":now()});
                let bytes = serde_json::to_vec(&payload)?;
                let mut msg = b"ESCrypter receipt v1\0".to_vec();
                msg.extend_from_slice(&bytes);
                let sig = crate::crypto::sign(&msg, &self.receipt)?;
                u.receipt = Some(
                    json!({"payload_hex":hex::encode(bytes),"signature":hex::encode(sig),"public_key":hex::encode(&self.receipt_pub)}),
                );
                u.finalizing = true;
                uploads.insert(uid.into(), u.clone());
                save(&self.dir.join("uploads.json"), &*uploads)?;
            }
            use std::os::unix::ffi::OsStrExt;
            let a = std::ffi::CString::new(u.temp.as_os_str().as_bytes())?;
            let b = std::ffi::CString::new(u.destination.as_os_str().as_bytes())?;
            ensure!(
                unsafe {
                    libc::renameat2(
                        libc::AT_FDCWD,
                        a.as_ptr(),
                        libc::AT_FDCWD,
                        b.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                } == 0,
                "Cannot finalize without overwriting destination"
            );
        } else {
            ensure!(
                u.finalizing && u.receipt.is_some(),
                "Upload temporary file missing"
            );
            ensure!(
                fs::metadata(&u.destination)?.len() == u.size
                    && hash(&u.destination, None)? == u.sha256,
                "Finalized destination changed"
            );
        }
        File::open(u.destination.parent().unwrap())?.sync_all()?;
        u.finished = true;
        let receipt = u.receipt.clone();
        uploads.insert(uid.into(), u);
        save(&self.dir.join("uploads.json"), &*uploads)?;
        Ok(json!({"receipt":receipt}))
    }
}
fn peer_ok(stream: &UnixStream) -> Result<()> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut n,
            )
        } == 0,
        "Cannot authenticate local peer"
    );
    ensure!(
        unsafe { cred.assume_init().uid == libc::getuid() },
        "Wrong peer account"
    );
    Ok(())
}
fn serve() -> Result<()> {
    crate::crypto::init()?;
    let cfg: Config = read_json(&config_path())?;
    ensure!(
        (1..=8).contains(&cfg.max_jobs) && (1..=200).contains(&cfg.history_limit),
        "Invalid service limits"
    );
    let cfg = Config {
        root: fs::canonicalize(&cfg.root)?,
        key_root: fs::canonicalize(&cfg.key_root)?,
        ..cfg
    };
    ensure!(
        !cfg.root.starts_with(&cfg.key_root) && !cfg.key_root.starts_with(&cfg.root),
        "Key root and data root must be separate"
    );
    let dir = data_dir();
    private_dir(&dir)?;
    private_dir(&dir.join("tmp"))?;
    let path = socket_path()?;
    private_dir(path.parent().unwrap())?;
    // Lock survives for the process lifetime; do not unlink another live socket.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path.with_extension("lock"))?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Agent already running"
    );
    let mut jobs: BTreeMap<String, Job> = if dir.join("jobs.json").exists() {
        read_json(&dir.join("jobs.json"))?
    } else {
        BTreeMap::new()
    };
    for j in jobs.values_mut() {
        if j.status == "running" || j.status == "starting" {
            j.status = "interrupted".into();
        }
    }
    save(&dir.join("jobs.json"), &jobs)?;
    let uploads = if dir.join("uploads.json").exists() {
        read_json(&dir.join("uploads.json"))?
    } else {
        BTreeMap::new()
    };
    let keypath = dir.join("receipt.key");
    let (public, secret) = if keypath.exists() {
        let b = zeroize::Zeroizing::new(fs::read(&keypath)?);
        ensure!(b.len() == 96, "Invalid receipt key");
        (b[..32].to_vec(), zeroize::Zeroizing::new(b[32..].to_vec()))
    } else {
        let (p, s) = crate::crypto::keypair();
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(keypath)?;
        f.write_all(&p)?;
        f.write_all(&s)?;
        f.sync_all()?;
        (p, s)
    };
    let service = Arc::new(Service {
        cfg,
        dir,
        jobs: Mutex::new(jobs),
        children: Mutex::new(BTreeMap::new()),
        uploads: Mutex::new(uploads),
        receipt: secret,
        receipt_pub: public,
    });
    if path.exists() {
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let count = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        if peer_ok(&stream).is_err() {
            continue;
        }
        if count.fetch_add(1, Ordering::SeqCst) >= 16 {
            count.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let count = count.clone();
        let service = service.clone();
        thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            loop {
                let mut v = match frame_read(&mut stream) {
                    Ok(Some(v)) => v,
                    _ => break,
                };
                let rid = v["id"].as_str().unwrap_or("").to_string();
                if rid.len() > 64 {
                    break;
                }
                let result = service.handle(&v);
                if let Some(a) = v.get_mut("secrets").and_then(Value::as_array_mut) {
                    for s in a {
                        if let Value::String(t) = s {
                            t.zeroize();
                        }
                        *s = Value::Null;
                    }
                }
                let response = match result {
                    Ok(r) => json!({"v":1,"id":rid,"ok":true,"result":r}),
                    Err(e) => {
                        json!({"v":1,"id":rid,"ok":false,"error":{"code":"request_rejected","message":e.to_string()}})
                    }
                };
                if frame_write(&mut stream, &response).is_err() {
                    break;
                }
            }
            count.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}
fn bridge() -> Result<()> {
    let mut stream =
        UnixStream::connect(socket_path()?).context("Start escrypter-agent.service first")?;
    peer_ok(&stream)?;
    let mut write = stream.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut write);
        let _ = write.shutdown(std::net::Shutdown::Write);
    });
    io::copy(&mut stream, &mut io::stdout().lock())?;
    Ok(())
}
pub fn main_entry() -> Result<()> {
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("--serve") => serve(),
        Some("--bridge") => bridge(),
        Some("--init") if a.len() == 4 => {
            let p = config_path();
            ensure!(!p.exists(), "Configuration already exists");
            private_dir(p.parent().unwrap())?;
            let cfg = Config {
                root: fs::canonicalize(&a[2])?,
                key_root: fs::canonicalize(&a[3])?,
                max_jobs: 2,
                memory_bytes: 1024 * 1024 * 1024,
                max_file_bytes: 1024 * 1024 * 1024 * 1024,
                max_upload_bytes: 2 * 1024 * 1024 * 1024 * 1024,
                history_limit: 200,
            };
            save(&p, &cfg)
        }
        _ => {
            println!("ESCrypter Agent 0.2.0\n--init DATA_ROOT KEY_ROOT\n--serve\n--bridge");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Arc<Service>) {
        crate::crypto::init().unwrap();
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("data");
        let keys = d.path().join("keys");
        let state = d.path().join("state");
        for p in [&root, &keys, &state] {
            private_dir(p).unwrap();
        }
        let (public, secret) = crate::crypto::keypair();
        let s = Arc::new(Service {
            cfg: Config {
                root,
                key_root: keys,
                max_jobs: 2,
                memory_bytes: 1024 * 1024 * 1024,
                max_file_bytes: 1024 * 1024,
                max_upload_bytes: 2 * 1024 * 1024,
                history_limit: 200,
            },
            dir: state,
            jobs: Mutex::new(BTreeMap::new()),
            children: Mutex::new(BTreeMap::new()),
            uploads: Mutex::new(BTreeMap::new()),
            receipt: secret,
            receipt_pub: public,
        });
        (d, s)
    }
    fn request(method: &str) -> Value {
        json!({"v":1,"id":"test-request-123456","method":method})
    }
    fn upload(s: &Service, data: &[u8]) -> (Value, PathBuf) {
        let v = json!({"upload_id":"test-upload-123456","path":"output","size":data.len(),"sha256":hex::encode(Sha256::digest(data))});
        let r = s.upload_prepare(&v).unwrap();
        (v, PathBuf::from(r["temporary_path"].as_str().unwrap()))
    }
    #[test]
    fn frames_roundtrip_and_limits() {
        let value = request("hello");
        let mut b = Vec::new();
        frame_write(&mut b, &value).unwrap();
        assert_eq!(frame_read(&mut &b[..]).unwrap(), Some(value));
        for bad in [
            vec![0, 0, 0, 0],
            vec![0, 4, 0, 1],
            vec![0, 0],
            vec![0, 0, 0, 1, b'{'],
        ] {
            assert!(frame_read(&mut &bad[..]).is_err());
        }
        assert!(frame_read(&mut &b""[..]).unwrap().is_none());
    }
    #[test]
    fn deterministic_frame_mutations_do_not_panic() {
        for n in 0..4096u32 {
            let b = n.wrapping_mul(2654435761).to_be_bytes();
            assert!(frame_read(&mut &b[..]).is_err());
        }
    }
    #[test]
    fn confinement_and_methods() {
        let (_d, s) = fixture();
        for p in ["../keys", "/etc/passwd", "data/../../keys", ""] {
            assert!(confined(&s.cfg.root, p, true).is_err());
        }
        std::os::unix::fs::symlink(&s.cfg.key_root, s.cfg.root.join("link")).unwrap();
        assert!(confined(&s.cfg.root, "link", false).is_err());
        assert!(s.handle(&request("shell")).is_err());
        let mut v = request("hello");
        v["v"] = json!(2);
        assert!(s.handle(&v).is_err());
    }
    #[test]
    fn resume_and_receipt_signature() {
        let (_d, s) = fixture();
        let data = b"Merhaba test payload";
        let (v, p) = upload(&s, data);
        fs::write(&p, &data[..7]).unwrap();
        let r = s.upload_prepare(&v).unwrap();
        assert_eq!(r["offset"], 7);
        assert_eq!(r["prefix_sha256"], hex::encode(Sha256::digest(&data[..7])));
        assert!(s.upload_finish(&v).is_err());
        fs::write(&p, data).unwrap();
        let r = s.upload_finish(&v).unwrap();
        let receipt = &r["receipt"];
        let payload = hex::decode(receipt["payload_hex"].as_str().unwrap()).unwrap();
        let mut msg = b"ESCrypter receipt v1\0".to_vec();
        msg.extend_from_slice(&payload);
        let sig = hex::decode(receipt["signature"].as_str().unwrap()).unwrap();
        assert!(crate::crypto::verify(&msg, &sig, &s.receipt_pub).is_ok());
        msg.push(0);
        assert!(crate::crypto::verify(&msg, &sig, &s.receipt_pub).is_err());
        assert_eq!(s.upload_finish(&v).unwrap(), r);
        assert_eq!(s.upload_prepare(&v).unwrap()["finished"], true);
    }
    #[test]
    fn upload_collision_quota_and_identity() {
        let (_d, s) = fixture();
        let (mut v, p) = upload(&s, b"new");
        fs::write(&p, b"new").unwrap();
        fs::write(s.cfg.root.join("output"), b"original").unwrap();
        assert!(s.upload_finish(&v).is_err());
        assert_eq!(fs::read(s.cfg.root.join("output")).unwrap(), b"original");
        v["sha256"] = json!("00".repeat(32));
        assert!(s.upload_prepare(&v).is_err());
        v["size"] = json!(u64::MAX);
        assert!(s.upload_prepare(&v).is_err());
    }
    #[test]
    fn finalize_restart_recovery() {
        let (_d, s) = fixture();
        let (v, p) = upload(&s, b"test");
        fs::write(&p, b"test").unwrap();
        let r = s.upload_finish(&v).unwrap();
        s.uploads
            .lock()
            .unwrap()
            .get_mut("test-upload-123456")
            .unwrap()
            .finished = false;
        assert_eq!(s.upload_prepare(&v).unwrap()["receipt"], r["receipt"]);
    }
    #[test]
    fn finalize_changed_destination_rejected() {
        let (_d, s) = fixture();
        let (v, p) = upload(&s, b"test");
        fs::write(&p, b"test").unwrap();
        s.upload_finish(&v).unwrap();
        s.uploads
            .lock()
            .unwrap()
            .get_mut("test-upload-123456")
            .unwrap()
            .finished = false;
        fs::write(s.cfg.root.join("output"), b"evil").unwrap();
        assert!(s.upload_finish(&v).is_err());
    }
    #[test]
    fn empty_upload_and_private_permissions() {
        let (_d, s) = fixture();
        let (v, p) = upload(&s, b"");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        s.upload_finish(&v).unwrap();
        assert_eq!(fs::metadata(s.cfg.root.join("output")).unwrap().len(), 0);
    }
    #[test]
    fn job_replay_is_bound_to_request() {
        let (_d, s) = fixture();
        let spec = json!({"operation":"verify","input":"missing"});
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&spec).unwrap()));
        s.jobs.lock().unwrap().insert(
            "test-job-12345678".into(),
            Job {
                id: "test-job-12345678".into(),
                request_hash: digest,
                operation: "verify".into(),
                status: "completed".into(),
                created: 0,
                seq: 0,
                events: VecDeque::new(),
                output: None,
            },
        );
        let mut v = json!({"job_id":"test-job-12345678","spec":spec});
        assert_eq!(s.submit(&v).unwrap()["replayed"], true);
        v["spec"]["input"] = json!("changed");
        assert!(s.submit(&v).is_err());
    }
    #[test]
    fn event_ring_gap_and_pagination() {
        let (_d, s) = fixture();
        s.jobs.lock().unwrap().insert(
            "test-job-12345678".into(),
            Job {
                id: "test-job-12345678".into(),
                request_hash: String::new(),
                operation: "verify".into(),
                status: "completed".into(),
                created: 0,
                seq: 0,
                events: VecDeque::new(),
                output: None,
            },
        );
        for _ in 0..520 {
            s.record("test-job-12345678", json!({"event":"progress"}))
                .unwrap();
        }
        let mut v = request("events");
        v["job_id"] = json!("test-job-12345678");
        v["after"] = json!(0);
        let r = s.handle(&v).unwrap();
        assert_eq!(r["events"].as_array().unwrap().len(), 64);
        assert_eq!(r["gap"], true);
        assert_eq!(r["latest"], 520);
    }
}
