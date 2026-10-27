#!/usr/bin/env python3
"""Real agent/worker tests over its private socket, no external server needed."""
import ctypes, hashlib, json, os, pathlib, socket, struct, subprocess, sys, tempfile, time, unittest, uuid
BIN = pathlib.Path(sys.argv.pop(1) if len(sys.argv)>1 else 'target/debug').resolve()
PW='archive password for test'; SP='signing password for test'
def ident(): return str(uuid.uuid4())
class ECP(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='ecp-'); self.d=pathlib.Path(self.tmp.name)
  for name in ('data','keys','runtime'): (self.d/name).mkdir(mode=0o700)
  self.env=dict(os.environ,HOME=str(self.d),XDG_CONFIG_HOME=str(self.d/'config'),XDG_STATE_HOME=str(self.d/'state'),XDG_RUNTIME_DIR=str(self.d/'runtime'))
  subprocess.run([str(BIN/'escrypter-agent'),'--init',str(self.d/'data'),str(self.d/'keys')],env=self.env,check=True,capture_output=True)
  self.start()
 def start(self):
  self.proc=subprocess.Popen([str(BIN/'escrypter-agent'),'--serve'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.sock=self.d/'runtime/escrypter/agent.sock'
  for _ in range(200):
   if self.proc.poll() is not None: break
   try: self.rpc('hello');return
   except (OSError,EOFError): time.sleep(.01)
  raise AssertionError('agent did not start: '+repr(self.proc.communicate(timeout=2)))
 def stop(self):
  self.proc.terminate();self.proc.communicate(timeout=10)
 def tearDown(self): self.stop();self.tmp.cleanup()
 def rpc(self,method,ok=True,**fields):
  with socket.socket(socket.AF_UNIX) as s:
   s.settimeout(10);s.connect(str(self.sock)); b=json.dumps(dict(v=1,id=ident(),method=method,**fields)).encode();s.sendall(struct.pack('>I',len(b))+b)
   def read(n):
    b=b''
    while len(b)<n:
     c=s.recv(n-len(b))
     if not c:raise EOFError()
     b+=c
    return b
   r=json.loads(read(struct.unpack('>I',read(4))[0]));self.assertEqual(r['ok'],ok,r);return r.get('result',r.get('error'))
 def test_01_protocol_paths(self):
  self.assertEqual(self.rpc('hello')['version'],1)
  for path in ('../keys','/etc/passwd','data/../../keys'):
   self.rpc('list',ok=False,path=path)
  (self.d/'data/link').symlink_to(self.d/'keys');self.rpc('list',ok=False,path='link')
  self.rpc('execute',ok=False,command='touch bad')
 def test_02_invalid_frames(self):
  for b in (struct.pack('>I',0),struct.pack('>I',262145),struct.pack('>I',1)+b'{',b'\0\0'):
   with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(2);s.connect(str(self.sock));s.sendall(b);s.shutdown(socket.SHUT_WR)
    try:self.assertEqual(s.recv(10),b'')
    except ConnectionResetError:pass
  self.rpc('hello')
 def prepare(self,data=b'hello',name='upload.bin'):
  uid=ident();sha=hashlib.sha256(data).hexdigest();args=dict(upload_id=uid,path=name,size=len(data),sha256=sha)
  p=self.rpc('upload_prepare',**args);return uid,sha,args,pathlib.Path(p['temporary_path'])
 def test_03_upload_resume_receipt(self):
  data=os.urandom(524288);uid,sha,args,p=self.prepare(data)
  p.write_bytes(data[:123]);r=self.rpc('upload_prepare',**args);self.assertEqual(r['offset'],123);self.assertEqual(r['prefix_sha256'],hashlib.sha256(data[:123]).hexdigest())
  self.rpc('upload_finish',ok=False,upload_id=uid);p.write_bytes(data)
  receipt=self.rpc('upload_finish',upload_id=uid)['receipt'];payload=bytes.fromhex(receipt['payload_hex']);m=b'ESCrypter receipt v1\0'+payload
  sodium=ctypes.CDLL('libsodium.so.23');sodium.sodium_init();sodium.crypto_sign_verify_detached.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulonglong,ctypes.c_char_p]
  self.assertEqual(sodium.crypto_sign_verify_detached(bytes.fromhex(receipt['signature']),m,len(m),bytes.fromhex(receipt['public_key'])),0)
  self.assertEqual(json.loads(payload)['sha256'],sha);self.assertEqual(self.rpc('upload_finish',upload_id=uid)['receipt'],receipt)
  self.assertTrue(self.rpc('upload_prepare',**args)['finished']);self.assertEqual((self.d/'data/upload.bin').read_bytes(),data)
 def test_04_upload_no_overwrite_and_binding(self):
  uid,sha,args,p=self.prepare();p.write_bytes(b'hello');(self.d/'data/upload.bin').write_bytes(b'original')
  self.rpc('upload_finish',ok=False,upload_id=uid);self.assertEqual((self.d/'data/upload.bin').read_bytes(),b'original')
  self.rpc('upload_prepare',ok=False,**dict(args,sha256='00'*32));self.rpc('upload_prepare',ok=False,**dict(args,upload_id=ident(),size=2**50))
 def test_05_duplicate_agent_preserves_state(self):
  before=(self.d/'state/escrypter/jobs.json').read_bytes()
  p=subprocess.run([str(BIN/'escrypter-agent'),'--serve'],env=self.env,capture_output=True,timeout=10)
  self.assertNotEqual(p.returncode,0);self.assertEqual((self.d/'state/escrypter/jobs.json').read_bytes(),before);self.rpc('hello')
 def test_06_remote_job_disconnect_replay_and_secrets(self):
  subprocess.run([str(BIN/'escrypter'),'keygen',str(self.d/'keys/key')],input=(SP+'\n').encode(),check=True,capture_output=True)
  (self.d/'data/source').write_text('Merhaba dünya')
  jid=ident();spec=dict(operation='encrypt',inputs=['source'],output='output.esc',key='key',profile='fast')
  self.rpc('submit',job_id=jid,spec=spec,secrets=[PW,SP]);self.assertTrue(self.rpc('submit',job_id=jid,spec=spec,secrets=[PW,SP])['replayed'])
  self.rpc('submit',ok=False,job_id=jid,spec=dict(spec,output='other.esc'),secrets=[PW,SP])
  for _ in range(300):
   jobs=self.rpc('jobs')['jobs']
   if jobs[0]['status'] not in ('running','starting'):break
   time.sleep(.02)
  self.assertEqual(jobs[0]['status'],'completed');self.assertGreater(self.rpc('events',job_id=jid,after=0)['latest'],0)
  state=(self.d/'state/escrypter/jobs.json').read_text();self.assertNotIn(PW,state);self.assertNotIn(SP,state)
  subprocess.run([str(BIN/'escrypter'),'decrypt',str(self.d/'data/output.esc'),str(self.d/'out')],input=(PW+'\n').encode(),check=True,capture_output=True)
  self.assertEqual((self.d/'out/source').read_text(),'Merhaba dünya');self.rpc('forget',job_id=jid);self.assertEqual(self.rpc('jobs')['jobs'],[])
 def test_07_finalize_crash_recovery(self):
  uid,sha,args,p=self.prepare();p.write_bytes(b'hello');receipt=self.rpc('upload_finish',upload_id=uid)['receipt'];self.stop()
  state=self.d/'state/escrypter/uploads.json';records=json.loads(state.read_text());records[uid]['finished']=False;state.write_text(json.dumps(records));self.start()
  self.assertEqual(self.rpc('upload_prepare',**args)['receipt'],receipt)
 def test_08_restart_marks_interrupted(self):
  self.stop();p=self.d/'state/escrypter/jobs.json';jid=ident();p.write_text(json.dumps({jid:dict(id=jid,request_hash='00',operation='verify',status='running',created=0,seq=0,events=[],output=None)}));self.start();self.assertEqual(self.rpc('jobs')['jobs'][0]['status'],'interrupted')
 def test_09_permissions(self):
  for p,mode in [(self.sock,0o600),(self.d/'state/escrypter/receipt.key',0o600),(self.d/'state/escrypter',0o700)]:self.assertEqual(p.stat().st_mode&0o777,mode)
 def test_10_empty_upload(self):
  uid,sha,args,p=self.prepare(b'');self.rpc('upload_finish',upload_id=uid);self.assertEqual((self.d/'data/upload.bin').stat().st_size,0)
if __name__=='__main__':
 with tempfile.TemporaryDirectory() as d:
  try:
   with socket.socket(socket.AF_UNIX) as probe:probe.bind(d+'/probe')
  except PermissionError:
   print('UNAVAILABLE: execution environment prohibits Unix socket binding; no ECP socket tests were run.',file=sys.stderr);sys.exit(77)
 unittest.main(verbosity=2)
