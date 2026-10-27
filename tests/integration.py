#!/usr/bin/env python3
import json, os, sys, pathlib, subprocess, tempfile, tarfile, io, hashlib, unittest
BIN=str(pathlib.Path(sys.argv.pop(1) if len(sys.argv)>1 else 'target/release/escrypter').resolve())
PW='correct horse battery staple'; SP='signing password for tests'
def call(*args, secrets=(), ok=True):
 p=subprocess.run([BIN,*map(str,args)],input=('\n'.join(secrets)+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if (p.returncode==0)!=ok: raise AssertionError((args,p.returncode,p.stdout.decode(),p.stderr.decode()))
 return p
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.d=pathlib.Path(cls.tmp.name);cls.key=cls.d/'key';cls.src=cls.d/'source';cls.src.mkdir();(cls.src/'Türkçe.txt').write_text('Merhaba! Bu test mesajıdır');(cls.src/'empty').mkdir();(cls.src/'zero').touch();cls.pkg=cls.d/'test.esc';cls.rec=cls.d/'recovery';call('keygen',cls.key,secrets=[SP]);call('encrypt',cls.pkg,cls.key,'fast',cls.rec,cls.src,secrets=[PW,SP])
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_01_layout(self):
  self.assertGreaterEqual(self.pkg.stat().st_size,4_000_000)
  with tarfile.open(self.pkg,'r:') as t:
   names=t.getnames();pieces=[n for n in names if n.startswith('escs/')];self.assertEqual(len(pieces),100);self.assertEqual(len({pathlib.Path(n).name for n in pieces}),100)
   for i in range(10,101,10):self.assertEqual(sum(n.startswith(f'escs/esc{i}/') for n in pieces),10)
   manifest=t.extractfile('files/manifest.xml').read();self.assertNotIn(PW.encode(),manifest);self.assertNotIn(b'Merhaba',manifest)
 def test_02_roundtrip(self):
  out=self.d/'roundtrip';call('decrypt',self.pkg,out,secrets=[PW]);self.assertEqual((out/'source/Türkçe.txt').read_bytes(),(self.src/'Türkçe.txt').read_bytes());self.assertTrue((out/'source/empty').is_dir());self.assertEqual((out/'source/zero').stat().st_size,0)
 def test_03_wrong_password(self):
  out=self.d/'wrong';call('decrypt',self.pkg,out,secrets=['incorrect'],ok=False);self.assertFalse(out.exists())
 def test_04_recovery(self):
  out=self.d/'recovered';call('recover',self.pkg,out,secrets=[self.rec.read_text().strip()]);self.assertEqual((out/'source/Türkçe.txt').read_bytes(),(self.src/'Türkçe.txt').read_bytes())
 def mutate(self,name,mode):
  dst=self.d/name
  with tarfile.open(self.pkg) as src,tarfile.open(dst,'w') as out:
   changed=False
   for member in src:
    data=src.extractfile(member).read()
    if not changed and member.name.startswith('escs/'):
     changed=True
     if mode=='missing':continue
     if mode=='duplicate':out.addfile(member,io.BytesIO(data))
     if mode=='tamper':data=bytes([data[0]^1])+data[1:]
     if mode=='path':member.name='../escape'
    out.addfile(member,io.BytesIO(data))
  return dst
 def test_05_tamper_missing_duplicates_paths(self):
  for mode in ('tamper','missing','duplicate','path'):
   with self.subTest(mode=mode):call('verify',self.mutate(mode+'.esc',mode),ok=False)
 def test_06_trust(self):
  call('verify',self.pkg,'00'*32,ok=False)
  with tarfile.open(self.pkg) as t:fp=hashlib.sha256(t.extractfile('files/signer.pub').read()).hexdigest()
  call('verify',self.pkg,fp)
 def test_07_rekey(self):
  p=self.d/'new.esc';new='new secret password words';call('rekey',self.pkg,p,self.key,secrets=[PW,new,SP]);call('decrypt',p,self.d/'oldpass',secrets=[PW],ok=False);call('decrypt',p,self.d/'newpass',secrets=[new]);call('verify',p)
 def test_08_overwrite(self):
  call('encrypt',self.pkg,self.key,'fast','-',self.src,secrets=[PW,SP],ok=False)
  call('decrypt',self.pkg,self.src,secrets=[PW],ok=False)
 def test_09_symlink(self):
  link=self.d/'link';link.symlink_to(self.src);call('encrypt',self.d/'link.esc',self.key,'fast','-',link,secrets=[PW,SP],ok=False)
 def test_10_multichunk(self):
  p=self.d/'random.bin';p.write_bytes(os.urandom(5_000_000));out=self.d/'large.esc';call('encrypt',out,self.key,'fast','-',p,secrets=[PW,SP]);call('decrypt',out,self.d/'large-output',secrets=[PW]);self.assertEqual(hashlib.sha256(p.read_bytes()).digest(),hashlib.sha256((self.d/'large-output/random.bin').read_bytes()).digest())
 def test_11_trailing_payload(self):
  p=self.d/'trailing.esc';p.write_bytes(self.pkg.read_bytes()+b'UNSIGNED CONTENT');call('verify',p,ok=False)
 def test_12_cancellation(self):
  import time
  source=self.d/'cancel-source';source.write_bytes(os.urandom(20_000_000));out=self.d/'cancelled.esc'
  before=set(self.d.iterdir())
  p=subprocess.Popen([BIN,'--events','encrypt',str(out),str(self.key),'high','-',str(source)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  p.stdin.write((PW+'\n'+SP+'\n').encode());p.stdin.flush()
  while True:
   line=p.stderr.readline()
   if not line:raise AssertionError('Process ended before cancellation')
   if json.loads(line).get('event')=='total':break
  p.terminate();p.wait(timeout=30);p.stdin.close();p.stdout.close();p.stderr.close();self.assertNotEqual(p.returncode,0);self.assertFalse(out.exists());self.assertEqual(before,set(self.d.iterdir()))
 def test_13_content_preview_events(self):
  p=call('--events','list-content',self.pkg,secrets=[PW]);events=[json.loads(l) for l in p.stderr.splitlines()]
  self.assertEqual(events[-1]['event'],'completed');content=next(e['data'] for e in events if e['event']=='content')
  self.assertIn('Türkçe.txt',json.dumps(content,ensure_ascii=False));self.assertNotIn(PW,p.stderr.decode());self.assertEqual([e['seq'] for e in events],list(range(1,len(events)+1)))
 def test_14_signing_key_password_and_export(self):
  changed=self.d/'changed-key';pub=self.d/'public';new='replacement signing password'
  call('key-password',self.key,changed,secrets=[SP,new]);call('public-key',changed,pub,secrets=[new]);self.assertEqual(pub.stat().st_size,32)
  call('public-key',changed,self.d/'rejected-public',secrets=[SP],ok=False)
  with tarfile.open(self.pkg) as t:self.assertEqual(pub.read_bytes(),t.extractfile('files/signer.pub').read())
 def test_15_package_info_without_password(self):
  p=call('--events','info',self.pkg);events=[json.loads(l) for l in p.stderr.splitlines()];self.assertIn('package',[e['event'] for e in events]);self.assertNotIn(b'Merhaba',p.stderr)
 def test_16_oversized_password_and_metadata(self):
  call('keygen',self.d/'oversized-key',secrets=['a'*4097],ok=False)
  malformed=self.d/'malformed-key';malformed.write_bytes(b'x'*(1024*1024+1));call('public-key',malformed,self.d/'bad-public',secrets=[SP],ok=False)
 def test_17_output_permissions(self):
  self.assertEqual(self.key.stat().st_mode&0o777,0o600);self.assertEqual(self.pkg.stat().st_mode&0o777,0o600);self.assertEqual(self.rec.stat().st_mode&0o777,0o600)
 def test_18_invalid_cli_rejected(self):
  call('unknown-command',ok=False);call('verify',ok=False);call('--help')
if __name__=='__main__':unittest.main(verbosity=2)
