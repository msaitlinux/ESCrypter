#!/usr/bin/env python3
"""Small reproducible bounded-memory samples; not a capacity benchmark."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile,time
binary=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'target/release/escrypter').resolve()
results=[]
def run(args,secrets):
 start=time.perf_counter();peak=0
 p=subprocess.Popen([str(binary),'--events',*map(str,args)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ,ESCRYPTER_MEMORY_MIB='1024'))
 p.stdin.write(('\n'.join(secrets)+'\n').encode());p.stdin.close();p.stdin=None
 while p.poll() is None:
  time.sleep(.01)
 out,err=p.communicate();assert p.returncode==0,err.decode()
 return dict(seconds=round(time.perf_counter()-start,3))
with tempfile.TemporaryDirectory() as td:
 d=pathlib.Path(td);pw='test password words';sp='signing password words';key=d/'key';run(['keygen',key],[sp])
 for label,size,random in [('repetitive-32MiB',32*1024*1024,False),('random-8MiB',8*1024*1024,True)]:
  src=d/label;src.write_bytes(os.urandom(size) if random else (b'Merhaba ESCrypter!\n'*(size//18+1))[:size])
  for level in ['fast','balanced','high']:
   pkg=d/f'{label}-{level}.esc';out=d/f'{label}-{level}-out'
   enc=run(['encrypt',pkg,key,level,'-',src],[pw,sp]);dec=run(['decrypt',pkg,out],[pw]);assert hashlib.sha256(src.read_bytes()).digest()==hashlib.sha256((out/src.name).read_bytes()).digest()
   results.append(dict(input=label,input_bytes=src.stat().st_size,profile=level,archive_bytes=pkg.stat().st_size,encrypt=enc,decrypt=dec))
print(json.dumps(dict(note='Single-run local samples; 1 GiB worker virtual memory limit. RSS omitted because process namespace visibility is unreliable in the execution environment.',results=results),indent=2))
