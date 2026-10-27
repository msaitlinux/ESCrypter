#!/usr/bin/env python3
"""Generate offline license inventory; does not download or execute dependencies.
Normal mode uses Cargo's resolved metadata after build. --draft reads the previous
lockfile and locally installed sources; draft versions are explicitly unverified.
"""
import argparse,json,pathlib,subprocess,tomllib,datetime
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(*args):
 p=subprocess.run(args,capture_output=True,text=True)
 return p.stdout.strip() if p.returncode==0 else ''
def text(path):
 try:return pathlib.Path(path).read_text(errors='replace')
 except OSError:return ''
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--draft',action='store_true');args=parser.parse_args()
 items=[dict(name='ESCrypter',version='0.2.0',license='GPL-3.0-only',category='Application source',url='https://www.gnu.org/licenses/gpl-3.0.html',text=text(ROOT/'LICENSE')),
 dict(name='ESCrypter 0.1.0 inherited source',version='0.1.0',license='MIT',category='Original attribution retained; earlier grants remain valid',url='',text=text(ROOT/'licenses/0.1.0-MIT.txt'))]
 if args.draft:
  old=tomllib.loads(text(ROOT/'docs/previous-release/0.1.0-Cargo.lock'))
  names={p['name'] for p in old['package'] if p['name']!='escrypter'}|{'serde','serde_derive','serde_json'}
  packages=[]
  for name in sorted(names):
   candidates=list(pathlib.Path('/usr/share/cargo/registry').glob(name+'-*/Cargo.toml'))
   candidates=[p for p in candidates if tomllib.loads(text(p)).get('package',{}).get('name')==name]
   if candidates:
    p=sorted(candidates)[-1];data=tomllib.loads(text(p))['package'];packages.append(dict(data,manifest_path=str(p)))
 else:
  raw=run('cargo','metadata','--offline','--format-version','1','--manifest-path',str(ROOT/'Cargo.toml'))
  if not raw:raise SystemExit('Resolved Cargo metadata unavailable; run cargo build first')
  packages=json.loads(raw)['packages']
 for p in packages:
  if p['name']=='escrypter':continue
  root=pathlib.Path(p['manifest_path']).parent
  parts=[]
  for f in sorted(root.iterdir()):
   if f.is_file() and f.name.upper().startswith(('LICENSE','COPYING','NOTICE','COPYRIGHT')):parts.append(f.name+'\n'+text(f))
  if not parts:
   for f in root.glob('**/LICENSE*'):
    if f.is_file():parts.append(str(f.relative_to(root))+'\n'+text(f))
  # Debian source packages may point to a common license through copyright.
  notice=text('/usr/share/doc/librust-'+p['name'].replace('_','-')+'-dev/copyright')
  if notice:parts.append(notice)
  if not parts and not args.draft:raise SystemExit('Missing license text for '+p['name'])
  items.append(dict(name=p['name'],version=p['version'],license=p.get('license','See notice'),category='Rust source (linked or build dependency)',url=p.get('repository') or p.get('homepage') or '',text='\n\n'.join(parts) or 'License text unavailable in draft; build must resolve this.'))
 native=[('qt6-base-dev','Qt 6','Runtime / dynamically linked','https://www.qt.io/'),('qt6-svg-dev','Qt SVG','Runtime / dynamically linked','https://www.qt.io/'),('libsodium-dev','libsodium','Runtime / dynamically linked','https://libsodium.org/'),('liblzma-dev','liblzma / XZ','Runtime / dynamically linked','https://tukaani.org/xz/'),('libcurl4-openssl-dev','libcurl','Runtime / dynamically linked','https://curl.se/'),('openssh-client','OpenSSH','External SSH transport','https://www.openssh.com/'),('wget','GNU Wget','External optional HTTPS downloader','https://www.gnu.org/software/wget/'),('systemd','systemd','External optional user service manager','https://systemd.io/'),('cargo','Cargo','Build tool','https://www.rust-lang.org/'),('rustc','Rust compiler','Build tool','https://www.rust-lang.org/'),('cmake','CMake','Build tool','https://cmake.org/'),('g++','GNU C++ compiler','Build tool','https://gcc.gnu.org/')]
 for package,name,category,url in native:
  version=run('dpkg-query','-W','-f=${Version}',package)
  copyright=text('/usr/share/doc/'+package+'/copyright')
  # GNU compiler meta packages may keep their copyright with the versioned package.
  if not copyright and package=='g++':copyright=text('/usr/share/doc/g++-'+run('g++','-dumpversion').split('.')[0]+'/copyright')
  if not copyright and package=='libcurl4-openssl-dev':copyright=text('/usr/share/doc/libcurl4/copyright') or text('/usr/share/doc/libcurl4t64/copyright')
  if not copyright and not args.draft:raise SystemExit('Install '+package+' to collect its license notice')
  items.append(dict(name=name,version=version or 'not installed in draft environment',license='See full component notice',category=category,url=url,text=copyright or 'Pending build-environment inventory.'))
 # Include full referenced common texts, not only /usr/share/common-licenses paths.
 for p in sorted(pathlib.Path('/usr/share/common-licenses').iterdir()):
  if p.is_file():items.append(dict(name='Full license text: '+p.name,version='',license=p.name,category='Referenced license text',url='',text=text(p)))
 result=dict(schema=1,draft=args.draft,generated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),components=items)
 (ROOT/'licenses').mkdir(exist_ok=True)
 (ROOT/'licenses/catalog.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 if not args.draft:(ROOT/'THIRD_PARTY_NOTICES.txt').write_text('\n\n'.join(i['name']+' '+i['version']+'\n'+i['text'] for i in items))
if __name__=='__main__':main()
