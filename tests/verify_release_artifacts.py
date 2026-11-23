import base64,hashlib,json,re,zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
data=(root/'dist/installer.zip').read_bytes();digest=hashlib.sha256(data).hexdigest()
assert (root/'dist/installer.sha256').read_text().split()[0]==digest
with zipfile.ZipFile(root/'dist/s1-local/installer.zip') as old, zipfile.ZipFile(root/'dist/installer.zip') as new:
    assert old.read('panel/payload.json')==new.read('panel/payload.json')
    assert json.loads(new.read('versions.json'))['installer_release']=='0.4.0-rc11'
    for name in new.namelist():
        if name=='panel/payload.json':continue
        assert new.read(name)==(root/name).read_bytes().replace(b'\r\n',b'\n'),name
for name in ['windows.ps1','macos.sh']:
    text=(root/'bootstrap'/name).read_text()
    encoded=max(re.findall(r'[A-Za-z0-9+/=]{100,}',text),key=len)
    loader=base64.b64decode(encoded).decode()
    assert digest in loader
    assert 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.4.0-rc11/dist/installer.zip' in loader
    assert 'example.invalid' not in loader
    compile(loader,name,'exec')
print('RC11 ZIP/source, SHA, exact panel, both decoded loaders URL/SHA/syntax PASS')
