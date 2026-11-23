"""Build an unpublished S1 candidate in isolation, retaining the exact rc10 panel."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import zipfile
import build_release

ROOT = Path(__file__).resolve().parent
CANDIDATE_URL = 'https://example.invalid/empire-vpn-s1-local/installer.zip'
RC10_SHA = 'f0dbed6ce57d21744a3dd8d026a931cf470bcb4132fafa641b15d336eee6211c'
CORE = '0af8a3b39489e0f71222264c4f0c800872870838'


def main():
    output = ROOT / 'dist/s1-local'
    if output.exists():
        raise ValueError('Candidate directory already exists; preserve it or select a new explicit build location')
    original = ROOT / 'dist/installer.zip'
    data = original.read_bytes()
    if hashlib.sha256(data).hexdigest() != RC10_SHA:
        raise ValueError('Expected exact accepted rc10 bundle')
    with zipfile.ZipFile(original) as z:
        payload_bytes = z.read('panel/payload.json')
    payload = json.loads(payload_bytes)
    if payload['source_sha'] != CORE:
        raise ValueError('Expected rc10 panel core')
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary).resolve()/'source'; source.mkdir()
        stage = Path(temporary).resolve()/'panel'; stage.mkdir()
        by_path = {entry['path']: entry for entry in payload['files']}
        if set(by_path) != {build_release.panel_destination(n) for n in build_release.PANEL_PATHS}:
            raise ValueError('Panel allowlist mismatch')
        for name in build_release.PANEL_PATHS:
            entry = by_path[build_release.panel_destination(name)]
            content = base64.b64decode(entry['data'], validate=True)
            if hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise ValueError('Panel content hash mismatch')
            target = stage/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(content)
        if build_release.panel_payload(stage, CORE) != payload_bytes:
            raise ValueError('Payload differs from verified core reconstruction')
        for name in ['client.py','controller.py','remote.py','render.py','verify.py','versions.json','README.md','GUIDE.md','CLIENT_EXPORT_V1.md','TEST_RESULTS.md','MIGRATION_TEST.md','delivery.py','server_boot.py.in']:
            shutil.copy2(ROOT/name, source/name)
        for name in ['templates','bootstrap','examples/site-handoff']:
            shutil.copytree(ROOT/name, source/name)
        version = json.loads((source/'versions.json').read_text())
        version['installer_release'] = '0.4.0-rc10-s1-local'
        (source/'versions.json').write_text(json.dumps(version, indent=2)+'\n')
        previous_root = build_release.ROOT
        try:
            build_release.ROOT = source
            build_release.build(stage, CORE, CANDIDATE_URL)
        finally:
            build_release.ROOT = previous_root
        with zipfile.ZipFile(source/'dist/installer.zip') as z:
            if z.read('panel/payload.json') != payload_bytes:
                raise ValueError('Candidate panel changed')
        output.mkdir()
        backup = output/'rc10-before'; backup.mkdir()
        for name in ['dist/installer.zip','dist/installer.sha256','bootstrap/windows.ps1','bootstrap/macos.sh']:
            target = backup/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        for name in ['installer.zip','installer.sha256','site-handoff-example.zip']:
            shutil.copy2(source/'dist'/name,output/name)
        for name in ['windows.ps1','macos.sh']:
            shutil.copy2(source/'bootstrap'/name,output/name)
        manifest = dict(format='empire-s1-local-v1', publication='unpublished-local-only', release_url=CANDIDATE_URL,
            base_bundle_sha256=RC10_SHA, panel_source_sha=CORE, panel_payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
            files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()})
        (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print(json.dumps(manifest,indent=2))

if __name__ == '__main__':
    main()
