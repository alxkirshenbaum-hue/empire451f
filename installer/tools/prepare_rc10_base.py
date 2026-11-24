"""Restore the exact rc10 build input from a local immutable Git tag; no network."""
import hashlib
from pathlib import Path
import subprocess

EXPECTED = "f0dbed6ce57d21744a3dd8d026a931cf470bcb4132fafa641b15d336eee6211c"
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "dist/s1-local/rc10-before/dist/installer.zip"

def main():
    result = subprocess.run(["git", "-C", str(ROOT), "show", "v0.4.0-rc10:dist/installer.zip"], check=True, capture_output=True)
    if hashlib.sha256(result.stdout).hexdigest() != EXPECTED:
        raise ValueError("rc10 tag bundle SHA256 mismatch; input not written")
    if TARGET.exists():
        if hashlib.sha256(TARGET.read_bytes()).hexdigest() != EXPECTED:
            raise ValueError("Existing build input differs; refusing overwrite")
    else:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(result.stdout)
    print("Exact rc10 build input ready; SHA256 verified")

if __name__ == "__main__":
    main()
