# Software-only Secure Boot Demo

This is a small Python project that models the checks a secure bootloader performs before accepting a firmware image. It does **not** execute the image or modify the computer's real boot process.

## What it demonstrates

- Ed25519 signatures prove that the image metadata came from the holder of the signing private key.
- A SHA-256 digest and image size bind the metadata to the exact image bytes.
- A target identifier prevents accepting an image intended for a different simulated device.
- A local version record demonstrates rollback rejection.
- Verification fails closed: any mismatch rejects the image.

## Setup

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Demo

Create a sample image and a development key pair:

```powershell
Set-Content -NoNewline -Path sample-firmware.bin -Value 'Example firmware image, version 1'
python secureboot.py keygen
```

Sign version 1 for a named simulated device:

```powershell
python secureboot.py sign --image sample-firmware.bin --version 1 --target demo-x86_64
```

Verify and accept it:

```powershell
python secureboot.py boot --image sample-firmware.bin --target demo-x86_64
```

Try changing the image, changing the target, editing the manifest, or signing version 0 and attempting to boot it after version 1. Each case should be rejected. The boot command reports acceptance but never runs the image.

## Files

- `secureboot.py`: key generation, signing, manifest validation, verification, and simulated boot policy.
- `keys/dev-private.pem`: development signing key; keep it secret in a real signing setup.
- `keys/trusted-public.pem`: public key pinned by the simulated bootloader.
- `release/manifest.json` and `release/manifest.sig`: signed image metadata and detached signature.
- `boot-state.json`: simulated highest accepted version.

Generated keys, releases, local state, and virtual environments are excluded by `.gitignore`.

## Security limits to discuss in a report

This is an educational simulation, not production secure boot. Since the verifier, pinned public key, and rollback state are ordinary files/software, someone who can replace those files can bypass the checks. Real secure boot needs a trusted first stage and protected storage for trust anchors and anti-rollback state (often provided by platform firmware or hardware). The private key generated here is unencrypted and is only suitable for a local demonstration. Ed25519 is provided by the `cryptography` library; this project does not implement cryptography itself.
