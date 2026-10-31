# PNK Authenticator

A private, encrypted two-factor authentication (2FA) vault built with Python and Flet. Securely store your authenticator accounts, generate time-based one-time passwords (TOTP), scan QR codes, and transfer accounts between devices.

## Features

- **Encrypted storage** — Authenticator accounts are protected using Fernet symmetric encryption.
- **PIN protection** — Protect access to your authenticator vault.
- **Secure key derivation** — PBKDF2-HMAC-SHA256 with 600,000 iterations.
- **TOTP generation** — Generate six-digit authentication codes using HMAC-SHA1 with 30-second intervals.
- **QR code scanning** — Scan authenticator QR codes using your device's camera or clipboard image.
- **Account management** — Add, view, and delete authenticator accounts.
- **Duplicate detection** — Avoid accidentally importing duplicate accounts.
- **Encrypted transfers** — Export and import accounts using password-protected transfer files or Bluetooth sync.
- **Cross-platform support** — Android mobile support (`main.py`) and Windows desktop support (`2fa.py`).

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.13 | Application logic |
| Flet | User interface |
| Flutter | Android application packaging |
| Cryptography | Encryption and key derivation |
| Pillow | Image processing |
| NumPy | Image processing |
| OpenCV | QR code detection |
| Flet Camera | Camera integration (Android) |

## Security

PNK Authenticator uses multiple layers of protection to help keep authenticator secrets private.

- Fernet encryption protects stored vault data.
- PBKDF2-HMAC-SHA256 derives encryption keys.
- A randomly generated salt is used during key derivation.
- Account transfers use separate encryption keys derived from a transfer password.
- Transfer files use a randomly generated transfer PIN.

**Important:** Keep your vault PIN, transfer PINs, and backups private. Losing your vault credentials may make your encrypted data unrecoverable.

Never commit your actual vault files, encryption salts, passwords, or other private data to GitHub.

## Installation

### Requirements

- Windows 10 or newer
- Python 3.13
- Java Development Kit (JDK 21 recommended)
- Android Studio & Android SDK (for building Android APKs)
- Flutter (managed through the Flet build environment)

### 1. Clone the repository

```powershell
git clone https://github.com/YOUR_USERNAME/PNK-Authenticator.git
cd PNK-Authenticator
```

### 2. Create a virtual environment

```powershell
py -3.13 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
py -m pip install --upgrade pip
py -m pip install --upgrade flet flet-cli
py -m pip install flet-camera cryptography pillow numpy opencv-python-headless
```

---

## Building Executables & Packages

This repository contains two variants of the application:
1. **`main.py`** — The mobile/Android version featuring camera scanning and mobile UI layouts.
2. **`2fa.py`** — The Windows desktop version featuring clipboard QR scanning and Bluetooth peer-to-peer sync.

### Building the Android Version (`main.py`) into an APK

Make sure your Android SDK and JDK are installed and configured. Set your Java environment variables if necessary:

```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
```

Build the release APK specifying `main.py` as the module entry point:

```powershell
flet build apk --module-name main.py
```

The generated APK will be available in the `build/apk` output directory and can be installed on compatible Android devices.

### Building the Windows Version (`2fa.py`) into an EXE

To bundle the Windows desktop application into a standalone executable (`.exe`), you can use Flet's build command or `flet pack`:

Using `flet build`:
```powershell
flet build windows --module-name 2fa.py
```

Alternatively, using `flet pack` (PyInstaller-based packaging):
```powershell
flet pack --name "PNK Authenticator Windows" --icon assets/icon.ico 2fa.py
```

The generated executable will be placed in the `dist` directory.

---

## Project Structure

```text
PNK-Authenticator/
│
├── main.py        # Android / Mobile entry point
├── 2fa.py         # Windows / Desktop entry point
├── pyproject.toml
├── README.md
│
├── .venv/
├── build/
└── dist/
```

Additional files and directories may be generated during development and builds.

## Configuration

Application metadata and Android permissions are configured in `pyproject.toml`.

Current application configuration:

- **Application name:** PNK Authenticator
- **Package identifier:** `com.pnkwtf`
- **Version:** 1.0.0
- **Minimum Android SDK:** 24
- **Camera permission:** Enabled

## Contributing

Contributions, suggestions, and bug reports are welcome!

If you find a bug or have an idea for an improvement, feel free to open an issue or submit a pull request.

## License

# CC BY 4.0
Attribution 4.0 International
You are free to:
Share — copy and redistribute the material in any medium or format for any purpose, even commercially.
Adapt — remix, transform, and build upon the material for any purpose, even commercially.
The licensor cannot revoke these freedoms as long as you follow the license terms.
Under the following terms:
Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

---

**PNK Authenticator** — Your authentication codes, securely stored.
