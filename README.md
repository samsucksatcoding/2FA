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
- **Cross-platform support** — Separate implementations tailored for Android mobile (`Android/`) and Windows desktop (`Windows/`).

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
- Java Development Kit (JDK 21 recommended for Android builds)
- Android Studio & Android SDK (for building Android APKs)
- Flutter (managed through the Flet build environment)

### 1. Clone the repository

```powershell
git clone https://github.com/YOUR_USERNAME/PNK-Authenticator.git
cd "PNK Authenticator"
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

## Building Executables & Packages

The codebase is split into two directories tailored for each target platform:

### 1. Building the Android APK (`Android/Main.py`)

Make sure your Android SDK and JDK are installed and configured. Set your Java environment variables if necessary:

```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
```

Navigate into the `Android` directory and run the build command:

```powershell
cd Android
flet build apk --module-name Main.py
```

The generated `.apk` file will be generated under `Android/build/apk/`.

### 2. Building the Windows Executable (`Windows/2fa.py`)

To build the standalone Windows application (`.exe`), navigate into the `Windows` directory:

```powershell
cd Windows
```

Using Flet build:

```powershell
flet build windows --module-name 2fa.py
```

Or using `flet pack` (PyInstaller):

```powershell
flet pack --name "PNK Authenticator" 2fa.py
```

The compiled output will be generated inside the `Windows/dist` directory.

## Project Structure

```text
PNK Authenticator/
├── Android/
│   ├── Main.py
│   └── pyproject.toml
├── Windows/
│   └── 2fa.py
└── README.md
```

Additional files and directories (like `build/` and `dist/`) may be generated inside each platform folder during builds.

## Configuration

Application metadata and Android permissions are configured in `Android/pyproject.toml`.

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
