import asyncio
import base64
import hashlib
import hmac
import json
import os
import platform
import secrets
import socket
import struct
import threading
import time
import traceback
from urllib.parse import parse_qs, unquote, urlparse

import flet as ft
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageGrab

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None


DATA_FILE = "secure_2fa_vault.enc"
SALT_FILE = "vault.salt"
BLUETOOTH_PORT = 4
KDF_ITERATIONS = 600_000
SYNC_ITERATIONS = 300_000
MAX_SYNC_SIZE = 2_000_000


class VaultError(Exception):
    pass


class TwoFactorVault:
    def __init__(self):
        self.key = None
        self.data = {"accounts": []}
        self.lock = threading.RLock()

    @staticmethod
    def derive_key(pin, salt, iterations=KDF_ITERATIONS):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )

        return base64.urlsafe_b64encode(
            kdf.derive(pin.encode("utf-8"))
        )

    @staticmethod
    def validate_data(data):
        if not isinstance(data, dict):
            raise VaultError("Invalid vault format.")

        if not isinstance(data.get("accounts"), list):
            raise VaultError("Invalid account list.")

        for account in data["accounts"]:
            if not isinstance(account, dict):
                raise VaultError("Invalid account.")

            if not isinstance(account.get("name"), str):
                raise VaultError("Invalid account name.")

            if not isinstance(account.get("secret"), str):
                raise VaultError("Invalid account secret.")

        return data

    def setup_pin(self, pin):
        if len(pin) < 4:
            raise VaultError(
                "PIN must contain at least four characters."
            )

        if os.path.exists(SALT_FILE) or os.path.exists(DATA_FILE):
            raise VaultError("Vault files already exist.")

        salt = os.urandom(16)
        self.key = self.derive_key(pin, salt)
        self.data = {"accounts": []}

        self.write_file(SALT_FILE, salt)
        self.save_data()

    @staticmethod
    def write_file(path, content):
        temporary = path + ".tmp"

        try:
            with open(temporary, "wb") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary, path)

        finally:
            if os.path.exists(temporary):
                try:
                    os.remove(temporary)
                except OSError:
                    pass

    def verify_pin(self, pin):
        try:
            with open(SALT_FILE, "rb") as file:
                salt = file.read()

            if len(salt) != 16:
                return False

            candidate = self.derive_key(pin, salt)

            with open(DATA_FILE, "rb") as file:
                encrypted = file.read()

            decrypted = Fernet(candidate).decrypt(encrypted)

            data = self.validate_data(
                json.loads(decrypted.decode("utf-8"))
            )

            with self.lock:
                self.key = candidate
                self.data = data

            return True

        except Exception:
            self.key = None
            return False

    def save_data(self):
        with self.lock:
            if not self.key:
                raise VaultError("Vault is locked.")

            payload = json.dumps(
                self.data,
                ensure_ascii=False
            ).encode("utf-8")

            encrypted = Fernet(self.key).encrypt(payload)

            self.write_file(DATA_FILE, encrypted)

    @staticmethod
    def normalize_secret(secret):
        return "".join(
            secret.strip().split()
        ).upper().rstrip("=")

    def add_account(self, name, secret):
        name = name.strip()
        secret = self.normalize_secret(secret)

        if not name or not secret:
            raise VaultError("Both fields are required.")

        try:
            padded = secret + "=" * (
                (8 - len(secret) % 8) % 8
            )

            base64.b32decode(padded, casefold=True)

        except Exception:
            raise VaultError("Invalid Base32 secret.")

        with self.lock:
            for account in self.data["accounts"]:
                if account["secret"] == secret:
                    return False

            self.data["accounts"].append({
                "name": name,
                "secret": secret
            })

            self.save_data()

        return True

    def delete_account(self, secret):
        secret = self.normalize_secret(secret)

        with self.lock:
            original_accounts = list(self.data["accounts"])

            self.data["accounts"] = [
                account
                for account in self.data["accounts"]
                if account["secret"] != secret
            ]

            if len(self.data["accounts"]) == len(original_accounts):
                return False

            try:
                self.save_data()
            except Exception:
                self.data["accounts"] = original_accounts
                raise

        return True

    def merge_accounts(self, accounts):
        if not isinstance(accounts, list):
            raise VaultError("Invalid imported account list.")

        added = 0

        for account in accounts:
            if not isinstance(account, dict):
                continue

            try:
                if self.add_account(
                    account.get("name", ""),
                    account.get("secret", "")
                ):
                    added += 1

            except Exception:
                continue

        return added


def generate_totp(secret):
    secret = TwoFactorVault.normalize_secret(secret)

    padded = secret + "=" * (
        (8 - len(secret) % 8) % 8
    )

    key = base64.b32decode(padded, casefold=True)

    counter = int(time.time() // 30)

    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        hashlib.sha1
    ).digest()

    offset = digest[-1] & 0x0F

    binary = struct.unpack(
        ">I",
        digest[offset:offset + 4]
    )[0] & 0x7FFFFFFF

    return str(binary % 1_000_000).zfill(6)


def parse_otpauth(uri):
    parsed = urlparse(uri)

    if parsed.scheme.lower() != "otpauth":
        return None, None

    if parsed.netloc.lower() != "totp":
        raise VaultError(
            "Only TOTP authenticator codes are supported."
        )

    params = parse_qs(parsed.query)

    secret = params.get("secret", [None])[0]

    if not secret:
        raise VaultError("QR code does not contain a secret.")

    label = unquote(parsed.path.lstrip("/"))
    issuer = params.get("issuer", [""])[0]

    if ":" in label:
        label_issuer, name = label.split(":", 1)
        issuer = issuer or label_issuer
        name = name.strip()
    else:
        name = label.strip()

    if issuer and name and issuer.lower() not in name.lower():
        name = f"{issuer}: {name}"

    return name, secret


def derive_sync_key(pin, salt):
    return TwoFactorVault.derive_key(
        pin,
        salt,
        SYNC_ITERATIONS
    )


def create_bluetooth_socket():
    if platform.system() == "Windows":
        family = getattr(socket, "AF_BTH", None)
    else:
        family = getattr(socket, "AF_BLUETOOTH", None)

    if family is None or not hasattr(socket, "BTPROTO_RFCOMM"):
        raise OSError(
            "Bluetooth RFCOMM is unavailable on this system."
        )

    return socket.socket(
        family,
        socket.SOCK_STREAM,
        socket.BTPROTO_RFCOMM
    )


def receive_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))

        if not chunk:
            raise ConnectionError(
                "Bluetooth connection closed."
            )

        data.extend(chunk)

    return bytes(data)


def main(page: ft.Page):
    page.title = "Secure 2FA Vault"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.window.width = 450
    page.window.height = 750

    vault = TwoFactorVault()

    def update():
        try:
            page.update()
        except Exception:
            pass

    def show_error(message):
        page.clean()

        page.add(
            ft.Column(
                controls=[
                    ft.Icon(
                        ft.Icons.ERROR_OUTLINE,
                        size=60,
                        color=ft.Colors.RED_400
                    ),
                    ft.Text(
                        "Startup Error",
                        size=24,
                        weight=ft.FontWeight.BOLD
                    ),
                    ft.Text(message, selectable=True)
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER
            )
        )

        update()

    def show_setup():
        page.clean()

        pin = ft.TextField(
            label="Create PIN",
            password=True,
            can_reveal_password=True,
            autofocus=True
        )

        confirm = ft.TextField(
            label="Confirm PIN",
            password=True,
            can_reveal_password=True
        )

        error = ft.Text(color=ft.Colors.RED_400)

        def submit(e):
            if len(pin.value or "") < 4:
                error.value = (
                    "PIN must be at least four characters."
                )

            elif pin.value != confirm.value:
                error.value = "PINs do not match."

            else:
                try:
                    vault.setup_pin(pin.value)
                    show_vault()
                    return

                except Exception as ex:
                    error.value = str(ex)

            update()

        page.add(
            ft.Column(
                controls=[
                    ft.Icon(
                        ft.Icons.SHIELD,
                        size=64,
                        color=ft.Colors.PURPLE_300
                    ),
                    ft.Text(
                        "Secure 2FA Vault",
                        size=25,
                        weight=ft.FontWeight.BOLD
                    ),
                    ft.Text("Create your vault PIN."),
                    pin,
                    confirm,
                    error,
                    ft.Button(
                        "Create Vault",
                        on_click=submit,
                        width=220
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=18,
                width=350
            )
        )

        update()

    def show_login():
        page.clean()

        pin = ft.TextField(
            label="Enter PIN",
            password=True,
            can_reveal_password=True,
            autofocus=True
        )

        error = ft.Text(color=ft.Colors.RED_400)

        def submit(e):
            if vault.verify_pin(pin.value or ""):
                show_vault()
            else:
                error.value = (
                    "Incorrect PIN or damaged vault."
                )
                update()

        page.add(
            ft.Column(
                controls=[
                    ft.Icon(
                        ft.Icons.LOCK_OUTLINE,
                        size=64,
                        color=ft.Colors.PURPLE_300
                    ),
                    ft.Text(
                        "Unlock Vault",
                        size=25,
                        weight=ft.FontWeight.BOLD
                    ),
                    pin,
                    error,
                    ft.Button(
                        "Unlock",
                        on_click=submit,
                        width=220
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=18,
                width=350
            )
        )

        update()

    def show_vault():
        page.clean()
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH

        accounts_list = ft.ListView(
            expand=True,
            spacing=10,
            padding=5
        )

        timer_ring = ft.ProgressRing(
            value=1,
            width=24,
            height=24,
            stroke_width=3
        )

        timer_text = ft.Text("30s", size=12)

        name_input = ft.TextField(label="Account name")

        secret_input = ft.TextField(
            label="Base32 secret or otpauth URI"
        )

        add_error = ft.Text(color=ft.Colors.RED_400)

        send_status = ft.Text("Ready.")

        send_key = ft.Text(
            size=24,
            color=ft.Colors.PURPLE_300,
            font_family="monospace",
            weight=ft.FontWeight.BOLD
        )

        receive_address = ft.TextField(
            label="Sender Bluetooth MAC address"
        )

        receive_key = ft.TextField(
            label="8-digit transfer key",
            max_length=8,
            keyboard_type=ft.KeyboardType.NUMBER
        )

        receive_status = ft.Text()

        def confirm_delete(account):
            account_name = account["name"]
            account_secret = account["secret"]

            def delete_account(e):
                try:
                    deleted = vault.delete_account(
                        account_secret
                    )

                    page.pop_dialog()

                    if deleted:
                        refresh_codes()

                except Exception as ex:
                    page.pop_dialog()

                    show_error(
                        f"Could not delete account:\n{ex}"
                    )

            def cancel_delete(e):
                page.pop_dialog()

            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Delete Account?"),
                content=ft.Column(
                    controls=[
                        ft.Icon(
                            ft.Icons.DELETE_OUTLINE,
                            size=42,
                            color=ft.Colors.RED_400
                        ),
                        ft.Text(
                            f"Are you sure you want to delete "
                            f"'{account_name}'?",
                            size=15
                        ),
                        ft.Text(
                            "This action cannot be undone.",
                            color=ft.Colors.GREY_400,
                            size=12
                        )
                    ],
                    tight=True,
                    spacing=12,
                    width=300
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=cancel_delete
                    ),
                    ft.Button(
                        "Delete",
                        icon=ft.Icons.DELETE,
                        on_click=delete_account,
                        style=ft.ButtonStyle(
                            bgcolor=ft.Colors.RED_700,
                            color=ft.Colors.WHITE
                        )
                    )
                ]
            )

            page.show_dialog(dialog)

        def refresh_codes():
            accounts_list.controls.clear()

            with vault.lock:
                accounts = list(vault.data["accounts"])

            for account in accounts:
                try:
                    code = generate_totp(account["secret"])
                except Exception:
                    code = "INVALID SECRET"

                def copy_code(e, value=code):
                    try:
                        page.set_clipboard(value)
                    except Exception:
                        pass

                def delete_clicked(e, target=account):
                    confirm_delete(target)

                accounts_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=15,
                            content=ft.Row(
                                controls=[
                                    ft.Column(
                                        controls=[
                                            ft.Text(
                                                account["name"],
                                                size=16,
                                                weight=ft.FontWeight.BOLD
                                            ),
                                            ft.Text(
                                                f"{code[:3]} {code[3:]}"
                                                if len(code) == 6
                                                else code,
                                                size=24,
                                                font_family="monospace",
                                                color=ft.Colors.PURPLE_200
                                            )
                                        ],
                                        expand=True
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.CONTENT_COPY,
                                        tooltip="Copy code",
                                        on_click=copy_code
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE_OUTLINE,
                                        tooltip="Delete account",
                                        icon_color=ft.Colors.RED_400,
                                        on_click=delete_clicked
                                    )
                                ],
                                spacing=0
                            )
                        )
                    )
                )

            if not accounts:
                accounts_list.controls.append(
                    ft.Container(
                        padding=30,
                        content=ft.Column(
                            controls=[
                                ft.Icon(
                                    ft.Icons.KEY,
                                    size=45,
                                    color=ft.Colors.GREY_500
                                ),
                                ft.Text(
                                    "No accounts yet",
                                    size=17,
                                    weight=ft.FontWeight.BOLD
                                ),
                                ft.Text(
                                    "Press + to add your first account.",
                                    color=ft.Colors.GREY_400
                                )
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        )
                    )
                )

            update()

        def scan_qr(e):
            if cv2 is None:
                add_error.value = (
                    "Install QR dependencies with:\n"
                    "py -m pip install opencv-python numpy"
                )
                update()
                return

            try:
                image = ImageGrab.grabclipboard()

                if not isinstance(image, Image.Image):
                    add_error.value = (
                        "No QR image found on clipboard."
                    )
                    update()
                    return

                array = np.array(image.convert("RGB"))
                array = cv2.cvtColor(
                    array,
                    cv2.COLOR_RGB2BGR
                )

                detector = cv2.QRCodeDetector()
                decoded, _, _ = detector.detectAndDecode(array)

                if not decoded:
                    add_error.value = "Could not read QR code."
                    update()
                    return

                if decoded.lower().startswith("otpauth://"):
                    parsed_name, parsed_secret = parse_otpauth(
                        decoded
                    )

                    name_input.value = parsed_name or ""
                    secret_input.value = parsed_secret

                else:
                    secret_input.value = decoded

                add_error.value = (
                    "QR code loaded successfully."
                )
                add_error.color = ft.Colors.GREEN_400

            except Exception as ex:
                add_error.value = str(ex)

            update()

        def save_account(e):
            try:
                name = name_input.value or ""
                secret = secret_input.value or ""

                if secret.lower().startswith("otpauth://"):
                    parsed_name, parsed_secret = parse_otpauth(
                        secret
                    )

                    name = name or parsed_name
                    secret = parsed_secret

                added = vault.add_account(name, secret)

                if not added:
                    add_error.value = (
                        "This account is already in your vault."
                    )
                    add_error.color = ft.Colors.ORANGE_400
                    update()
                    return

                name_input.value = ""
                secret_input.value = ""

                page.pop_dialog()
                refresh_codes()

            except Exception as ex:
                add_error.value = str(ex)
                add_error.color = ft.Colors.RED_400
                update()

        add_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Add 2FA Account"),
            content=ft.Column(
                controls=[
                    ft.Text(
                        "Paste a secret or scan an authenticator QR code.",
                        size=12,
                        color=ft.Colors.GREY_400
                    ),
                    name_input,
                    secret_input,
                    ft.Button(
                        "Scan QR from Clipboard",
                        icon=ft.Icons.CONTENT_PASTE,
                        on_click=scan_qr
                    ),
                    add_error
                ],
                tight=True,
                spacing=12,
                width=330,
                scroll=ft.ScrollMode.AUTO
            ),
            actions=[
                ft.TextButton(
                    "Cancel",
                    on_click=lambda e: page.pop_dialog()
                ),
                ft.Button(
                    "Add Account",
                    on_click=save_account
                )
            ]
        )

        def open_add(e):
            add_error.value = ""
            add_error.color = ft.Colors.RED_400
            page.show_dialog(add_dialog)

        def send_bluetooth(e):
            transfer_pin = str(
                secrets.randbelow(90_000_000) + 10_000_000
            )

            send_key.value = transfer_pin
            send_status.value = (
                "Waiting for Bluetooth connection..."
            )

            page.show_dialog(send_dialog)

            def worker():
                server = None
                client = None

                try:
                    server = create_bluetooth_socket()
                    server.bind(("", BLUETOOTH_PORT))
                    server.listen(1)
                    server.settimeout(120)

                    client, address = server.accept()
                    client.settimeout(20)

                    salt = os.urandom(16)

                    with vault.lock:
                        payload = json.dumps(
                            vault.data["accounts"],
                            ensure_ascii=False
                        ).encode("utf-8")

                    encrypted = Fernet(
                        derive_sync_key(transfer_pin, salt)
                    ).encrypt(payload)

                    if len(encrypted) > MAX_SYNC_SIZE:
                        raise VaultError(
                            "Transfer is too large."
                        )

                    client.sendall(
                        salt
                        + struct.pack(">I", len(encrypted))
                        + encrypted
                    )

                    send_status.value = (
                        f"Encrypted transfer sent to {address}."
                    )

                except Exception as ex:
                    send_status.value = (
                        f"Bluetooth error: {ex}"
                    )

                finally:
                    if client:
                        client.close()

                    if server:
                        server.close()

                    update()

            threading.Thread(
                target=worker,
                daemon=True
            ).start()

        send_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Bluetooth Transfer"),
            content=ft.Column(
                controls=[
                    ft.Text(
                        "Give this key to the receiving device:"
                    ),
                    send_key,
                    ft.Text(
                        "Your account data is encrypted before transmission.",
                        size=12,
                        color=ft.Colors.GREY_400
                    ),
                    send_status
                ],
                tight=True,
                spacing=14,
                width=320
            ),
            actions=[
                ft.TextButton(
                    "Close",
                    on_click=lambda e: page.pop_dialog()
                )
            ]
        )

        def receive_bluetooth(e):
            address = (
                receive_address.value or ""
            ).strip()

            pin = (
                receive_key.value or ""
            ).strip()

            if (
                not address
                or len(pin) != 8
                or not pin.isdigit()
            ):
                receive_status.value = (
                    "Enter a Bluetooth address and an 8-digit key."
                )
                receive_status.color = ft.Colors.RED_400
                update()
                return

            receive_status.value = "Connecting..."
            receive_status.color = ft.Colors.PURPLE_200
            update()

            def worker():
                sock = None

                try:
                    sock = create_bluetooth_socket()
                    sock.settimeout(30)
                    sock.connect((address, BLUETOOTH_PORT))

                    salt = receive_exact(sock, 16)

                    length = struct.unpack(
                        ">I",
                        receive_exact(sock, 4)
                    )[0]

                    if not 0 < length <= MAX_SYNC_SIZE:
                        raise VaultError(
                            "Invalid transfer size."
                        )

                    encrypted = receive_exact(sock, length)

                    decrypted = Fernet(
                        derive_sync_key(pin, salt)
                    ).decrypt(encrypted)

                    accounts = json.loads(
                        decrypted.decode("utf-8")
                    )

                    added = vault.merge_accounts(accounts)

                    receive_status.value = (
                        f"Successfully imported {added} account(s)."
                    )
                    receive_status.color = ft.Colors.GREEN_400

                    refresh_codes()

                except InvalidToken:
                    receive_status.value = (
                        "Incorrect transfer key or corrupted data."
                    )
                    receive_status.color = ft.Colors.RED_400

                except Exception as ex:
                    receive_status.value = (
                        f"Receive failed: {ex}"
                    )
                    receive_status.color = ft.Colors.RED_400

                finally:
                    if sock:
                        sock.close()

                    update()

            threading.Thread(
                target=worker,
                daemon=True
            ).start()

        receive_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Receive Bluetooth Transfer"),
            content=ft.Column(
                controls=[
                    receive_address,
                    receive_key,
                    receive_status
                ],
                tight=True,
                spacing=12,
                width=320
            ),
            actions=[
                ft.TextButton(
                    "Cancel",
                    on_click=lambda e: page.pop_dialog()
                ),
                ft.Button(
                    "Connect & Receive",
                    on_click=receive_bluetooth
                )
            ]
        )

        def open_receive(e):
            receive_status.value = ""
            receive_key.value = ""
            page.show_dialog(receive_dialog)

        header = ft.Row(
            controls=[
                ft.Text(
                    "Your 2FA Codes",
                    size=20,
                    weight=ft.FontWeight.BOLD
                ),
                ft.Row(
                    controls=[
                        timer_ring,
                        timer_text,
                        ft.IconButton(
                            icon=ft.Icons.REFRESH,
                            tooltip="Refresh",
                            on_click=lambda e: refresh_codes()
                        ),
                        ft.IconButton(
                            icon=ft.Icons.BLUETOOTH,
                            tooltip="Send",
                            on_click=send_bluetooth
                        ),
                        ft.IconButton(
                            icon=ft.Icons.BLUETOOTH_CONNECTED,
                            tooltip="Receive",
                            on_click=open_receive
                        ),
                        ft.IconButton(
                            icon=ft.Icons.ADD,
                            tooltip="Add Account",
                            on_click=open_add
                        )
                    ],
                    spacing=0
                )
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        )

        page.add(
            header,
            ft.Divider(),
            accounts_list
        )

        refresh_codes()

        async def timer_loop():
            last_counter = -1

            while True:
                try:
                    now = time.time()
                    counter = int(now // 30)
                    remaining = 30 - (int(now) % 30)

                    timer_ring.value = remaining / 30
                    timer_text.value = f"{remaining}s"

                    if counter != last_counter:
                        last_counter = counter
                        refresh_codes()
                    else:
                        update()

                    await asyncio.sleep(1)

                except Exception:
                    break

        page.run_task(timer_loop)

    try:
        salt_exists = os.path.exists(SALT_FILE)
        data_exists = os.path.exists(DATA_FILE)

        if salt_exists and data_exists:
            show_login()

        elif salt_exists or data_exists:
            show_error(
                "Your vault files are incomplete.\n\n"
                "Restore both secure_2fa_vault.enc and vault.salt "
                "from the same backup."
            )

        else:
            show_setup()

    except Exception:
        show_error(traceback.format_exc())


if __name__ == "__main__":
    ft.run(main)
