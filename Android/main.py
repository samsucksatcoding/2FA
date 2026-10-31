import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import cv2
import flet as ft
import flet_camera as fc
import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image


APP_DIR = Path(os.environ.get("FLET_APP_STORAGE_DATA", str(Path.home()))) / ".secure_2fa_vault"
APP_DIR.mkdir(parents=True, exist_ok=True)

DATA_FILE = APP_DIR / "secure_2fa_vault.enc"
SALT_FILE = APP_DIR / "vault.salt"

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

        APP_DIR.mkdir(parents=True, exist_ok=True)

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
    def normalize_secret(secret):
        return "".join(
            secret.strip().split()
        ).upper().rstrip("=")

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

    @staticmethod
    def write_file(path, content):
        temporary = str(path) + ".tmp"

        try:
            with open(temporary, "wb") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary, path)

        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    def setup_pin(self, pin):
        if len(pin) < 4:
            raise VaultError("PIN must contain at least four characters.")

        if DATA_FILE.exists() or SALT_FILE.exists():
            raise VaultError("Vault files already exist.")

        salt = os.urandom(16)

        self.key = self.derive_key(pin, salt)
        self.data = {"accounts": []}

        self.write_file(SALT_FILE, salt)
        self.save_data()

    def verify_pin(self, pin):
        try:
            salt = SALT_FILE.read_bytes()

            if len(salt) != 16:
                return False

            candidate = self.derive_key(pin, salt)
            encrypted = DATA_FILE.read_bytes()

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
            if any(
                account["secret"] == secret
                for account in self.data["accounts"]
            ):
                return False

            self.data["accounts"].append({
                "name": name,
                "secret": secret
            })

            try:
                self.save_data()
            except Exception:
                self.data["accounts"].pop()
                raise

        return True

    def delete_account(self, secret):
        secret = self.normalize_secret(secret)

        with self.lock:
            previous = list(self.data["accounts"])

            self.data["accounts"] = [
                account
                for account in previous
                if account["secret"] != secret
            ]

            if len(previous) == len(self.data["accounts"]):
                return False

            try:
                self.save_data()
            except Exception:
                self.data["accounts"] = previous
                raise

        return True

    def merge_accounts(self, accounts):
        if not isinstance(accounts, list):
            raise VaultError("Invalid imported account list.")

        prepared = []
        added_secrets = set()

        with self.lock:
            existing_secrets = {
                account["secret"]
                for account in self.data["accounts"]
            }

            for account in accounts:
                if not isinstance(account, dict):
                    continue

                try:
                    name = account.get("name", "")
                    secret = account.get("secret", "")

                    if not isinstance(name, str) or not isinstance(secret, str):
                        continue

                    name = name.strip()
                    secret = self.normalize_secret(secret)

                    if not name or not secret:
                        continue

                    padded = secret + "=" * (
                        (8 - len(secret) % 8) % 8
                    )

                    base64.b32decode(padded, casefold=True)

                    if secret in existing_secrets or secret in added_secrets:
                        continue

                    prepared.append({
                        "name": name,
                        "secret": secret
                    })

                    added_secrets.add(secret)

                except Exception:
                    continue

            if not prepared:
                return 0

            previous = list(self.data["accounts"])
            self.data["accounts"].extend(prepared)

            try:
                self.save_data()
            except Exception:
                self.data["accounts"] = previous
                raise

        return len(prepared)

    def export_accounts(self, transfer_pin):
        salt = os.urandom(16)

        with self.lock:
            payload = json.dumps(
                self.data["accounts"],
                ensure_ascii=False
            ).encode("utf-8")

        encrypted = Fernet(
            self.derive_key(
                transfer_pin,
                salt,
                SYNC_ITERATIONS
            )
        ).encrypt(payload)

        if len(encrypted) > MAX_SYNC_SIZE:
            raise VaultError("Export is too large.")

        return (
            b"2FASYNC1"
            + salt
            + struct.pack(">I", len(encrypted))
            + encrypted
        )

    def import_accounts(self, content, transfer_pin):
        if not content.startswith(b"2FASYNC1"):
            raise VaultError("Invalid transfer file.")

        if len(content) < 28:
            raise VaultError("Transfer file is incomplete.")

        salt = content[8:24]

        length = struct.unpack(
            ">I",
            content[24:28]
        )[0]

        if not 0 < length <= MAX_SYNC_SIZE:
            raise VaultError("Invalid transfer size.")

        encrypted = content[28:]

        if len(encrypted) != length:
            raise VaultError("Transfer file is incomplete.")

        decrypted = Fernet(
            self.derive_key(
                transfer_pin,
                salt,
                SYNC_ITERATIONS
            )
        ).decrypt(encrypted)

        accounts = json.loads(
            decrypted.decode("utf-8")
        )

        return self.merge_accounts(accounts)


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
        raise VaultError("Only TOTP codes are supported.")

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


def decode_qr_image(image_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    array = np.array(image)
    array = cv2.cvtColor(array, cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()

    decoded, _, _ = detector.detectAndDecode(array)

    if not decoded:
        raise VaultError("Could not read QR code.")

    return decoded


async def main(page: ft.Page):
    page.title = "Secure 2FA Vault"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 16
    page.bgcolor = ft.Colors.with_opacity(0.04, ft.Colors.PURPLE)

    page.window.width = 450
    page.window.height = 850
    page.scroll = ft.ScrollMode.AUTO

    vault = TwoFactorVault()

    file_picker = ft.FilePicker()
    page.services.append(file_picker)

    def update():
        try:
            page.update()
        except Exception:
            pass

    def notify(message, color=ft.Colors.PURPLE_300):
        page.open(
            ft.SnackBar(
                content=ft.Text(message),
                bgcolor=color
            )
        )

    def show_error(message):
        page.clean()

        page.add(
            ft.SafeArea(
                content=ft.Column(
                    controls=[
                        ft.Icon(
                            ft.Icons.ERROR_OUTLINE,
                            size=65,
                            color=ft.Colors.RED_400
                        ),
                        ft.Text(
                            "Something went wrong",
                            size=24,
                            weight=ft.FontWeight.BOLD
                        ),
                        ft.Text(
                            message,
                            selectable=True,
                            text_align=ft.TextAlign.CENTER
                        )
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=18
                )
            )
        )

        update()

    def show_setup():
        page.clean()

        pin = ft.TextField(
            label="Create PIN",
            password=True,
            can_reveal_password=True,
            autofocus=True,
            max_length=128
        )

        confirm = ft.TextField(
            label="Confirm PIN",
            password=True,
            can_reveal_password=True,
            max_length=128
        )

        error = ft.Text(color=ft.Colors.RED_400)

        def submit(e):
            if len(pin.value or "") < 4:
                error.value = "PIN must be at least four characters."

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
            ft.SafeArea(
                content=ft.Container(
                    expand=True,
                    alignment=ft.Alignment.CENTER,
                    content=ft.Column(
                        controls=[
                            ft.Icon(
                                ft.Icons.SHIELD,
                                size=75,
                                color=ft.Colors.PURPLE_300
                            ),
                            ft.Text(
                                "Secure 2FA Vault",
                                size=28,
                                weight=ft.FontWeight.BOLD
                            ),
                            ft.Text(
                                "Your codes. Your device. Your privacy.",
                                color=ft.Colors.GREY_400,
                                text_align=ft.TextAlign.CENTER
                            ),
                            pin,
                            confirm,
                            error,
                            ft.Button(
                                "Create Vault",
                                icon=ft.Icons.LOCK,
                                on_click=submit,
                                expand=True
                            )
                        ],
                        spacing=18,
                        width=340,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER
                    )
                )
            )
        )

        update()

    def show_login():
        page.clean()

        pin = ft.TextField(
            label="Enter PIN",
            password=True,
            can_reveal_password=True,
            autofocus=True,
            max_length=128
        )

        error = ft.Text(color=ft.Colors.RED_400)

        def submit(e):
            if vault.verify_pin(pin.value or ""):
                show_vault()
            else:
                error.value = "Incorrect PIN or damaged vault."
                update()

        page.add(
            ft.SafeArea(
                content=ft.Container(
                    expand=True,
                    alignment=ft.Alignment.CENTER,
                    content=ft.Column(
                        controls=[
                            ft.Icon(
                                ft.Icons.LOCK_OUTLINE,
                                size=75,
                                color=ft.Colors.PURPLE_300
                            ),
                            ft.Text(
                                "Unlock Vault",
                                size=28,
                                weight=ft.FontWeight.BOLD
                            ),
                            pin,
                            error,
                            ft.Button(
                                "Unlock",
                                icon=ft.Icons.LOCK_OPEN,
                                on_click=submit,
                                expand=True
                            )
                        ],
                        spacing=18,
                        width=340,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER
                    )
                )
            )
        )

        update()

    def show_vault():
        page.clean()

        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH

        timer_running = True

        accounts_list = ft.ListView(
            expand=True,
            spacing=12,
            padding=5,
            auto_scroll=False
        )

        timer_ring = ft.ProgressRing(
            value=1,
            width=22,
            height=22,
            stroke_width=3
        )

        timer_text = ft.Text("30s", size=12)

        count_text = ft.Text(
            "0 accounts",
            color=ft.Colors.GREY_400,
            size=13
        )

        name_input = ft.TextField(label="Account name")

        secret_input = ft.TextField(
            label="Base32 secret or otpauth URI",
            multiline=True,
            min_lines=1,
            max_lines=3
        )

        add_error = ft.Text(color=ft.Colors.RED_400)

        def refresh_codes():
            accounts_list.controls.clear()

            with vault.lock:
                accounts = list(vault.data["accounts"])

            count_text.value = (
                f"{len(accounts)} account"
                f"{'' if len(accounts) == 1 else 's'}"
            )

            for account in accounts:
                try:
                    code = generate_totp(account["secret"])
                except Exception:
                    code = "INVALID SECRET"

                def copy_code(e, value=code):
                    if value == "INVALID SECRET":
                        notify("This account has an invalid secret.", ft.Colors.RED_400)
                        return

                    page.set_clipboard(value)
                    notify("Code copied to clipboard.")

                def delete_clicked(e, target=account):
                    confirm_delete(target)

                accounts_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=16,
                            border_radius=16,
                            content=ft.Row(
                                controls=[
                                    ft.Column(
                                        controls=[
                                            ft.Text(
                                                account["name"],
                                                size=15,
                                                weight=ft.FontWeight.BOLD,
                                                max_lines=1,
                                                overflow=ft.TextOverflow.ELLIPSIS
                                            ),
                                            ft.Text(
                                                f"{code[:3]} {code[3:]}"
                                                if len(code) == 6
                                                else code,
                                                size=27,
                                                font_family="monospace",
                                                weight=ft.FontWeight.BOLD,
                                                color=ft.Colors.PURPLE_200
                                            )
                                        ],
                                        expand=True,
                                        spacing=5
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.CONTENT_COPY,
                                        tooltip="Copy code",
                                        on_click=copy_code
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE_OUTLINE,
                                        icon_color=ft.Colors.RED_400,
                                        tooltip="Delete account",
                                        on_click=delete_clicked
                                    )
                                ],
                                spacing=2,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER
                            )
                        )
                    )
                )

            if not accounts:
                accounts_list.controls.append(
                    ft.Container(
                        padding=35,
                        content=ft.Column(
                            controls=[
                                ft.Icon(
                                    ft.Icons.KEY,
                                    size=55,
                                    color=ft.Colors.GREY_500
                                ),
                                ft.Text(
                                    "No accounts yet",
                                    size=19,
                                    weight=ft.FontWeight.BOLD
                                ),
                                ft.Text(
                                    "Tap the + button to add your first account.",
                                    color=ft.Colors.GREY_400,
                                    text_align=ft.TextAlign.CENTER
                                )
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=10
                        )
                    )
                )

            update()

        def confirm_delete(account):
            def delete(e):
                try:
                    vault.delete_account(account["secret"])
                    page.pop_dialog()
                    refresh_codes()
                    notify("Account deleted.")

                except Exception as ex:
                    page.pop_dialog()
                    notify(f"Delete failed: {ex}", ft.Colors.RED_400)

            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Delete account?"),
                content=ft.Text(
                    f"Delete {account['name']} from your vault? "
                    "This cannot be undone."
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=lambda e: page.pop_dialog()
                    ),
                    ft.Button(
                        "Delete",
                        icon=ft.Icons.DELETE,
                        on_click=delete,
                        style=ft.ButtonStyle(
                            bgcolor=ft.Colors.RED_700,
                            color=ft.Colors.WHITE
                        )
                    )
                ]
            )

            page.show_dialog(dialog)

        def save_account(e):
            try:
                name = name_input.value or ""
                secret = secret_input.value or ""

                if secret.lower().startswith("otpauth://"):
                    parsed_name, parsed_secret = parse_otpauth(secret)
                    name = name or parsed_name
                    secret = parsed_secret

                added = vault.add_account(name, secret)

                if not added:
                    add_error.value = "This account already exists."
                    update()
                    return

                name_input.value = ""
                secret_input.value = ""

                page.pop_dialog()
                refresh_codes()
                notify("Account added successfully.")

            except Exception as ex:
                add_error.value = str(ex)
                update()

        def open_add(e):
            name_input.value = ""
            secret_input.value = ""
            add_error.value = ""

            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Add 2FA Account"),
                content=ft.Column(
                    controls=[
                        ft.Text(
                            "Enter an authenticator secret or scan a QR code.",
                            color=ft.Colors.GREY_400,
                            size=12
                        ),
                        name_input,
                        secret_input,
                        ft.Button(
                            "Scan QR with Camera",
                            icon=ft.Icons.QR_CODE_SCANNER,
                            on_click=open_camera
                        ),
                        ft.OutlinedButton(
                            "Import QR Image",
                            icon=ft.Icons.IMAGE,
                            on_click=import_qr_image
                        ),
                        add_error
                    ],
                    tight=True,
                    spacing=12,
                    width=320,
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

            page.show_dialog(dialog)

        async def open_camera(e):
            camera = fc.Camera(
                expand=True,
                preview_enabled=True
            )

            status = ft.Text("Starting camera...")
            initialized = False
            closing = False
            capturing = False

            async def close_camera(e=None):
                nonlocal closing

                if closing:
                    return

                closing = True

                try:
                    if initialized:
                        try:
                            await camera.stop_image_stream()
                        except Exception:
                            pass

                        try:
                            await camera.pause_preview()
                        except Exception:
                            pass

                    page.pop_dialog()

                except Exception:
                    pass

            async def capture_qr(e):
                nonlocal capturing

                if capturing or closing:
                    return

                capturing = True

                try:
                    status.value = "Capturing QR code..."
                    update()

                    photo = await camera.take_picture()

                    if isinstance(photo, str):
                        photo = base64.b64decode(photo)

                    decoded = decode_qr_image(photo)

                    if decoded.lower().startswith("otpauth://"):
                        parsed_name, parsed_secret = parse_otpauth(decoded)
                        name_input.value = parsed_name or ""
                        secret_input.value = parsed_secret
                    else:
                        secret_input.value = decoded

                    status.value = "QR code scanned!"
                    update()

                    await close_camera()
                    notify("QR code scanned successfully.")

                except Exception as ex:
                    status.value = str(ex)
                    update()

                finally:
                    capturing = False

            async def initialize_camera():
                nonlocal initialized

                try:
                    cameras = await camera.get_available_cameras()

                    if closing:
                        return

                    if not cameras:
                        status.value = "No camera found."
                        update()
                        return

                    selected = next(
                        (
                            item for item in cameras
                            if item.lens_direction == fc.CameraLensDirection.BACK
                        ),
                        cameras[0]
                    )

                    await camera.initialize(
                        description=selected,
                        resolution_preset=fc.ResolutionPreset.HIGH,
                        enable_audio=False,
                        image_format_group=fc.ImageFormatGroup.JPEG
                    )

                    initialized = True

                    if closing:
                        await close_camera()
                        return

                    status.value = "Position the QR code inside the camera view."
                    update()

                except Exception as ex:
                    if not closing:
                        status.value = f"Camera error: {ex}"
                        update()

            camera_dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Scan QR Code"),
                content=ft.Column(
                    controls=[
                        ft.Container(
                            height=350,
                            width=320,
                            bgcolor=ft.Colors.BLACK,
                            border_radius=15,
                            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
                            content=camera
                        ),
                        status,
                        ft.Text(
                            "Make sure the entire QR code is visible.",
                            size=12,
                            color=ft.Colors.GREY_400
                        )
                    ],
                    tight=True,
                    spacing=12,
                    width=320
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=close_camera
                    ),
                    ft.Button(
                        "Capture & Scan",
                        icon=ft.Icons.QR_CODE_SCANNER,
                        on_click=capture_qr
                    )
                ]
            )

            page.show_dialog(camera_dialog)
            await initialize_camera()

        async def import_qr_image(e):
            try:
                result = await file_picker.pick_files(
                    dialog_title="Select QR code image",
                    allowed_extensions=["png", "jpg", "jpeg", "webp"],
                    file_type=ft.FilePickerFileType.CUSTOM,
                    with_data=True
                )

                if not result:
                    return

                selected_file = result[0]

                if not selected_file.bytes:
                    raise VaultError("Could not read selected image.")

                decoded = decode_qr_image(selected_file.bytes)

                if decoded.lower().startswith("otpauth://"):
                    parsed_name, parsed_secret = parse_otpauth(decoded)
                    name_input.value = parsed_name or ""
                    secret_input.value = parsed_secret
                else:
                    secret_input.value = decoded

                update()
                notify("QR image imported successfully.")

            except Exception as ex:
                notify(f"QR import failed: {ex}", ft.Colors.RED_400)

        async def export_accounts(e):
            transfer_pin = str(
                secrets.randbelow(90_000_000) + 10_000_000
            )

            try:
                content = vault.export_accounts(transfer_pin)

                saved = await file_picker.save_file(
                    dialog_title="Export encrypted 2FA accounts",
                    file_name="secure_2fa_transfer.2fasync",
                    src_bytes=content
                )

                if saved:
                    page.show_dialog(
                        ft.AlertDialog(
                            modal=True,
                            title=ft.Text("Export Complete"),
                            content=ft.Column(
                                controls=[
                                    ft.Text(
                                        "Your encrypted transfer file is ready."
                                    ),
                                    ft.Text(
                                        "One-time transfer key:",
                                        color=ft.Colors.GREY_400
                                    ),
                                    ft.Container(
                                        padding=15,
                                        bgcolor=ft.Colors.with_opacity(
                                            0.12,
                                            ft.Colors.PURPLE
                                        ),
                                        border_radius=12,
                                        content=ft.Text(
                                            transfer_pin,
                                            size=26,
                                            font_family="monospace",
                                            weight=ft.FontWeight.BOLD,
                                            color=ft.Colors.PURPLE_200
                                        )
                                    ),
                                    ft.Text(
                                        "Keep this key separate from the transfer file. "
                                        "The file cannot be decrypted without it.",
                                        size=12,
                                        color=ft.Colors.GREY_400
                                    )
                                ],
                                tight=True,
                                spacing=14,
                                width=300
                            ),
                            actions=[
                                ft.TextButton(
                                    "Close",
                                    on_click=lambda e: page.pop_dialog()
                                )
                            ]
                        )
                    )

            except Exception as ex:
                notify(f"Export failed: {ex}", ft.Colors.RED_400)

        async def import_accounts(e):
            pin_input = ft.TextField(
                label="8-digit transfer key",
                keyboard_type=ft.KeyboardType.NUMBER,
                max_length=8
            )

            status = ft.Text(color=ft.Colors.RED_400)

            async def select_transfer(e):
                pin = (pin_input.value or "").strip()

                if len(pin) != 8 or not pin.isdigit():
                    status.value = "Enter the 8-digit transfer key."
                    update()
                    return

                try:
                    result = await file_picker.pick_files(
                        dialog_title="Select encrypted transfer",
                        allowed_extensions=["2fasync"],
                        file_type=ft.FilePickerFileType.CUSTOM,
                        with_data=True
                    )

                    if not result:
                        return

                    selected_file = result[0]
                    content = selected_file.bytes

                    if not content:
                        raise VaultError("Could not read transfer file.")

                    added = vault.import_accounts(content, pin)

                    page.pop_dialog()
                    refresh_codes()
                    notify(f"Imported {added} account(s).")

                except InvalidToken:
                    status.value = "Incorrect transfer key or corrupted file."
                    update()

                except Exception as ex:
                    status.value = str(ex)
                    update()

            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Import Accounts"),
                content=ft.Column(
                    controls=[
                        ft.Text(
                            "Select an encrypted .2fasync file and enter its transfer key.",
                            size=12,
                            color=ft.Colors.GREY_400
                        ),
                        pin_input,
                        status
                    ],
                    tight=True,
                    spacing=12,
                    width=300
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=lambda e: page.pop_dialog()
                    ),
                    ft.Button(
                        "Select File",
                        icon=ft.Icons.UPLOAD_FILE,
                        on_click=select_transfer
                    )
                ]
            )

            page.show_dialog(dialog)

        def show_options(e):
            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text("Vault Options"),
                content=ft.Column(
                    controls=[
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.FILE_UPLOAD_OUTLINED),
                            title=ft.Text("Export accounts"),
                            subtitle=ft.Text("Create an encrypted transfer file"),
                            on_click=lambda e: (
                                page.pop_dialog(),
                                page.run_task(export_accounts, None)
                            )
                        ),
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.FILE_DOWNLOAD_OUTLINED),
                            title=ft.Text("Import accounts"),
                            subtitle=ft.Text("Restore or merge an encrypted transfer"),
                            on_click=lambda e: (
                                page.pop_dialog(),
                                page.run_task(import_accounts, None)
                            )
                        ),
                        ft.Divider(),
                        ft.ListTile(
                            leading=ft.Icon(ft.Icons.LOCK),
                            title=ft.Text("Lock vault"),
                            subtitle=ft.Text("Return to the PIN screen"),
                            on_click=lambda e: (
                                page.pop_dialog(),
                                lock_vault()
                            )
                        )
                    ],
                    tight=True,
                    width=320
                ),
                actions=[
                    ft.TextButton(
                        "Close",
                        on_click=lambda e: page.pop_dialog()
                    )
                ]
            )

            page.show_dialog(dialog)

        def lock_vault():
            nonlocal timer_running

            timer_running = False
            vault.key = None
            vault.data = {"accounts": []}
            show_login()

        header = ft.Row(
            controls=[
                ft.Column(
                    controls=[
                        ft.Text(
                            "My Authenticator",
                            size=22,
                            weight=ft.FontWeight.BOLD
                        ),
                        count_text
                    ],
                    spacing=2,
                    expand=True
                ),
                timer_ring,
                timer_text,
                ft.IconButton(
                    icon=ft.Icons.MORE_VERT,
                    tooltip="Options",
                    on_click=show_options
                )
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER
        )

        page.add(
            ft.SafeArea(
                content=ft.Column(
                    controls=[
                        header,
                        ft.Divider(),
                        accounts_list,
                        ft.Container(
                            padding=10,
                            content=ft.Row(
                                controls=[
                                    ft.Button(
                                        "Add",
                                        icon=ft.Icons.ADD,
                                        on_click=open_add,
                                        expand=True
                                    ),
                                    ft.OutlinedButton(
                                        "Import",
                                        icon=ft.Icons.DOWNLOAD,
                                        on_click=import_accounts,
                                        expand=True
                                    )
                                ],
                                spacing=10
                            )
                        )
                    ],
                    expand=True,
                    spacing=12
                ),
                expand=True
            )
        )

        refresh_codes()

        async def timer_loop():
            last_counter = -1

            while timer_running:
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

                except asyncio.CancelledError:
                    break

                except Exception:
                    break

        page.run_task(timer_loop)

    try:
        salt_exists = SALT_FILE.exists()
        data_exists = DATA_FILE.exists()

        if salt_exists and data_exists:
            show_login()

        elif salt_exists or data_exists:
            show_error(
                "Your vault files are incomplete. "
                "Restore both files from the same backup."
            )

        else:
            show_setup()

    except Exception as ex:
        show_error(str(ex))


if __name__ == "__main__":
    ft.run(main)
