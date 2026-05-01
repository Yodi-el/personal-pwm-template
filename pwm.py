#!/usr/bin/env python3
"""
encrypted-vault password manager (pwm)
vault file: vault.enc (encrypted JSON with salt, nonce, ciphertext)
"""

import argparse
import base64
import getpass
import json
import os
import secrets
import sys
from tabulate import tabulate
from argon2.low_level import hash_secret_raw, Type
import cryptography.hazmat.primitives.ciphers.aead as aead

# --- Constants ---
VAULT_FILE = "vault.enc"
ARGON2_TIME_COST = 3        # increase for slower/safer (but slower to open)
ARGON2_MEMORY_COST = 65536  # 64 MB (adjust based on your RAM)
ARGON2_PARALLELISM = 4
SALT_LENGTH = 16
NONCE_LENGTH = 12

# --- Key derivation ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the master password and salt using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )

# --- Encryption / Decryption ---
def encrypt_data(password: str, plaintext: str) -> bytes:
    """Encrypt plaintext using AES‑256‑GCM. Returns salt + nonce + ciphertext."""
    salt = secrets.token_bytes(SALT_LENGTH)
    derived_key = derive_key(password, salt)          # AES key from master password + salt
    nonce = secrets.token_bytes(NONCE_LENGTH)
    aesgcm = aead.AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return salt + nonce + ciphertext

def decrypt_data(password: str, blob: bytes) -> str:
    """Decrypt blob produced by encrypt_data. Returns plaintext string."""
    salt = blob[:SALT_LENGTH]
    nonce = blob[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    ct = blob[SALT_LENGTH + NONCE_LENGTH:]
    derived_key = derive_key(password, salt)
    aesgcm = aead.AESGCM(derived_key)
    plain = aesgcm.decrypt(nonce, ct, None)
    return plain.decode("utf-8")

# --- Vault operations ---
def load_vault(master_password: str) -> dict:
    """Load and decrypt the vault. Returns empty dict if file doesn't exist."""
    if not os.path.exists(VAULT_FILE):
        print("No vault found. Creating a new one.")
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted_blob = f.read()
    try:
        plain_json = decrypt_data(master_password, encrypted_blob)
        return json.loads(plain_json)
    except Exception:
        sys.exit("Error: wrong master password or corrupted vault.")

def save_vault(master_password: str, vault: dict):
    """Encrypt and write the vault to disk."""
    plain_json = json.dumps(vault, indent=2, sort_keys=True)
    encrypted_blob = encrypt_data(master_password, plain_json)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_blob)

def add_entry(vault: dict, service: str, username: str, password: str):
    if service in vault:
        print(f"Service '{service}' already exists. Use 'update' to change it.")
        return
    vault[service] = {"username": username, "password": password}
    print(f"Added entry for '{service}'.")

def get_entry(vault: dict, service: str):
    entry = vault.get(service)
    if entry:
        print(f"Service:  {service}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
    else:
        print(f"No entry found for '{service}'.")

def list_entries(vault: dict):
    if not vault:
        print("Vault is empty.")
        return
    table = [[s, vault[s]["username"]] for s in sorted(vault.keys())]
    print(tabulate(table, headers=["Service", "Username"], tablefmt="simple"))

def search_entries(vault: dict, keyword: str):
    results = {s: vault[s] for s in vault if keyword.lower() in s.lower()}
    if not results:
        print("No matching entries.")
        return
    table = [[s, vault[s]["username"]] for s in sorted(results.keys())]
    print(tabulate(table, headers=["Service", "Username"], tablefmt="simple"))

def delete_entry(vault: dict, service: str):
    if service in vault:
        del vault[service]
        print(f"Deleted entry '{service}'.")
    else:
        print(f"No entry named '{service}'.")

def update_entry(vault: dict, service: str, username=None, password=None):
    if service not in vault:
        print(f"Entry '{service}' does not exist. Use 'add' to create it.")
        return
    if username:
        vault[service]["username"] = username
    if password:
        vault[service]["password"] = password
    print(f"Updated entry '{service}'.")

def generate_password(length=20):
    """Generate a secure random password (letters, digits, symbols)."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    pwd = "".join(secrets.choice(chars) for _ in range(length))
    print(f"Generated password: {pwd}")

# --- CLI entry point ---
def main():
    parser = argparse.ArgumentParser(description="encrypted vault password manager")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List all services")
    sub.add_parser("search", help="Search by service name").add_argument("keyword")
    sub.add_parser("get", help="Get credentials for a service").add_argument("service")
    sub.add_parser("delete", help="Delete a service entry").add_argument("service")

    add_cmd = sub.add_parser("add", help="Add a new entry")
    add_cmd.add_argument("service")
    add_cmd.add_argument("username")
    add_cmd.add_argument("password", nargs="?", default=None)  # optional, will prompt if absent

   
    up_cmd = sub.add_parser("update", help="Update an existing entry")
    up_cmd.add_argument("service")
    """
    up_cmd.add_argument("--username", default=None)
    up_cmd.add_argument("--password", default=None)
    """ 

    sub.add_parser("chpass", help="Change the master password of the vault")

    sub.add_parser("gen", help="Generate a strong random password").add_argument(
        "length", nargs="?", type=int, default=20
    )

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    if args.command == "chpass":
        # Prompt for current master password
        old_master = getpass.getpass("Current master password: ")
        # Try loading the vault
        try:
            with open(VAULT_FILE, "rb") as f:
                blob = f.read()
            # Test decryption to verify old password (we don't need the data yet, just validation)
            old_data = json.loads(decrypt_data(old_master, blob))
        except FileNotFoundError:
            sys.exit("No vault file found. Create one first with 'add'.")
        except Exception:
            sys.exit("Incorrect current master password.")

        # Get new password with confirmation
        new_master = getpass.getpass("New master password: ")
        new_master_confirm = getpass.getpass("Confirm new master password: ")
        if new_master != new_master_confirm:
            sys.exit("Passwords do not match. Master password unchanged.")

        # Encrypt the same data with the new password
        plaintext = json.dumps(old_data, indent=2, sort_keys=True)
        encrypted_blob = encrypt_data(new_master, plaintext)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted_blob)
        print("Master password changed successfully.")
        sys.exit(0)   # Exit without further processing
        
    # Password generation doesn't need a vault
    if args.command == "gen":
        generate_password(args.length if hasattr(args, "length") else 20)
        return

    # All other commands need the master password
    master_pw = getpass.getpass("Master password: ")
    vault = load_vault(master_pw)

    # Dispatch commands
    if args.command == "list":
        list_entries(vault)
    elif args.command == "search":
        keyword = getattr(args, "keyword", "")
        search_entries(vault, keyword)
    elif args.command == "get":
        get_entry(vault, args.service)
    elif args.command == "delete":
        delete_entry(vault, args.service)
    elif args.command == "add":
        password = args.password
        if not password:
            password = getpass.getpass(f"Password for {args.service}: ")
        add_entry(vault, args.service, args.username, password)
    elif args.command == "update":
        service = args.service
        if service not in vault:
            print(f"Entry '{service}' does not exist. Use 'add' to create it.")
            sys.exit(0)

        # Ask for username update
        update_username = input("Change username? [y/N] ").strip().lower()
        if update_username in ("y", "yes"):
            new_username = input("New username: ").strip()
            if new_username:
                vault[service]["username"] = new_username
                print("Username updated.")
        else:
            new_username = None

        # Ask for password update
        update_password = input("Change password? [y/N] ").strip().lower()
        if update_password in ("y", "yes"):
            new_password = getpass.getpass("New password: ")
            if new_password:
                vault[service]["password"] = new_password
                print("Password updated.")
        else:
            new_password = None

        # Check if anything was actually changed
        if update_username not in ("y", "yes") and update_password not in ("y", "yes"):
            print("No changes made.")
        else:
            print(f"Entry '{service}' updated.")
    """"
    elif args.command == "update":
        username = args.username
        password = args.password
        if not username and not password:
            print("Specify at least --username or --password to update.")
            return
        update_entry(vault, args.service, username, password)
    """
    
    # Save vault after any modification
    save_vault(master_pw, vault)

if __name__ == "__main__":
    main()