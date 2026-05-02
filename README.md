Personal Encrypted Password Manager (pwm)

A minimal, CLI‑based password manager that stores credentials in an **encrypted vault file** (`vault.enc`). The vault can be safely synced via a **private Git repository** without exposing your secrets.

# How it works

- You provide a **master password** each time you run a command.
- A strong encryption key is derived from the master password using **Argon2id** (memory‑hard).
- All entries are encrypted with **AES‑256‑GCM** and saved to a single file (`vault.enc`).
- The encrypted vault file is safe to commit to Git—without the master password, the data is unreadable.

# Requirements

- Python 3.10 or newer
- pip (Python package installer)
- Git (if you want to sync the vault)

# Installation (local or in GitHub Codespaces)

1. **Clone the repository** (if you haven’t already):

        git clone https://github.com/YOUR_USER/private-pwm.git
        cd private-pwm

3. **Create a virtual environment and install dependencies**
## On Linux/macOS (or GitHub Codespaces)

    python3 -m venv venv
    source venv/bin/activate

## On Windows

    python -m venv venv
    venv\Scripts\activate

# Install required packages

Using:

        pip install argon2-cffi cryptography tabulate

or else use:

        pip install -r requirements.txt
        
# Usage
All commands (except gen) will ask for your master password.
Type it carefully—it is not displayed on screen.

## Add new entry

    python pwm.py add <service> <username>

You’ll be prompted for the service password (hidden).
Example:
    python pwm.py add github myuser@email.com

## Get an entry

    python pwm.py get <service>

Shows username and password.

## List all entries

        python pwm.py list

Prints a table of all stored services and their usernames (passwords hidden).

## Search by service name

        python pwm.py search <keyword>

Lists all services containing <keyword>.

## Update an entry (interactive)

    python pwm.py update <service>

You’ll be asked:

Change username? [y/N] — answer y to enter a new username, anything else to keep the current one.

Change password? [y/N] — answer y to enter a new password (hidden), anything else to keep the current one.

## Delete an entry

    python pwm.py delete <service>

## Generate a random password

    python pwm.py gen [length]

Default length is 20. Example for 32 characters:

    python pwm.py gen 32

# Syncing the vault across devices
After making changes (add, update, delete), commit the encrypted vault:

    git add vault.enc
    git commit -m "update vault"
    git push

On another device, pull the latest vault:

    git pull

Run the password manager as usual—the same master password unlocks the vault.

⚠️ Keep your master password secret. If you lose it, the vault cannot be recovered. If you think it has been compromised, change it immediately and re‑encrypt the vault.

# Security notes
The master password is never stored — not in a file, not in the repository, not in environment variables.

The vault file is encrypted with AES‑256‑GCM using a key derived from the master password and a random salt.

Use a strong, unique master password (a long passphrase is recommended).

(Optional) For extra security, you can add a key file kept offline — contact the author for instructions.

# Troubleshooting
If you see ModuleNotFoundError: No module named 'xxx', make sure the virtual environment is activated and run

    pip install --force-reinstall argon2-cffi cryptography tabulate
