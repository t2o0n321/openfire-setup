# Ubuntu Server Security Hardening Toolkit
Provides automated scripts and configuration assets to **audit** and **harden** the security of Ubuntu servers. Focuses on best practices for SSH, firewall (UFW), Fail2Ban, kernel parameters, shared memory, and the removal of insecure services.

## Usage

### 1. Harden Your Server

Run the hardening script as root (or with sudo):

```sh
# Use -y to auto-confirm all prompts:
sudo ./secure_your_server.sh [-y]
```

### 2. Audit Server Security
```sh
sudo ./audit_server_security.sh
```

## Customization
- Allowed Ports:
    - Edit the `UFW_ALLOWED_PORTS` array in common.sh to match your needs.

- Fail2Ban Settings:
    - `secure_your_server.sh` automatically update `assets/fail2ban/ufw.aggressive.conf` from the settings in `common.sh`. 
    - For further modifications, modify `assets/fail2ban/jail.local` and `common.sh` manually.

## Reference
- https://gist.github.com/mirajehossain/59c6e62fcdc84ca1e28b6a048038676c