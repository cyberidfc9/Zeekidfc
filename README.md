# 🛡 Zeek IDS CLI Setup Tool
**Developed by IG: [@cyberidfc](https://instagram.com/cyberidfc) — Follow for new updates**

An interactive, menu-driven Python CLI utility that automates the installation, network configuration, alerting, and reporting of a Zeek Intrusion Detection System (IDS) on Ubuntu/Debian machines.

---

## 🚀 Key Features

* **One-Click Installation**: Auto-detects OS distributions (Ubuntu/Debian) and configures official repository channels to install Zeek.
* **Network Interface Configuration**: Scans active interfaces and updates configuration paths for sniffing.
* **Email Alert Setup**: Guides you in setting up Postfix SMTP relay utilizing your secure Google App Passwords.
* **Intrusion Detection Rules**: Deploys custom port-scanning rules in `local.zeek` ignoring VirtualBox invalid checksums.
* **Automatic Log Emails**: Creates a cron job at your preferred intervals to send latest notice log files directly to the admin email.
* **Interactive Testing & Status**: Runs on-demand `nmap` scans against target machines and pulls real-time diagnostics of Zeek, Postfix, and Cron.

---

## 🛠 Prerequisites

1. **Linux OS**: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, or Debian.
2. **Root Access**: Must be executed with `sudo` permissions.
3. **Gmail Account & App Password**: Needed to send emails. You can generate a 16-character App Password at:
   👉 [Google App Passwords](https://myaccount.google.com/apppasswords)

---

## 💻 Installation & Usage

To download and run this tool on your system, execute the following commands in your terminal:

```bash
# 1. Clone the repository
git clone https://github.com/cyberidfc9/Zeekidfc.git

# 2. Navigate into the project folder
cd Zeekidfc

# 3. Run the interactive CLI installer with root privileges
sudo python3 zeek-setup.py
```

### Main Menu Overview:

```text
  ╔══════════════════════════════════════════════════╗
  ║  🛡  ZEEK IDS SETUP TOOL  v1.0                   ║
  ║  Automated IDS Installer & Configuration        ║
  ╚══════════════════════════════════════════════════╝

  Zeek: ● Installed   Postfix: ● Installed
  ────────────────────────────────────────────────────

    [1]  Full Setup  (Install Everything Step by Step)
    [2]  Install Zeek Only
    [3]  Configure Network Interface
    [4]  Setup Email Alerts (Postfix + Gmail)
    [5]  Configure Detection Rules
    [6]  Setup Automatic Log Emailing (Cron)
    [7]  Test IDS (Run Port Scan)
    [8]  Check System Status
    [9]  Uninstall / Reset
    [0]  Exit
```

---

## 📂 Configuration Files Touched

* **Zeek Node Configuration**: `/opt/zeek/etc/node.cfg`
* **Zeek Local Site Rules**: `/opt/zeek/share/zeek/site/local.zeek`
* **Postfix SMTP Config**: `/etc/postfix/main.cf`
* **Gmail Credentials**: `/etc/postfix/sasl_passwd`
* **System Crontab**: Managed for user `root`
