#!/usr/bin/env python3
"""
Zeek IDS Setup Tool v1.0
========================
An interactive CLI tool to automate Zeek IDS installation,
network configuration, email alerting, and detection rules
on Ubuntu/Debian systems.

Author : Internship Lab Project
License: MIT
"""

import os
import sys
import subprocess
import shutil
import time
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

# ──────────────────────────────────────────────
# ANSI Color Helpers
# ──────────────────────────────────────────────
class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BG_BLUE = "\033[44m"
    BG_GREEN= "\033[42m"
    BG_RED  = "\033[41m"

def draw_box(lines_with_colors, title_padding=2):
    """
    Dynamic box drawing utility for CLI terminals.
    Automatically strips ANSI escape sequences before measuring width.
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    def get_display_width(text):
        clean_text = ansi_escape.sub('', text)
        width = 0
        for char in clean_text:
            if ord(char) > 0xffff or char in "🛡":
                width += 2
            else:
                width += 1
        return width

    widths = [get_display_width(line) for line in lines_with_colors]
    max_width = max(widths) if widths else 40
    box_width = max_width + (title_padding * 2)
    
    top_border = f"  {C.CYAN}╔" + "═" * box_width + f"╗{C.RESET}"
    bottom_border = f"  {C.CYAN}╚" + "═" * box_width + f"╝{C.RESET}"
    
    output = [top_border]
    for line in lines_with_colors:
        line_width = get_display_width(line)
        total_padding = box_width - line_width
        left_pad = title_padding
        right_pad = total_padding - left_pad
        if right_pad < 0:
            right_pad = 0
        padded_line = f"  {C.CYAN}║{C.RESET}" + " " * left_pad + line + " " * right_pad + f"{C.CYAN}║{C.RESET}"
        output.append(padded_line)
    output.append(bottom_border)
    return "\n".join(output)

def ok(msg):
    print(f"  {C.GREEN}[✓]{C.RESET} {msg}")

def fail(msg):
    print(f"  {C.RED}[✗]{C.RESET} {msg}")

def warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

def info(msg):
    print(f"  {C.CYAN}[i]{C.RESET} {msg}")

def step(msg):
    print(f"\n  {C.BOLD}{C.BLUE}▶ {msg}{C.RESET}")

def header(title):
    print()
    print(draw_box([f"{C.BOLD}{C.WHITE}{title}{C.RESET}"], title_padding=4))
    print()
    print()

def separator():
    print(f"  {C.DIM}{'─' * 52}{C.RESET}")

def press_enter():
    input(f"\n  {C.DIM}Press Enter to continue...{C.RESET}")

# ──────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────
def run_cmd(cmd, capture=True, check=False, shell=True):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=capture,
            text=True, timeout=300
        )
        return result
    except subprocess.TimeoutExpired:
        fail(f"Command timed out: {cmd}")
        return None
    except Exception as e:
        fail(f"Command failed: {e}")
        return None

def run_cmd_live(cmd):
    """Run a command with live output to terminal."""
    try:
        process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        output = []
        for line in process.stdout:
            print(f"    {C.DIM}{line.rstrip()}{C.RESET}")
            output.append(line)
        process.wait()
        return process.returncode, ''.join(output)
    except Exception as e:
        fail(f"Command error: {e}")
        return 1, str(e)

def is_root():
    return os.geteuid() == 0

def check_root():
    if not is_root():
        fail("This tool must be run as root (sudo).")
        print(f"\n  {C.YELLOW}Usage: sudo python3 {sys.argv[0]}{C.RESET}\n")
        sys.exit(1)

def get_input(prompt, default=None, required=True):
    """Get user input with optional default value."""
    if default:
        display = f"  {C.WHITE}{prompt} {C.DIM}[{default}]{C.RESET}: "
    else:
        display = f"  {C.WHITE}{prompt}{C.RESET}: "

    while True:
        value = input(display).strip()
        if not value and default:
            return default
        if not value and required:
            warn("This field is required. Please enter a value.")
            continue
        return value

def get_choice(prompt, options):
    """Display numbered options and get user choice."""
    print()
    for i, opt in enumerate(options, 1):
        print(f"    {C.CYAN}{i}{C.RESET}) {opt}")
    print()
    while True:
        choice = input(f"  {C.WHITE}{prompt}{C.RESET}: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice)
        warn(f"Please enter a number between 1 and {len(options)}")

def confirm(prompt):
    """Yes/No confirmation."""
    ans = input(f"  {C.WHITE}{prompt} (y/n){C.RESET}: ").strip().lower()
    return ans in ('y', 'yes')

def detect_os():
    """Detect the Linux distribution."""
    result = run_cmd("cat /etc/os-release")
    if result and result.returncode == 0:
        output = result.stdout
        if 'ubuntu' in output.lower():
            match = re.search(r'VERSION_ID="(.+?)"', output)
            version = match.group(1) if match else "unknown"
            return 'ubuntu', version
        elif 'debian' in output.lower():
            match = re.search(r'VERSION_ID="(.+?)"', output)
            version = match.group(1) if match else "unknown"
            return 'debian', version
    return 'unknown', 'unknown'

def get_interfaces():
    """List all network interfaces with their IPs."""
    interfaces = []
    result = run_cmd("ip -o addr show | awk '{print $2, $4}'")
    if result and result.returncode == 0:
        seen = set()
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0]
                ip = parts[1].split('/')[0]
                if iface not in seen and iface != 'lo':
                    interfaces.append((iface, ip))
                    seen.add(iface)
    return interfaces

def is_zeek_installed():
    """Check if Zeek is already installed."""
    result = run_cmd("which zeek 2>/dev/null")
    if result and result.returncode == 0:
        return True
    return os.path.exists("/opt/zeek/bin/zeek")

def get_zeek_version():
    """Get installed Zeek version."""
    path = "/opt/zeek/bin/zeek" if os.path.exists("/opt/zeek/bin/zeek") else "zeek"
    result = run_cmd(f"{path} --version 2>/dev/null")
    if result and result.returncode == 0:
        return result.stdout.strip()
    return None

def is_postfix_installed():
    """Check if Postfix is installed."""
    result = run_cmd("dpkg -l postfix 2>/dev/null | grep -q '^ii'")
    return result and result.returncode == 0

def is_nmap_installed():
    """Check if nmap is installed."""
    result = run_cmd("which nmap 2>/dev/null")
    if result and result.returncode == 0:
        return True
    return os.path.exists("/usr/bin/nmap")

def zeek_prefix():
    """Find the Zeek installation prefix."""
    result = run_cmd("which zeek 2>/dev/null")
    if result and result.returncode == 0:
        path = result.stdout.strip()
        return str(Path(path).parent.parent)
    if os.path.exists("/opt/zeek/bin/zeek"):
        return "/opt/zeek"
    return "/opt/zeek"

def backup_file(filepath):
    """Create a backup of a file before modifying it."""
    if os.path.exists(filepath):
        backup = f"{filepath}.backup.{int(time.time())}"
        shutil.copy2(filepath, backup)
        info(f"Backup created: {os.path.basename(backup)}")


# ══════════════════════════════════════════════
# MODULE 1: Install Zeek
# ══════════════════════════════════════════════
def install_zeek():
    header("INSTALL ZEEK IDS")

    if is_zeek_installed():
        version = get_zeek_version()
        ok(f"Zeek is already installed: {version}")
        if not confirm("Do you want to reinstall?"):
            return True

    distro, version = detect_os()
    if distro not in ('ubuntu', 'debian'):
        fail(f"Unsupported OS: {distro}. This tool supports Ubuntu/Debian only.")
        return False

    info(f"Detected OS: {distro.title()} {version}")

    step("Adding Zeek OBS repository...")
    codename_result = run_cmd("lsb_release -cs")
    if not codename_result or codename_result.returncode != 0:
        fail("Could not determine OS codename")
        return False
    codename = codename_result.stdout.strip()
    info(f"OS codename: {codename}")

    # Install prerequisites
    step("Installing prerequisites...")
    retcode, _ = run_cmd_live(
        "apt-get update -y && apt-get install -y curl gnupg2 apt-transport-https"
    )
    if retcode != 0:
        fail("Failed to install prerequisites")
        return False
    ok("Prerequisites installed")

    # Add Zeek repository key and source
    step("Adding Zeek repository...")
    key_url = f"https://download.opensuse.org/repositories/security:zeek/xUbuntu_{version}/Release.key"
    repo_url = f"https://download.opensuse.org/repositories/security:/zeek/xUbuntu_{version}/"

    cmds = [
        f"curl -fsSL {key_url} | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg",
        f'echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] {repo_url} /" '
        f'> /etc/apt/sources.list.d/zeek.list',
        "apt-get update -y"
    ]
    for cmd in cmds:
        retcode, _ = run_cmd_live(cmd)
        if retcode != 0:
            warn(f"Command had issues (may be OK): {cmd[:60]}...")

    # Install Zeek
    step("Installing Zeek (this may take several minutes)...")
    retcode, _ = run_cmd_live("apt-get install -y zeek")
    if retcode != 0:
        fail("Zeek installation failed")
        return False

    # Add Zeek to PATH
    step("Adding Zeek to system PATH...")
    prefix = zeek_prefix()
    profile = "/etc/profile.d/zeek.sh"
    with open(profile, 'w') as f:
        f.write(f'# Zeek PATH (generated by zeek-setup)\n')
        f.write(f'export PATH="{prefix}/bin:$PATH"\n')
    os.environ['PATH'] = f"{prefix}/bin:" + os.environ.get('PATH', '')
    ok(f"Zeek added to PATH via {profile}")

    # Verify
    if is_zeek_installed():
        version = get_zeek_version()
        ok(f"Zeek installed successfully: {version}")
        return True
    else:
        fail("Zeek installation could not be verified")
        return False


# ══════════════════════════════════════════════
# MODULE 2: Configure Network Interface
# ══════════════════════════════════════════════
def configure_network():
    header("CONFIGURE NETWORK INTERFACE")

    prefix = zeek_prefix()
    node_cfg = f"{prefix}/etc/node.cfg"

    if not os.path.exists(node_cfg):
        fail(f"Zeek config not found at {node_cfg}")
        fail("Please install Zeek first (Option 2)")
        return False

    interfaces = get_interfaces()
    if not interfaces:
        fail("No network interfaces found!")
        return False

    step("Available network interfaces:")
    options = []
    for iface, ip in interfaces:
        options.append(f"{iface}  ({ip})")

    choice = get_choice("Select the sniffing interface", options)
    selected_iface = interfaces[choice - 1][0]
    selected_ip = interfaces[choice - 1][1]

    info(f"Selected: {selected_iface} ({selected_ip})")

    # Update node.cfg
    step(f"Updating {node_cfg}...")
    backup_file(node_cfg)

    node_content = f"""# Zeek node configuration (generated by zeek-setup tool)
[zeek]
type=standalone
host=localhost
interface={selected_iface}
"""
    with open(node_cfg, 'w') as f:
        f.write(node_content)
    ok(f"Interface set to {selected_iface}")

    # Update networks.cfg
    networks_cfg = f"{prefix}/etc/networks.cfg"
    subnet = '.'.join(selected_ip.split('.')[:3]) + '.0/24'
    step(f"Adding local network: {subnet}")
    backup_file(networks_cfg)

    with open(networks_cfg, 'w') as f:
        f.write(f"# Local networks (generated by zeek-setup tool)\n")
        f.write(f"{subnet}    Local Network\n")
    ok(f"Local network configured: {subnet}")

    return True


# ══════════════════════════════════════════════
# MODULE 3: Setup Email Alerts
# ══════════════════════════════════════════════
def setup_email():
    header("SETUP EMAIL ALERTS")
    info("This will configure Postfix to send alerts via Gmail SMTP")
    separator()

    # Get user inputs
    admin_email = get_input("Enter admin email (Gmail address)")
    if '@gmail.com' not in admin_email.lower():
        warn("This tool is optimized for Gmail. Other providers may not work.")
        if not confirm("Continue anyway?"):
            return False

    # Show App Password instructions
    print(f"""
  {C.CYAN}╔═══════════════════════════════════════════════════════╗{C.RESET}
  {C.CYAN}║{C.BOLD}{C.WHITE}        HOW TO GENERATE GMAIL APP PASSWORD             {C.RESET}{C.CYAN}║{C.RESET}
  {C.CYAN}╚═══════════════════════════════════════════════════════╝{C.RESET}

  {C.YELLOW}PREREQUISITE: Enable 2-Step Verification first!{C.RESET}

  {C.WHITE}Step 1:{C.RESET} Open browser → {C.CYAN}https://myaccount.google.com{C.RESET}
  {C.WHITE}Step 2:{C.RESET} Click {C.GREEN}"Security"{C.RESET} from the left sidebar
  {C.WHITE}Step 3:{C.RESET} Scroll down to {C.GREEN}"2-Step Verification"{C.RESET}
         → If OFF: Click it → Follow prompts → Enter phone
           number → Verify OTP → Turn ON
         → If already ON: Skip to Step 4
  {C.WHITE}Step 4:{C.RESET} Go to → {C.CYAN}https://myaccount.google.com/apppasswords{C.RESET}
         (Or search "App Passwords" in Google Account settings)
  {C.WHITE}Step 5:{C.RESET} In the "App name" field, type: {C.GREEN}Zeek IDS{C.RESET}
  {C.WHITE}Step 6:{C.RESET} Click {C.GREEN}"Create"{C.RESET}
  {C.WHITE}Step 7:{C.RESET} Google will show a 16-character password like:
         {C.CYAN}┌─────────────────────────┐{C.RESET}
         {C.CYAN}│{C.RESET}  {C.BOLD}abcd efgh ijkl mnop{C.RESET}    {C.CYAN}│{C.RESET}
         {C.CYAN}└─────────────────────────┘{C.RESET}
         {C.YELLOW}COPY THIS PASSWORD!{C.RESET} (Remove spaces when pasting)
  {C.WHITE}Step 8:{C.RESET} Paste this password below when asked

  {C.RED}⚠ IMPORTANT NOTES:{C.RESET}
    • This is {C.BOLD}NOT{C.RESET} your Gmail login password
    • The app password is shown only ONCE — copy it immediately
    • If you lose it, delete and create a new one
    • 2-Step Verification MUST be ON first
""")

    app_password = get_input("Enter Gmail App Password (16 chars, no spaces)")
    app_password = app_password.replace(' ', '')

    if len(app_password) != 16:
        warn(f"App password should be 16 characters (you entered {len(app_password)})")
        if not confirm("Continue anyway?"):
            return False

    # Install Postfix
    step("Installing Postfix and mailutils...")
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    retcode, _ = run_cmd_live(
        "apt-get install -y postfix mailutils libsasl2-modules"
    )
    if retcode != 0:
        warn("Postfix installation had issues, attempting to continue...")

    # Configure main.cf
    step("Configuring Postfix for Gmail SMTP relay...")
    main_cf = "/etc/postfix/main.cf"
    backup_file(main_cf)

    hostname = os.uname().nodename
    main_cf_content = f"""# Postfix configuration (generated by zeek-setup tool)
smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level = encrypt
smtp_tls_session_cache_database = btree:${{data_directory}}/smtp_scache

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = {hostname}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = localhost.localdomain, localhost
relayhost = [smtp.gmail.com]:587
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4

# Gmail SMTP authentication
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_mechanism_filter = plain,login
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
"""
    with open(main_cf, 'w') as f:
        f.write(main_cf_content)
    ok("Postfix main.cf configured")

    # Create SASL password file
    step("Setting up Gmail authentication...")
    sasl_file = "/etc/postfix/sasl_passwd"
    with open(sasl_file, 'w') as f:
        f.write(f"[smtp.gmail.com]:587 {admin_email}:{app_password}\n")
    run_cmd("postmap /etc/postfix/sasl_passwd")
    run_cmd("chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db")
    ok("Gmail SASL authentication configured")

    # Restart Postfix
    step("Restarting Postfix...")
    run_cmd("systemctl restart postfix")
    run_cmd("systemctl enable postfix")
    ok("Postfix restarted and enabled")

    # Test email
    step("Sending test email...")
    run_cmd(
        f'echo "This is a test email from Zeek IDS Setup Tool. '
        f'If you received this, email alerting is working!" | '
        f'mail -s "Zeek IDS Setup - Test Email" {admin_email}'
    )
    time.sleep(4)

    # Check mail log
    result = run_cmd("tail -n 10 /var/log/mail.log")
    if result and 'status=sent' in result.stdout:
        ok(f"Test email sent successfully to {admin_email}")
        info("Check your Gmail inbox (also check Spam folder)")
    else:
        warn("Could not confirm email delivery. Check /var/log/mail.log")

    return True


# ══════════════════════════════════════════════
# MODULE 4: Configure Detection Rules
# ══════════════════════════════════════════════
def configure_rules():
    header("CONFIGURE DETECTION RULES")

    prefix = zeek_prefix()
    local_zeek = f"{prefix}/share/zeek/site/local.zeek"
    zeekctl_cfg = f"{prefix}/etc/zeekctl.cfg"

    if not os.path.exists(local_zeek):
        fail(f"Zeek site policy not found at {local_zeek}")
        fail("Please install Zeek first (Option 2)")
        return False

    admin_email = get_input("Enter admin email for alerts")
    threshold = get_input("Port scan threshold (unique ports before alert)", default="20")

    try:
        threshold = int(threshold)
    except ValueError:
        warn("Invalid number, using default: 20")
        threshold = 20

    # Generate local.zeek
    step("Generating detection rules...")
    backup_file(local_zeek)

    local_zeek_content = f'''# ═══════════════════════════════════════════════
# ZEEK IDS - LOCAL SITE POLICY
# Generated by Zeek IDS Setup Tool v1.0
# ═══════════════════════════════════════════════

redef digest_salt = "zeek-ids-setup-tool";

# Load standard scripts
@load policy/frameworks/notice
@load misc/loaded-scripts
@load misc/capture-loss
@load misc/stats

# Ignore checksums (required for VirtualBox / VM environments)
redef ignore_checksums = T;

# ── Port Scan Detection Module ──
module PortScan;

export {{
    redef enum Notice::Type += {{
        Port_Scan_Detected
    }};
}}

# Email alert configuration
redef Notice::emailed_types += {{
    Notice::Tally,
    PortScan::Port_Scan_Detected
}};

redef Notice::mail_dest = "{admin_email}";

# Track unique destination ports per source IP
global scan_tracker: table[addr] of set[port] &default=set() &read_expire = 5 mins;

event new_connection(c: connection)
{{
    local src = c$id$orig_h;
    local dstp = c$id$resp_p;

    if ( src !in scan_tracker )
        scan_tracker[src] = set();
    add scan_tracker[src][dstp];

    if ( |scan_tracker[src]| > {threshold} )
    {{
        NOTICE([
            $note = PortScan::Port_Scan_Detected,
            $msg = fmt("Possible port scan from %s (unique ports=%d)",
                        src, |scan_tracker[src]|),
            $src = src
        ]);
    }}
}}
'''
    with open(local_zeek, 'w') as f:
        f.write(local_zeek_content)
    ok("Detection rules written to local.zeek")
    info(f"Port scan threshold: {threshold} unique ports")

    # Update zeekctl.cfg MailTo
    step("Updating ZeekControl mail settings...")
    if os.path.exists(zeekctl_cfg):
        backup_file(zeekctl_cfg)
        with open(zeekctl_cfg, 'r') as f:
            content = f.read()
        content = re.sub(
            r'^MailTo\s*=\s*.*$',
            f'MailTo = {admin_email}',
            content, flags=re.MULTILINE
        )
        with open(zeekctl_cfg, 'w') as f:
            f.write(content)
        ok(f"ZeekControl MailTo set to {admin_email}")

    # Deploy Zeek
    step("Deploying Zeek configuration...")
    zeekctl = f"{prefix}/bin/zeekctl"
    retcode, _ = run_cmd_live(f"{zeekctl} deploy")
    if retcode == 0:
        ok("Zeek deployed successfully!")
    else:
        warn("Zeek deployment had issues")

    # Verify
    result = run_cmd(f"{zeekctl} status")
    if result and 'running' in result.stdout:
        ok("Zeek is running with new detection rules!")
    else:
        warn("Zeek may not be running. Check with: sudo zeekctl status")

    return True


# ══════════════════════════════════════════════
# MODULE 5: Setup Automatic Log Emailing
# ══════════════════════════════════════════════
def setup_log_email():
    header("SETUP AUTOMATIC LOG EMAILING")

    admin_email = get_input("Enter admin email for log reports")
    prefix = zeek_prefix()
    spool_dir = f"{prefix}/spool/zeek"
    log_dir = f"{prefix}/logs"

    # Create the send_notice_log.py helper script
    step("Creating log sender script...")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    send_script = os.path.join(script_dir, "send_notice_log.py")

    send_script_content = f'''#!/usr/bin/env python3
"""
Zeek Notice Log Email Sender
Sends the latest notice.log file as an email attachment.
Generated by Zeek IDS Setup Tool.
"""
import smtplib
import os
import glob
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

TO_EMAIL = "{admin_email}"
ZEEK_SPOOL = "{spool_dir}"
ZEEK_LOGS = "{log_dir}"

def find_notice_log():
    """Find the most recent notice.log file."""
    active = os.path.join(ZEEK_SPOOL, "notice.log")
    if os.path.exists(active) and os.path.getsize(active) > 200:
        return active
    today = datetime.now().strftime("%Y-%m-%d")
    archive_dir = os.path.join(ZEEK_LOGS, today)
    if os.path.exists(archive_dir):
        files = sorted(glob.glob(os.path.join(archive_dir, "notice.*.log.gz")),
                       reverse=True)
        if files:
            return files[0]
    return None

def send_email(file_path):
    """Send the notice.log file as an email attachment."""
    msg = MIMEMultipart()
    msg["From"] = "zeek-ids@" + os.uname().nodename
    msg["To"] = TO_EMAIL
    msg["Subject"] = f"Zeek IDS Notice Log - {{datetime.now().strftime(\'%Y-%m-%d %H:%M\')}}"
    body = (
        f"Zeek IDS Notice Log Report\\n"
        f"Generated: {{datetime.now().strftime(\'%Y-%m-%d %H:%M:%S\')}}\\n"
        f"Host: {{os.uname().nodename}}\\n"
        f"Log File: {{file_path}}\\n"
    )
    msg.attach(MIMEText(body, "plain"))
    try:
        with open(file_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            filename = os.path.basename(file_path)
            part.add_header("Content-Disposition", f"attachment; filename={{filename}}")
            msg.attach(part)
    except Exception as e:
        print(f"Error reading file: {{e}}")
        return False
    try:
        server = smtplib.SMTP("localhost", 25)
        server.sendmail(msg["From"], TO_EMAIL, msg.as_string())
        server.quit()
        print(f"Notice log sent to {{TO_EMAIL}}")
        return True
    except Exception as e:
        print(f"Error sending email: {{e}}")
        return False

if __name__ == "__main__":
    log_file = find_notice_log()
    if log_file:
        send_email(log_file)
    else:
        print("No notice.log found to send.")
'''
    with open(send_script, 'w') as f:
        f.write(send_script_content)
    os.chmod(send_script, 0o755)
    ok(f"Log sender script created: {send_script}")

    # Choose cron frequency
    step("Choose how often to send the log report:")
    freq_options = [
        "Every 5 minutes  (good for testing/demo)",
        "Every 15 minutes",
        "Every 1 hour",
        "Every 6 hours",
        "Once daily (at midnight)",
        "Custom cron expression"
    ]
    choice = get_choice("Select frequency", freq_options)

    cron_map = {
        1: "*/5 * * * *",
        2: "*/15 * * * *",
        3: "0 * * * *",
        4: "0 */6 * * *",
        5: "0 0 * * *"
    }

    if choice == 6:
        cron_expr = get_input("Enter cron expression (e.g., */10 * * * *)")
    else:
        cron_expr = cron_map[choice]

    # Install crontab
    step("Setting up cron job...")
    cron_line = f"{cron_expr} {send_script} >/dev/null 2>&1"

    # Read existing crontab, remove old zeek-setup entries
    result = run_cmd("crontab -l 2>/dev/null")
    existing = result.stdout if result and result.returncode == 0 else ""
    lines = [l for l in existing.split('\n')
             if 'send_notice_log.py' not in l and l.strip()]
    lines.append(cron_line)
    cron_content = '\n'.join(lines) + '\n'
    run_cmd(f'echo "{cron_content}" | crontab -')

    ok(f"Cron job set: {cron_expr}")
    info(f"Script: {send_script}")
    info(f"Email: {admin_email}")

    return True


# ══════════════════════════════════════════════
# MODULE 6: Test IDS
# ══════════════════════════════════════════════
def test_ids():
    header("TEST IDS SYSTEM")

    if not is_nmap_installed():
        step("Installing nmap...")
        run_cmd_live("apt-get install -y nmap")

    target_ip = get_input("Enter target IP to scan (e.g., Windows VM IP)")
    port_range = get_input("Enter port range", default="1-50")

    # Check Zeek status
    prefix = zeek_prefix()
    zeekctl = f"{prefix}/bin/zeekctl"
    result = run_cmd(f"{zeekctl} status")

    if not result or 'running' not in result.stdout:
        step("Starting Zeek...")
        run_cmd_live(f"{zeekctl} deploy")
        time.sleep(2)

    # Run nmap scan
    step(f"Running port scan: nmap -Pn -p {port_range} {target_ip}")
    separator()
    retcode, _ = run_cmd_live(f"nmap -Pn -p {port_range} {target_ip}")
    separator()

    if retcode == 0:
        ok("Port scan completed")
    else:
        fail("Port scan failed")
        return False

    # Wait for Zeek to process
    info("Waiting for Zeek to process traffic...")
    time.sleep(4)

    # Check notice.log
    spool_dir = f"{prefix}/spool/zeek"
    notice_log = f"{spool_dir}/notice.log"

    step("Checking notice.log for alerts...")
    if os.path.exists(notice_log):
        with open(notice_log, 'r') as f:
            content = f.read()
        if 'Port_Scan_Detected' in content:
            ok("PORT SCAN DETECTED! Alert logged in notice.log")
            lines = [l for l in content.split('\n') if 'Port_Scan_Detected' in l]
            for line in lines[:3]:
                fields = line.split('\t')
                if len(fields) > 11:
                    print(f"    {C.GREEN}→ {fields[10]}: {fields[11]}{C.RESET}")
        else:
            warn("No port scan alerts found yet")
            info("The scan may not have exceeded the threshold")
    else:
        warn("notice.log not found yet")
        info("Try scanning more ports or wait a moment")

    # Check mail log
    step("Checking email delivery...")
    result = run_cmd("tail -n 15 /var/log/mail.log")
    if result and 'status=sent' in result.stdout:
        ok("Alert emails are being delivered!")
    else:
        info("No recent email deliveries found in mail log")

    return True


# ══════════════════════════════════════════════
# MODULE 7: Check System Status
# ══════════════════════════════════════════════
def check_status():
    header("SYSTEM STATUS")

    # Zeek Status
    step("Zeek IDS Status:")
    if is_zeek_installed():
        version = get_zeek_version()
        ok(f"Installed: {version}")
        prefix = zeek_prefix()
        zeekctl = f"{prefix}/bin/zeekctl"
        result = run_cmd(f"{zeekctl} status")
        if result:
            if 'running' in result.stdout:
                ok("Status: RUNNING")
                for line in result.stdout.split('\n'):
                    if 'running' in line:
                        print(f"    {C.DIM}{line.strip()}{C.RESET}")
            elif 'crashed' in result.stdout:
                fail("Status: CRASHED")
            else:
                warn("Status: STOPPED")
    else:
        fail("Zeek is NOT installed")

    # Postfix Status
    separator()
    step("Postfix Mail Status:")
    if is_postfix_installed():
        ok("Installed")
        result = run_cmd("systemctl is-active postfix")
        if result and result.stdout.strip() == 'active':
            ok("Status: RUNNING")
        else:
            fail("Status: NOT RUNNING")
    else:
        fail("Postfix is NOT installed")

    # Cron Jobs
    separator()
    step("Cron Jobs:")
    result = run_cmd("crontab -l 2>/dev/null")
    if result and result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if line.strip() and not line.startswith('#'):
                ok(f"Active: {line.strip()}")
    else:
        info("No cron jobs configured")

    # Recent Notices
    separator()
    step("Recent Alerts (notice.log):")
    prefix = zeek_prefix()
    notice_log = f"{prefix}/spool/zeek/notice.log"
    if os.path.exists(notice_log):
        result = run_cmd(f"grep 'Port_Scan_Detected' {notice_log} | tail -5")
        if result and result.stdout.strip():
            count = len(result.stdout.strip().split('\n'))
            ok(f"Found {count} recent port scan alert(s)")
            for line in result.stdout.strip().split('\n'):
                fields = line.split('\t')
                if len(fields) > 11:
                    print(f"    {C.GREEN}→ {fields[11][:70]}{C.RESET}")
        else:
            info("No port scan alerts in current notice.log")
    else:
        info("No active notice.log (Zeek may need a scan to trigger)")

    press_enter()
    return True


# ══════════════════════════════════════════════
# MODULE 8: Full Setup (Orchestrator)
# ══════════════════════════════════════════════
def full_setup():
    header("FULL IDS SETUP")
    info("This will walk you through the complete setup process")
    print(f"""
  {C.WHITE}Steps:{C.RESET}
    {C.CYAN}1.{C.RESET} Install Zeek IDS engine
    {C.CYAN}2.{C.RESET} Configure network sniffing interface
    {C.CYAN}3.{C.RESET} Setup email alerting (Postfix + Gmail)
    {C.CYAN}4.{C.RESET} Configure port scan detection rules
    {C.CYAN}5.{C.RESET} Setup automatic log emailing via cron
    {C.CYAN}6.{C.RESET} Test the IDS with a live port scan
""")
    separator()

    if not confirm("Ready to begin full setup?"):
        return False

    steps = [
        ("Step 1/6: Install Zeek",          install_zeek),
        ("Step 2/6: Configure Network",     configure_network),
        ("Step 3/6: Setup Email Alerts",    setup_email),
        ("Step 4/6: Configure Rules",       configure_rules),
        ("Step 5/6: Setup Log Emailing",    setup_log_email),
        ("Step 6/6: Test IDS",              test_ids),
    ]

    results = []
    for title, func in steps:
        print(f"\n  {C.BG_BLUE}{C.WHITE}{C.BOLD} {title} {C.RESET}")
        success = func()
        results.append((title, success))
        if not success:
            warn(f"{title} had issues")
            if not confirm("Continue with next step?"):
                break

    # Summary
    header("SETUP COMPLETE - SUMMARY")
    for title, success in results:
        if success:
            ok(title)
        else:
            fail(title)

    separator()
    prefix = zeek_prefix()
    print(f"""
  {C.GREEN}{C.BOLD}Your Zeek IDS is now configured!{C.RESET}

  {C.WHITE}Useful commands:{C.RESET}
    {C.CYAN}sudo {prefix}/bin/zeekctl status{C.RESET}   — Check Zeek status
    {C.CYAN}sudo {prefix}/bin/zeekctl start{C.RESET}    — Start Zeek
    {C.CYAN}sudo {prefix}/bin/zeekctl stop{C.RESET}     — Stop Zeek
    {C.CYAN}sudo {prefix}/bin/zeekctl deploy{C.RESET}   — Redeploy config
    {C.CYAN}cat {prefix}/spool/zeek/notice.log{C.RESET} — View alerts
""")
    press_enter()
    return True


# ══════════════════════════════════════════════
# MODULE 9: Uninstall / Reset
# ══════════════════════════════════════════════
def uninstall_reset():
    header("UNINSTALL / RESET")

    options = [
        "Reset Zeek config only (keep Zeek installed)",
        "Remove cron jobs only",
        "Full uninstall (remove Zeek + Postfix + configs)",
        "Go back"
    ]
    choice = get_choice("What would you like to do?", options)

    if choice == 4:
        return True

    if choice == 1:
        if confirm("Reset all Zeek configurations to defaults?"):
            prefix = zeek_prefix()
            zeekctl = f"{prefix}/bin/zeekctl"
            step("Stopping Zeek...")
            run_cmd(f"{zeekctl} stop")
            step("Resetting local.zeek...")
            local_zeek = f"{prefix}/share/zeek/site/local.zeek"
            if os.path.exists(local_zeek):
                backup_file(local_zeek)
                with open(local_zeek, 'w') as f:
                    f.write("# Reset by zeek-setup tool\n@load misc/loaded-scripts\n")
            ok("Zeek config reset")

    elif choice == 2:
        if confirm("Remove all zeek-setup cron jobs?"):
            result = run_cmd("crontab -l 2>/dev/null")
            if result and result.returncode == 0:
                lines = [l for l in result.stdout.split('\n')
                         if 'send_notice_log.py' not in l and l.strip()]
                if lines:
                    cron_content = '\n'.join(lines) + '\n'
                    run_cmd(f'echo "{cron_content}" | crontab -')
                else:
                    run_cmd("crontab -r 2>/dev/null")
            ok("Cron jobs removed")

    elif choice == 3:
        print(f"\n  {C.RED}{C.BOLD}⚠ WARNING: This will remove Zeek, Postfix, and all configs!{C.RESET}")
        if confirm("Are you SURE you want to uninstall everything?"):
            if confirm("This is your LAST chance. Continue?"):
                prefix = zeek_prefix()
                step("Stopping Zeek...")
                run_cmd(f"{prefix}/bin/zeekctl stop 2>/dev/null")
                step("Removing Zeek...")
                run_cmd_live("apt-get remove --purge -y zeek")
                step("Removing cron jobs...")
                run_cmd("crontab -r 2>/dev/null")
                step("Cleaning up...")
                run_cmd("rm -f /etc/apt/sources.list.d/zeek.list")
                ok("Uninstall complete")

    return True


# ══════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════
def main_menu():
    while True:
        os.system('clear')

        # Banner
        banner_lines = [
            f"{C.BOLD}{C.WHITE}🛡  ZEEK IDS SETUP TOOL  v1.0{C.RESET}",
            f"{C.DIM}Automated IDS Installer & Configuration{C.RESET}",
            f"{C.MAGENTA}Developed by IG @cyberidfc{C.RESET}",
            f"{C.YELLOW}Follow for new updates{C.RESET}"
        ]
        print(draw_box(banner_lines, title_padding=3))

        # Status indicators
        z = f"{C.GREEN}● Installed{C.RESET}" if is_zeek_installed() else f"{C.RED}● Not Installed{C.RESET}"
        p = f"{C.GREEN}● Installed{C.RESET}" if is_postfix_installed() else f"{C.RED}● Not Installed{C.RESET}"
        print(f"  Zeek: {z}   Postfix: {p}")
        separator()

        menu_items = [
            f"{C.BOLD}Full Setup{C.RESET}  {C.DIM}(Install Everything Step by Step){C.RESET}",
            f"Install Zeek Only",
            f"Configure Network Interface",
            f"Setup Email Alerts {C.DIM}(Postfix + Gmail){C.RESET}",
            f"Configure Detection Rules",
            f"Setup Automatic Log Emailing {C.DIM}(Cron){C.RESET}",
            f"Test IDS {C.DIM}(Run Port Scan){C.RESET}",
            f"Check System Status",
            f"Uninstall / Reset",
            f"{C.RED}Exit{C.RESET}"
        ]

        print()
        for i, item in enumerate(menu_items):
            num = i + 1 if i < 9 else 0
            print(f"    {C.CYAN}[{num}]{C.RESET}  {item}")
        print()

        choice = input(f"  {C.WHITE}Enter your choice{C.RESET}: ").strip()

        actions = {
            '1': (full_setup, False),
            '2': (install_zeek, True),
            '3': (configure_network, True),
            '4': (setup_email, True),
            '5': (configure_rules, True),
            '6': (setup_log_email, True),
            '7': (test_ids, True),
            '8': (check_status, False),
            '9': (uninstall_reset, True),
        }

        if choice == '0':
            print(f"\n  {C.GREEN}Goodbye! Stay secure. 🛡{C.RESET}\n")
            sys.exit(0)
        elif choice in actions:
            func, needs_enter = actions[choice]
            func()
            if needs_enter:
                press_enter()
        else:
            warn("Invalid choice. Please try again.")
            time.sleep(1)


# ══════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════
if __name__ == '__main__':
    try:
        check_root()
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Interrupted. Goodbye!{C.RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {C.RED}Unexpected error: {e}{C.RESET}\n")
        sys.exit(1)
