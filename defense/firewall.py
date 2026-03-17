import subprocess
import os
import platform

def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Non-Windows systems
        return os.getuid() == 0 if hasattr(os, 'getuid') else False

def block_ip(ip):
    """Blocks an IP using Windows Firewall."""
    if platform.system() != "Windows":
        print(f"Skipping IP block for {ip} (Not Windows)")
        return

    rule_name = f"Block_{ip}"
    
    # SAFETY: Do not block localhost/127.0.0.1 during testing to avoid locking user out of dashboard
    if ip in ["127.0.0.1", "::1", "localhost"]:
        print(f"Safety: Skipping actual Windows Firewall block for {ip} (Localhost). Action logged in DB.")
        return

    if not is_admin():
        print(f"[ERROR] Failed to block IP {ip}: Administrator privileges required. Please run as Administrator.")
        return

    cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        print(f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else str(e)
        print(f"Failed to block IP {ip}: {error_msg}")

def unblock_ip(ip):
    """Unblocks an IP."""
    if platform.system() != "Windows":
        return

    if not is_admin():
        print(f"[ERROR] Failed to unblock IP {ip}: Administrator privileges required.")
        return

    rule_name = f"Block_{ip}"
    cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        print(f"Unblocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        # Ignore if rule doesn't exist, but report permission issues
        if "requires elevation" in str(e.stderr):
             print(f"[ERROR] Failed to unblock IP {ip}: Administrator privileges required.")

def block_domain(domain):
    """Blocks a domain by modifying the hosts file to redirect to localhost."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    if platform.system() != "Windows":
        hosts_path = "/etc/hosts"

    entries = [f"127.0.0.1 {domain}\n", f"127.0.0.1 www.{domain}\n"]
    
    try:
        with open(hosts_path, "r") as f:
            content = f.read()
        
        to_add = []
        for entry in entries:
            if entry.strip() not in content:
                to_add.append(entry)
        
        if to_add:
            with open(hosts_path, "a") as f:
                for entry in to_add:
                    f.write(entry)
            print(f"Blocked Domain: {domain}")
            # Ensure it is logged in the actions table
            from data.database import log_action
            log_action("DOMAIN", domain, "BLOCK", f"Hosts file redirection applied.")
    except PermissionError:
        print(f"Permission denied blocking domain {domain}. Run as Admin.")

def unblock_domain(domain):
    """Unblocks a domain."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    if platform.system() != "Windows":
        hosts_path = "/etc/hosts"

    blocked_variations = [f"127.0.0.1 {domain}", f"127.0.0.1 www.{domain}"]
    
    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()
        
        with open(hosts_path, "w") as f:
            for line in lines:
                is_blocked = False
                for variant in blocked_variations:
                    if line.strip() == variant:
                        is_blocked = True
                        break
                if not is_blocked:
                    f.write(line)
        print(f"Unblocked Domain: {domain}")
    except PermissionError:
        print(f"Permission denied unblocking domain {domain}. Run as Admin.")
