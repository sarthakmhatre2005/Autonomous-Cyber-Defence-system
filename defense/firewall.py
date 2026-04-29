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
        return True

    rule_name_in = f"Block_In_{ip}"
    rule_name_out = f"Block_Out_{ip}"
    
    # SAFETY: Do not block localhost/127.0.0.1 during testing to avoid locking user out of dashboard
    if ip in ["127.0.0.1", "::1", "localhost"]:
        print(f"Safety: Skipping actual Windows Firewall block for {ip} (Localhost). Action logged in DB.")
        return True

    if not is_admin():
        print(f"[ERROR] Failed to block IP {ip}: Administrator privileges required. Please run as Administrator.")
        return False

    # Block Inbound
    cmd_in = f"netsh advfirewall firewall add rule name=\"{rule_name_in}\" dir=in action=block remoteip={ip}"
    # Block Outbound
    cmd_out = f"netsh advfirewall firewall add rule name=\"{rule_name_out}\" dir=out action=block remoteip={ip}"
    
    try:
        res_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
        res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
        
        ok_in = (res_in.returncode == 0) or ("already exists" in res_in.stderr.lower())
        ok_out = (res_out.returncode == 0) or ("already exists" in res_out.stderr.lower())
        
        if ok_in and ok_out:
            print(f"[Firewall] Successfully blocked {ip} (Inbound + Outbound)")
            return True
        else:
            err = res_in.stderr if res_in.returncode != 0 else res_out.stderr
            print(f"[Firewall] Failed to block IP {ip}: {err.strip()}")
            return False
    except Exception as e:
        print(f"[Firewall] Critical error executing firewall command: {e}")
        return False

def unblock_ip(ip):
    """Unblocks an IP."""
    if platform.system() != "Windows":
        return

    if not is_admin():
        print(f"[ERROR] Failed to unblock IP {ip}: Administrator privileges required.")
        return

    rule_name_in = f"Block_In_{ip}"
    rule_name_out = f"Block_Out_{ip}"
    cmd_in = f"netsh advfirewall firewall delete rule name=\"{rule_name_in}\""
    cmd_out = f"netsh advfirewall firewall delete rule name=\"{rule_name_out}\""
    try:
        subprocess.run(cmd_in, shell=True, check=True, capture_output=True)
        subprocess.run(cmd_out, shell=True, check=True, capture_output=True)
        print(f"Unblocked IP: {ip} (Inbound + Outbound)")
    except subprocess.CalledProcessError:
        pass

def block_domain(domain):
    """Blocks a domain by modifying the hosts file to redirect to localhost. Returns True on success."""
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
            from data.database import log_action
            log_action("DOMAIN", domain, "BLOCK", f"Hosts file redirection applied.")
        return True
    except PermissionError:
        print(f"[Firewall] Permission denied blocking domain {domain}. Run as Admin.")
        return False
    except Exception as e:
        print(f"[Firewall] Domain block failed for {domain}: {e}")
        return False

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
