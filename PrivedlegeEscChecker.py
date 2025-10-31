import os
import platform
import subprocess
import sys

def run_command(command):
    """Runs a command and returns its output, handling errors."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='ignore'
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error running command '{command}': {e}"

def check_linux_privesc():
    """Checks for common Linux/macOS privilege escalation vectors."""
    print("\n" + "="*20, "Linux/macOS Privilege Escalation Checks", "="*20)

    # 1. Check sudo permissions for the current user
    print("\n--- [1] Checking sudo permissions (sudo -l) ---")
    sudo_check = run_command("sudo -ln") # -n for non-interactive
    if "a password is required" in sudo_check:
        print("Sudo requires a password. Run 'sudo -l' manually to check permissions.")
    elif "(ALL : ALL) ALL" in sudo_check or "NOPASSWD:" in sudo_check:
        print("[VULNERABLE] User may have powerful sudo privileges or passwordless sudo.")
        print(sudo_check)
    else:
        print("[INFO] Sudo permissions seem restricted. Review manually.")
        print(sudo_check)

    # 2. Find SUID/SGID binaries
    print("\n--- [2] Searching for SUID/SGID binaries ---")
    print("This may take a moment...")
    # Common paths to search. Add more if needed.
    # Note: Searching from '/' can be very slow.
    suid_command = "find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null"
    sgid_command = "find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -perm -2000 -type f 2>/dev/null"
    
    suid_files = run_command(suid_command)
    if suid_files:
        print("[VULNERABLE] Found SUID files. Check GTFOBins to see if they can be exploited.")
        print(suid_files)
    else:
        print("[INFO] No unusual SUID files found in common locations.")

    sgid_files = run_command(sgid_command)
    if sgid_files:
        print("\n[VULNERABLE] Found SGID files. These might be exploitable.")
        print(sgid_files)
    else:
        print("[INFO] No unusual SGID files found in common locations.")

    # 3. Check for writable /etc/passwd
    print("\n--- [3] Checking for writable /etc/passwd ---")
    if os.access('/etc/passwd', os.W_OK):
        print("[VULNERABLE] /etc/passwd is writable by the current user!")
    else:
        print("[INFO] /etc/passwd is not writable.")

def check_windows_privesc():
    """Checks for common Windows privilege escalation vectors."""
    print("\n" + "="*20, "Windows Privilege Escalation Checks", "="*20)

    # 1. Check for Unquoted Service Paths
    print("\n--- [1] Checking for Unquoted Service Paths ---")
    unquoted_paths_cmd = 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /v /i \'"\''
    unquoted_services = run_command(unquoted_paths_cmd)
    if unquoted_services:
        print("[VULNERABLE] Found services with unquoted paths that start automatically.")
        print("Check if you have write permissions in the path hierarchy.")
        print(unquoted_services)
    else:
        print("[INFO] No unquoted service paths found for auto-start services.")

    # 2. Check for "AlwaysInstallElevated" registry key
    print("\n--- [2] Checking for 'AlwaysInstallElevated' Policy ---")
    try:
        import winreg
        key_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        always_elevated_user = False
        always_elevated_machine = False

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
                if value == 1:
                    always_elevated_user = True
        except FileNotFoundError:
            pass # Key doesn't exist, which is secure.

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
                if value == 1:
                    always_elevated_machine = True
        except FileNotFoundError:
            pass # Key doesn't exist, which is secure.

        if always_elevated_user and always_elevated_machine:
            print("[VULNERABLE] 'AlwaysInstallElevated' is set for both user and machine.")
            print("This allows any user to install MSI packages with SYSTEM privileges.")
        else:
            print("[INFO] 'AlwaysInstallElevated' policy is not enabled.")

    except ImportError:
        print("[INFO] 'winreg' module not available. Skipping registry check.")
    except Exception as e:
        print(f"[ERROR] Could not check registry: {e}")


if __name__ == "__main__":
    system = platform.system()
    if system == "Linux" or system == "Darwin": # Darwin is macOS
        check_linux_privesc()
    elif system == "Windows":
        check_windows_privesc()
    else:
        print(f"Unsupported operating system: {system}")
