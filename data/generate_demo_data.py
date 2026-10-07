"""
data/generate_demo_data.py
--------------------------
Synthetic security-log generator for the Cloud-Based Cyber Threat Detection
Dashboard demo.

Event composition (610 total)
------------------------------
  500  Normal events       – SSH logins, HTTP/HTTPS requests, DNS queries,
                             FTP connections from internal hosts to mixed targets.
   50  Brute-force events  – Single attacker IP issuing rapid failed SSH
                             logins (>5 failures in any 5-minute window).
   30  Port-scan events    – Single scanner IP probing 20+ unique destination
                             ports within 1 minute.
   20  Abnormal-traffic    – Single exfiltration IP sending very large byte
                             and packet counts over short bursts.
   10  ML-anomaly events   – Outlier combinations of all feature dimensions.

Output files
------------
  data/demo_security_logs.csv  – Full synthetic dataset (610 rows).
  data/sample_events.json      – First 20 events as a JSON record list.

Usage
-----
  python data/generate_demo_data.py

Dependencies: pandas, numpy
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ---------------------------------------------------------------------------
# Reference data pools
# ---------------------------------------------------------------------------

# Internal /24 subnets
INTERNAL_HOSTS = [f"192.168.{subnet}.{host}"
                  for subnet in range(1, 6)
                  for host in range(2, 52)]   # 250 internal IPs

# External IPs – realistic public address spread
EXTERNAL_IPS = [
    "45.33.32.156",  "104.21.14.101", "172.67.75.22",  "185.220.101.35",
    "91.108.4.0",    "198.51.100.14", "203.0.113.77",  "8.8.8.8",
    "1.1.1.1",       "51.15.43.212",  "77.88.55.77",   "95.217.163.246",
    "188.166.2.31",  "54.93.218.204", "34.117.59.81",  "142.250.80.46",
    "13.32.99.221",  "23.94.54.22",   "192.241.213.5", "107.170.48.228",
    "210.140.92.183","91.92.251.103", "118.193.68.18", "162.55.32.109",
]

# Common service ports and their protocols / event types
SERVICE_MAP = {
    22:   ("TCP", "SSH"),
    80:   ("TCP", "HTTP"),
    443:  ("TCP", "HTTPS"),
    21:   ("TCP", "FTP"),
    53:   ("UDP", "DNS"),
    3389: ("TCP", "RDP"),
    8080: ("TCP", "HTTP"),
    8443: ("TCP", "HTTPS"),
    25:   ("TCP", "SMTP"),
    110:  ("TCP", "POP3"),
    143:  ("TCP", "IMAP"),
    3306: ("TCP", "MYSQL"),
    5432: ("TCP", "PGSQL"),
    6379: ("TCP", "REDIS"),
}
COMMON_PORTS = list(SERVICE_MAP.keys())

# Realistic usernames
USERNAMES = [
    "admin", "root", "ubuntu", "ec2-user", "deploy", "jenkins",
    "git",   "www-data", "postgres", "mysql",  "redis",  "nagios",
    "alice", "bob",    "carol",    "dave",    "eve",    "frank",
    "grace", "hank",   "iris",     "jack",
]

# Today's date anchor (midnight)
TODAY = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def rand_internal() -> str:
    """Return a random internal (192.168.x.x) IP address."""
    return random.choice(INTERNAL_HOSTS)


def rand_external() -> str:
    """Return a random external IP address."""
    return random.choice(EXTERNAL_IPS)


def rand_ts(start_offset_h: float = 0, window_h: float = 24) -> datetime:
    """Return a random datetime within [TODAY + start_offset_h, +window_h)."""
    base = TODAY + timedelta(hours=start_offset_h)
    return base + timedelta(seconds=random.uniform(0, window_h * 3600))


def rand_port_service():
    """Return (port, protocol, event_type) for a random common service."""
    port = random.choice(COMMON_PORTS)
    proto, etype = SERVICE_MAP[port]
    return port, proto, etype


def make_row(
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    user: str,
    event_type: str,
    status: str,
    bytes_: int,
    packets: int,
) -> dict:
    """Assemble a canonical event dictionary."""
    return {
        "timestamp":        ts.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":        src_ip,
        "destination_ip":   dst_ip,
        "source_port":      src_port,
        "destination_port": dst_port,
        "protocol":         protocol,
        "user":             user,
        "event_type":       event_type,
        "status":           status,
        "bytes":            bytes_,
        "packets":          packets,
    }


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------

def generate_normal_events(n: int = 500) -> list[dict]:
    """
    Generate *n* normal security events covering common services and mixed
    success/failure outcomes typical of a healthy enterprise network.

    Included event types
    --------------------
    * SSH logins          (port 22)
    * HTTP/HTTPS requests (ports 80, 443, 8080, 8443)
    * DNS queries         (port 53)
    * FTP connections     (port 21)
    * RDP sessions        (port 3389)
    * DB connections      (ports 3306, 5432, 6379)
    """
    rows = []
    for _ in range(n):
        ts       = rand_ts()                          # any time in the 24h window
        dst_port, proto, etype = rand_port_service()
        src_ip   = rand_internal()
        dst_ip   = rand_external() if random.random() < 0.6 else rand_internal()
        src_port = random.randint(1024, 65535)        # ephemeral source port
        user     = random.choice(USERNAMES)

        # Mostly successful; ~8 % failures
        status   = "success" if random.random() > 0.08 else "failed"

        # Byte/packet counts vary by service type
        if etype in ("DNS",):
            bytes_   = random.randint(64,  512)
            packets  = random.randint(1,   4)
        elif etype in ("HTTP", "HTTPS"):
            bytes_   = random.randint(512, 65_000)
            packets  = random.randint(5,   80)
        elif etype in ("SSH", "RDP"):
            bytes_   = random.randint(800, 8_000)
            packets  = random.randint(10,  60)
        elif etype in ("FTP",):
            bytes_   = random.randint(200, 120_000)
            packets  = random.randint(3,   150)
        else:
            bytes_   = random.randint(128, 4_096)
            packets  = random.randint(2,   30)

        rows.append(make_row(ts, src_ip, dst_ip, src_port, dst_port,
                             proto, user, etype, status, bytes_, packets))
    return rows


def generate_brute_force_events(n: int = 50) -> list[dict]:
    """
    Generate *n* brute-force SSH events from a single attacker IP.

    All events are concentrated within tight 5-minute bursts to ensure
    the `failed_login_count` feature fires above the detection threshold (≥5).
    Credentials are rotated to simulate a dictionary / credential-stuffing
    attack.
    """
    rows        = []
    attacker_ip = "185.220.101.35"   # known Tor exit node range
    target_ip   = rand_internal()
    burst_start = TODAY + timedelta(hours=random.uniform(1, 20))

    events_per_burst = 10            # 5 bursts × 10 events = 50 total
    num_bursts       = n // events_per_burst

    for burst in range(num_bursts):
        window_start = burst_start + timedelta(minutes=burst * 7)  # 7-min gap between bursts
        for i in range(events_per_burst):
            ts      = window_start + timedelta(seconds=random.uniform(0, 280))  # <5 min
            user    = random.choice(USERNAMES)
            status  = "failed" if i < events_per_burst - 1 else "success"      # last one succeeds
            bytes_  = random.randint(400, 900)
            packets = random.randint(6, 14)
            rows.append(make_row(
                ts, attacker_ip, target_ip,
                random.randint(40000, 60000), 22,
                "TCP", user, "SSH", status, bytes_, packets,
            ))
    return rows


def generate_port_scan_events(n: int = 30) -> list[dict]:
    """
    Generate *n* port-scan events from a single scanner IP.

    Events are packed into a single 1-minute window targeting 25+ distinct
    destination ports on the same victim host, ensuring the
    `unique_ports_per_ip` feature breaches the detection threshold (≥20).
    """
    scanner_ip  = "91.92.251.103"
    victim_ip   = rand_internal()
    scan_start  = TODAY + timedelta(hours=random.uniform(0, 22))

    # Generate 30 unique ports to scan (well-known + high ports)
    scan_ports  = random.sample(
        list(range(1, 1024)) + COMMON_PORTS + list(range(3000, 9000, 100)),
        k=n,
    )
    scan_ports  = list(dict.fromkeys(scan_ports))[:n]  # deduplicate, keep order

    rows = []
    for i, dst_port in enumerate(scan_ports):
        ts      = scan_start + timedelta(seconds=random.uniform(0, 55))   # within 1 min
        proto   = "TCP"
        etype   = "PORT_SCAN"
        status  = "rejected" if random.random() < 0.8 else "success"      # most ports closed
        bytes_  = random.randint(40, 120)      # tiny probe packets
        packets = random.randint(1, 3)
        rows.append(make_row(
            ts, scanner_ip, victim_ip,
            random.randint(40000, 65535), dst_port,
            proto, "unknown", etype, status, bytes_, packets,
        ))
    return rows


def generate_abnormal_traffic_events(n: int = 20) -> list[dict]:
    """
    Generate *n* abnormal-traffic events simulating data exfiltration.

    A single internal host transfers massive payloads (50 MB – 500 MB per
    burst) to an external server via HTTPS, producing extreme `bytes` and
    `packets` values that flag on the `bytes_per_source` feature.
    """
    exfil_src   = "192.168.3.99"
    exfil_dst   = "23.94.54.22"       # external C2-like host
    burst_start = TODAY + timedelta(hours=random.uniform(2, 4))   # early-morning

    rows = []
    for i in range(n):
        ts      = burst_start + timedelta(seconds=i * 15)   # one packet every ~15 s
        bytes_  = random.randint(2_500_000, 25_000_000)     # 2.5 MB – 25 MB per record
        packets = random.randint(1_800, 18_000)
        status  = "success"
        rows.append(make_row(
            ts, exfil_src, exfil_dst,
            random.randint(49152, 65535), 443,
            "TCP", "deploy", "HTTPS", status, bytes_, packets,
        ))
    return rows


def generate_ml_anomaly_events(n: int = 10) -> list[dict]:
    """
    Generate *n* ML-anomaly events with outlier combinations across all
    feature dimensions.

    Each event has an unusual multi-dimensional profile:
    * After-hours timestamp
    * Extremely high or low byte count for the protocol
    * Unusual source/destination port combination
    * Rare internal-to-internal communication pattern
    * Mixed success/failure to confuse simple rule engines
    """
    anomaly_ips = [
        "192.168.2.77",  "192.168.4.201",
    ]
    rows = []
    for i in range(n):
        # Force after-hours (22:00–05:59)
        hour_offset = random.choice(list(range(22, 24)) + list(range(0, 6)))
        ts = TODAY + timedelta(
            hours=hour_offset,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        src_ip  = random.choice(anomaly_ips)
        dst_ip  = random.choice(anomaly_ips)          # internal-to-internal
        # Unusual high port as destination (disguised C2 over non-standard port)
        dst_port = random.choice([4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345])
        src_port = random.randint(1024, 65535)
        # Byte volume is either extremely high OR suspiciously zero
        bytes_  = random.choice([
            0,
            random.randint(50_000_000, 200_000_000),  # 50–200 MB
        ])
        packets = random.randint(0, 5) if bytes_ == 0 else random.randint(40_000, 160_000)
        status  = random.choice(["success", "failed", "rejected"])
        proto   = random.choice(["TCP", "UDP"])
        etype   = "ANOMALY"
        user    = random.choice(["root", "admin", "unknown"])

        rows.append(make_row(ts, src_ip, dst_ip, src_port, dst_port,
                             proto, user, etype, status, bytes_, packets))
    return rows


# ---------------------------------------------------------------------------
# Main generation routine
# ---------------------------------------------------------------------------

def main():
    """
    Orchestrate synthetic data generation, assemble the master DataFrame,
    save output files, and print summary statistics.
    """
    print("=" * 65)
    print("  Cyber Threat Detection Dashboard – Demo Data Generator")
    print("=" * 65)

    # -- Generate each event class -----------------------------------------
    print("\n[1/6]  Generating 500 normal events …")
    normal_rows   = generate_normal_events(500)

    print("[2/6]  Generating  50 brute-force events …")
    bf_rows       = generate_brute_force_events(50)

    print("[3/6]  Generating  30 port-scan events …")
    scan_rows     = generate_port_scan_events(30)

    print("[4/6]  Generating  20 abnormal-traffic events …")
    abnormal_rows = generate_abnormal_traffic_events(20)

    print("[5/6]  Generating  10 ML-anomaly events …")
    anomaly_rows  = generate_ml_anomaly_events(10)

    # -- Combine and sort --------------------------------------------------
    all_rows = normal_rows + bf_rows + scan_rows + abnormal_rows + anomaly_rows
    df = pd.DataFrame(all_rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values("timestamp", inplace=True, ignore_index=True)

    # -- Resolve output paths relative to this file's location -------------
    here      = Path(__file__).parent          # data/
    csv_path  = here / "demo_security_logs.csv"
    json_path = here / "sample_events.json"

    print(f"[6/6]  Saving outputs …")
    df.to_csv(csv_path, index=False)
    print(f"        CSV  → {csv_path}  ({len(df)} rows)")

    # Sample: first 20 rows as JSON records
    sample = df.head(20).copy()
    sample["timestamp"] = sample["timestamp"].astype(str)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(sample.to_dict(orient="records"), fh, indent=2)
    print(f"        JSON → {json_path}  (20 records)")

    # -- Summary statistics ------------------------------------------------
    print("\n" + "=" * 65)
    print("  Summary Statistics")
    print("=" * 65)

    print(f"\n  Total events      : {len(df):,}")
    print(f"  Date range        : {df['timestamp'].min()}  →  {df['timestamp'].max()}")
    print(f"  Unique source IPs : {df['source_ip'].nunique()}")
    print(f"  Unique dest IPs   : {df['destination_ip'].nunique()}")

    print("\n  Event type breakdown:")
    et_counts = df["event_type"].value_counts()
    for etype, count in et_counts.items():
        print(f"    {etype:<15} {count:>5,}")

    print("\n  Status breakdown:")
    st_counts = df["status"].value_counts()
    for status, count in st_counts.items():
        print(f"    {status:<15} {count:>5,}")

    print("\n  Protocol breakdown:")
    pr_counts = df["protocol"].value_counts()
    for proto, count in pr_counts.items():
        print(f"    {proto:<10} {count:>5,}")

    print("\n  Bytes statistics:")
    print(f"    min     : {df['bytes'].min():>15,}")
    print(f"    max     : {df['bytes'].max():>15,}")
    print(f"    mean    : {df['bytes'].mean():>15,.1f}")
    print(f"    median  : {df['bytes'].median():>15,.1f}")
    print(f"    total   : {df['bytes'].sum():>15,}")

    print("\n  Top 5 source IPs by event count:")
    top_src = df["source_ip"].value_counts().head(5)
    for ip, count in top_src.items():
        print(f"    {ip:<22} {count:>5,} events")

    print("\n  Top 5 destination ports:")
    top_ports = df["destination_port"].value_counts().head(5)
    for port, count in top_ports.items():
        print(f"    port {port:<10} {count:>5,} events")

    print("\n" + "=" * 65)
    print("  Done!  Demo data ready for the dashboard.")
    print("=" * 65 + "\n")

    return df


if __name__ == "__main__":
    main()
