"""
data/log_generator.py
----------------------
Generates realistic synthetic network logs for testing.
Simulates both normal traffic and 6 attack types.

Used when you don't have real network logs — lets you
demo and test the entire system immediately.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random
import ipaddress

np.random.seed(42)
random.seed(42)

# Internal IP ranges (your network)
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 50)]
INTERNAL_SERVERS = [f"10.0.0.{i}" for i in [10, 20, 30, 50, 100]]

# External IPs (internet)
EXTERNAL_IPS = [f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                for _ in range(200)]

# Known malicious IPs (for demo purposes)
MALICIOUS_IPS = ["185.220.101.45", "23.129.64.214", "162.247.74.27",
                 "199.87.154.255", "178.73.215.171"]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = [22, 80, 443, 3389, 445, 3306, 5432, 8080, 8443, 25, 53, 21]


def generate_normal_traffic(n_events: int = 5000, start_time: datetime = None) -> pd.DataFrame:
    """Generate baseline normal network traffic."""
    if start_time is None:
        start_time = datetime.now() - timedelta(hours=24)

    records = []
    for i in range(n_events):
        ts = start_time + timedelta(seconds=i * 0.5 + np.random.exponential(0.3))
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(INTERNAL_SERVERS + EXTERNAL_IPS[:50])
        records.append({
            "timestamp":  ts,
            "src_ip":     src,
            "dst_ip":     dst,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   random.choice(COMMON_PORTS),
            "protocol":   random.choice(PROTOCOLS),
            "bytes_sent": int(np.random.lognormal(8, 1.5)),
            "bytes_recv": int(np.random.lognormal(10, 2)),
            "packets":    random.randint(3, 50),
            "duration":   round(np.random.exponential(2.0), 3),
            "success":    1 if random.random() > 0.05 else 0,
            "label":      "normal",
        })
    return pd.DataFrame(records)


def generate_port_scan(src_ip: str = None, start_time: datetime = None, n_ports: int = 500) -> pd.DataFrame:
    """Simulate a port scan: one IP probing hundreds of ports."""
    src_ip = src_ip or random.choice(MALICIOUS_IPS)
    dst_ip = random.choice(INTERNAL_SERVERS)
    start_time = start_time or datetime.now()

    records = []
    for i in range(n_ports):
        records.append({
            "timestamp":  start_time + timedelta(milliseconds=i * 60),
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   i + 1,
            "protocol":   "TCP",
            "bytes_sent": 60,
            "bytes_recv": 0,
            "packets":    1,
            "duration":   0.001,
            "success":    0,
            "label":      "port_scan",
        })
    return pd.DataFrame(records)


def generate_brute_force(src_ip: str = None, start_time: datetime = None, n_attempts: int = 300) -> pd.DataFrame:
    """Simulate SSH brute force: many failed login attempts."""
    src_ip = src_ip or random.choice(MALICIOUS_IPS)
    dst_ip = random.choice(INTERNAL_SERVERS)
    start_time = start_time or datetime.now()

    records = []
    for i in range(n_attempts):
        success = 1 if i == n_attempts - 1 and random.random() > 0.7 else 0
        records.append({
            "timestamp":  start_time + timedelta(seconds=i * 0.2),
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   22,
            "protocol":   "TCP",
            "bytes_sent": 100,
            "bytes_recv": 50 if success else 20,
            "packets":    3,
            "duration":   0.05,
            "success":    success,
            "label":      "brute_force",
        })
    return pd.DataFrame(records)


def generate_data_exfiltration(src_ip: str = None, start_time: datetime = None) -> pd.DataFrame:
    """Simulate data exfiltration: large outbound transfers."""
    src_ip = src_ip or random.choice(INTERNAL_IPS)
    dst_ip = random.choice(MALICIOUS_IPS)
    start_time = start_time or datetime.now()

    records = []
    for i in range(50):
        records.append({
            "timestamp":  start_time + timedelta(seconds=i * 5),
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   443,
            "protocol":   "TCP",
            "bytes_sent": random.randint(500_000, 2_000_000),
            "bytes_recv": random.randint(100, 500),
            "packets":    random.randint(500, 2000),
            "duration":   round(random.uniform(5, 15), 2),
            "success":    1,
            "label":      "data_exfil",
        })
    return pd.DataFrame(records)


def generate_lateral_movement(src_ip: str = None, start_time: datetime = None) -> pd.DataFrame:
    """Simulate lateral movement: connecting to many internal hosts."""
    src_ip = src_ip or random.choice(INTERNAL_IPS)
    start_time = start_time or datetime.now()

    records = []
    targets = random.sample(INTERNAL_IPS + INTERNAL_SERVERS, 30)
    for i, dst_ip in enumerate(targets):
        for port in [445, 3389, 22, 135]:
            records.append({
                "timestamp":  start_time + timedelta(seconds=i * 3),
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "src_port":   random.randint(1024, 65535),
                "dst_port":   port,
                "protocol":   "TCP",
                "bytes_sent": random.randint(200, 1000),
                "bytes_recv": random.randint(100, 500),
                "packets":    random.randint(3, 15),
                "duration":   round(random.uniform(0.1, 2.0), 3),
                "success":    1 if random.random() > 0.3 else 0,
                "label":      "lateral_movement",
            })
    return pd.DataFrame(records)


def generate_c2_beacon(src_ip: str = None, start_time: datetime = None, n_beacons: int = 40) -> pd.DataFrame:
    """Simulate C2 beacon: regular check-ins at fixed intervals."""
    src_ip = src_ip or random.choice(INTERNAL_IPS)
    dst_ip = random.choice(MALICIOUS_IPS)
    start_time = start_time or datetime.now()
    interval = 300  # every 5 minutes exactly

    records = []
    for i in range(n_beacons):
        # Very consistent timing = suspicious
        jitter = np.random.normal(0, 2)
        records.append({
            "timestamp":  start_time + timedelta(seconds=i * interval + jitter),
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   443,
            "protocol":   "TCP",
            "bytes_sent": random.randint(80, 120),
            "bytes_recv": random.randint(40, 80),
            "packets":    3,
            "duration":   round(random.uniform(0.05, 0.15), 3),
            "success":    1,
            "label":      "c2_beacon",
        })
    return pd.DataFrame(records)


def generate_full_dataset(
    n_normal: int = 8000,
    include_attacks: bool = True,
    save_path: str = "logs_sample/network_logs.csv"
) -> pd.DataFrame:
    """
    Generate a complete dataset with normal traffic and attack scenarios.
    Saves to CSV for use in training and testing.
    """
    print("[Generator] Creating normal baseline traffic...")
    dfs = [generate_normal_traffic(n_normal)]

    if include_attacks:
        attack_time = datetime.now() - timedelta(hours=2)
        print("[Generator] Injecting attack scenarios...")

        dfs.append(generate_port_scan(start_time=attack_time))
        dfs.append(generate_brute_force(start_time=attack_time + timedelta(minutes=35)))
        dfs.append(generate_data_exfiltration(start_time=attack_time + timedelta(minutes=70)))
        dfs.append(generate_lateral_movement(start_time=attack_time + timedelta(minutes=100)))
        dfs.append(generate_c2_beacon(start_time=attack_time + timedelta(minutes=130)))

    df = pd.concat(dfs, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    df.to_csv(save_path, index=False)
    print(f"[Generator] Saved {len(df)} events → {save_path}")
    print(f"  Normal: {(df['label']=='normal').sum()}")
    print(f"  Attacks: {(df['label']!='normal').sum()}")
    return df


if __name__ == "__main__":
    generate_full_dataset()
