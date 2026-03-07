"""WARP endpoint scanning with latency measurement."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import random
import socket
import time
from typing import TypedDict

import structlog

from app.config import settings

logger = structlog.get_logger()


class ScanResult(TypedDict):
    ip: str
    latency_ms: float


def probe_udp(ip: str, port: int, timeout: float = 1.0) -> ScanResult | None:
    """Probe a single IP via UDP. Returns result with latency or None."""
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(b"\x00")
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return ScanResult(ip=ip, latency_ms=latency_ms)
    except Exception:
        return None


def get_random_warp_ips(count: int = 20) -> list[str]:
    """Generate random IPs from known WARP CIDR ranges."""
    candidates: list[str] = []
    for _ in range(count):
        cidr = random.choice(settings.warp_cidrs)
        net = ipaddress.ip_network(cidr)
        ip = str(net.network_address + random.randint(1, net.num_addresses - 2))
        candidates.append(ip)
    return candidates


def smart_scan(port: int = 500, timeout: float = 0.8) -> str:
    """Find the first reachable WARP IP. Returns IP string."""
    candidates = settings.known_warp_ips[:3] + get_random_warp_ips(25)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(probe_udp, ip, port, timeout): ip
            for ip in candidates
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result is not None:
                logger.info("smart_scan_hit", ip=result["ip"], latency_ms=result["latency_ms"])
                return result["ip"]

    logger.warning("smart_scan_fallback", fallback_ip=settings.known_warp_ips[0])
    return settings.known_warp_ips[0]


def scan_all_working(port: int = 500, timeout: float = 1.2) -> list[ScanResult]:
    """Find all reachable WARP IPs with latency. Sorted fastest-first."""
    candidates = settings.known_warp_ips + get_random_warp_ips(30)

    working: list[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_ip = {
            executor.submit(probe_udp, ip, port, timeout): ip
            for ip in candidates
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result is not None:
                working.append(result)

    working.sort(key=lambda r: r["latency_ms"])
    logger.info("scan_complete", found=len(working), probed=len(candidates))
    return working
