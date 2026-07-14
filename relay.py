import ipaddress
import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

MAGIC_HEADER = b"\xff" * 6
MAGIC_SIZE = 102

# 9 is where WoL senders and listeners conventionally meet, so that is where we
# do both. Our own packets cannot trigger us: HOST_MAC is barred from
# RELAY_MACS, and a replay only goes out once the host is up - at which point
# relay() exits immediately.
LISTEN_PORT = 9
SEND_PORT = 9

# Written instead of a port number to check reachability by ping.
PING = "icmp"


def normalize_mac(mac):
    cleaned = mac.strip().replace(":", "").replace("-", "").lower()
    if len(cleaned) != 12 or not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"not a valid MAC address: {mac!r}")
    return cleaned


def parse_port(raw, field):
    """A TCP port number, or None for "icmp" meaning ping."""
    cleaned = raw.strip().lower()
    if cleaned == PING:
        return None
    if cleaned.isdigit() and 0 < int(cleaned) < 65536:
        return int(cleaned)
    raise ValueError(f"{field} must be a port number or '{PING}': {raw!r}")


def parse_targets(raw):
    """Parses "MAC=HOST:PORT,..." into {mac: (host, port)}, port None for ping.

    Splitting on "=" first is safe: a MAC never contains one.
    """
    targets = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        mac, sep, address = part.partition("=")
        if not sep:
            raise ValueError(f"RELAY_MACS entry must be MAC=HOST:PORT: {part!r}")
        host, sep, port = address.rpartition(":")
        if not sep or not host:
            raise ValueError(f"RELAY_MACS entry must be MAC=HOST:PORT: {part!r}")
        targets[normalize_mac(mac)] = (host, parse_port(port, "RELAY_MACS"))
    return targets


@dataclass(frozen=True)
class Config:
    host: str
    host_mac: str
    targets: dict
    broadcast: str = "255.255.255.255"
    host_port: int = 8006
    listen_port: int = LISTEN_PORT
    retry_every: int = 15
    max_retries: int = 20
    cooldown: int = 60

    def __post_init__(self):
        try:
            ipaddress.IPv4Address(self.broadcast)
        except ValueError:
            raise ValueError(f"BROADCAST must be an IPv4 address: {self.broadcast!r}") from None
        object.__setattr__(self, "host_mac", normalize_mac(self.host_mac))
        object.__setattr__(
            self, "targets", {normalize_mac(m): t for m, t in self.targets.items()}
        )
        if not self.targets:
            raise ValueError("RELAY_MACS must not be empty")
        if self.host_mac in self.targets:
            raise ValueError("HOST_MAC must not appear in RELAY_MACS - that would be a loop")

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(
            host=env["HOST"],
            host_mac=env["HOST_MAC"],
            targets=parse_targets(env["RELAY_MACS"]),
            broadcast=env.get("BROADCAST", "255.255.255.255"),
            host_port=parse_port(env.get("HOST_PORT", "8006"), "HOST_PORT"),
            listen_port=int(env.get("LISTEN_PORT", LISTEN_PORT)),
            retry_every=int(env.get("RETRY_EVERY", 15)),
            max_retries=int(env.get("MAX_RETRIES", 20)),
            cooldown=int(env.get("COOLDOWN", 60)),
        )


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def magic_packet(mac):
    return MAGIC_HEADER + bytes.fromhex(normalize_mac(mac)) * 16


def parse_magic_packet(data):
    """Returns the MAC a magic packet addresses, or None."""
    if len(data) < MAGIC_SIZE or not data.startswith(MAGIC_HEADER):
        return None
    mac = data[6:12]
    if data[6:MAGIC_SIZE] != mac * 16:
        return None
    return mac.hex()


def send_wol(mac, broadcast):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.sendto(magic_packet(mac), (broadcast, SEND_PORT))
    finally:
        sock.close()


def ping(host, timeout=2):
    """Shells out to the system ping - needs NET_RAW in a container."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def alive(host, port, timeout=2):
    """Is host reachable? port None means ping instead of a TCP connect."""
    if port is None:
        return ping(host, timeout)
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def describe(host, port):
    return f"{host}/{PING}" if port is None else f"{host}:{port}"


def wake_host(cfg, sleep=time.sleep):
    for attempt in range(1, cfg.max_retries + 1):
        log(f"host: magic packet to {cfg.host_mac} ({attempt}/{cfg.max_retries})")
        send_wol(cfg.host_mac, cfg.broadcast)
        sleep(cfg.retry_every)
        if alive(cfg.host, cfg.host_port):
            log("host is up")
            return True
    log(f"host unreachable after {cfg.max_retries} attempts - giving up")
    return False


def wake_device(mac, cfg, sleep=time.sleep):
    """Replays the magic packet until the device answers.

    One replay is not enough: HOST_PORT answering only proves the host is
    reachable, not that its WoL listener is running yet - that usually starts
    later in the boot, and a packet nobody listens for is lost. Rather than
    guess how long that takes, keep replaying until the device is up.
    """
    host, port = cfg.targets[mac]
    if alive(host, port):
        log(f"{mac} ({describe(host, port)}) already up")
        return True
    for attempt in range(1, cfg.max_retries + 1):
        log(f"{mac}: replaying magic packet ({attempt}/{cfg.max_retries})")
        send_wol(mac, cfg.broadcast)
        sleep(cfg.retry_every)
        if alive(host, port):
            log(f"{mac} is up")
            return True
    log(f"{mac} unreachable after {cfg.max_retries} attempts - giving up")
    return False


def relay(mac, cfg, sleep=time.sleep):
    """Wakes the host, then replays the magic packet until the device is up.

    If the host is already up, its own listener saw the original packet -
    there is nothing to relay.
    """
    if alive(cfg.host, cfg.host_port):
        log("host already up - its listener takes over")
        return False
    if not wake_host(cfg, sleep):
        return False
    return wake_device(mac, cfg, sleep)


def should_relay(data, cfg):
    mac = parse_magic_packet(data)
    if mac is None or mac not in cfg.targets:
        return None
    return mac


def listen(cfg, sock, running, spawn):
    while True:
        data, sender = sock.recvfrom(2048)
        mac = should_relay(data, cfg)
        if mac is None:
            continue
        if running.is_set():
            log(f"magic packet for {mac} from {sender[0]} - already relaying")
            continue
        running.set()
        log(f"magic packet for {mac} from {sender[0]}")
        spawn(mac)


def main():
    cfg = Config.from_env()
    running = threading.Event()

    def run(mac):
        try:
            relay(mac, cfg)
        finally:
            time.sleep(cfg.cooldown)
            running.clear()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", cfg.listen_port))
    log(f"wol-relay listening on udp/{cfg.listen_port}, host {describe(cfg.host, cfg.host_port)}")
    for mac, (host, port) in sorted(cfg.targets.items()):
        log(f"  {mac} -> {describe(host, port)}")
    listen(cfg, sock, running,
           lambda mac: threading.Thread(target=run, args=(mac,), daemon=True).start())


if __name__ == "__main__":
    main()
