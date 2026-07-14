import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass

MAGIC_HEADER = b"\xff" * 6
MAGIC_SIZE = 102

# Listening and sending on different ports is deliberate: a relay that listens
# where it sends would receive its own packets and trigger itself in a loop.
# 9 is where WoL listeners conventionally wait; 47009 is unprivileged and
# already targeted by many senders.
LISTEN_PORT = 47009
SEND_PORT = 9


def normalize_mac(mac):
    cleaned = mac.strip().replace(":", "").replace("-", "").lower()
    if len(cleaned) != 12 or not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"not a valid MAC address: {mac!r}")
    return cleaned


def parse_mac_list(raw):
    return frozenset(normalize_mac(part) for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Config:
    host: str
    host_mac: str
    relay_macs: frozenset
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
        object.__setattr__(self, "relay_macs", frozenset(normalize_mac(m) for m in self.relay_macs))
        if not self.relay_macs:
            raise ValueError("RELAY_MACS must not be empty")
        if self.host_mac in self.relay_macs:
            raise ValueError("HOST_MAC must not appear in RELAY_MACS - that would be a loop")

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(
            host=env["HOST"],
            host_mac=env["HOST_MAC"],
            relay_macs=parse_mac_list(env["RELAY_MACS"]),
            broadcast=env.get("BROADCAST", "255.255.255.255"),
            host_port=int(env.get("HOST_PORT", 8006)),
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


def alive(host, port, timeout=2):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


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


def relay(mac, cfg, sleep=time.sleep):
    """Wakes the host, then replays the magic packet once it is listening.

    If the host is already up, its own listener saw the original packet -
    there is nothing to relay.
    """
    if alive(cfg.host, cfg.host_port):
        log("host already up - its listener takes over")
        return False
    if not wake_host(cfg, sleep):
        return False
    log(f"replaying magic packet for {mac}")
    send_wol(mac, cfg.broadcast)
    return True


def should_relay(data, cfg):
    mac = parse_magic_packet(data)
    if mac is None or mac not in cfg.relay_macs:
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
    log(f"wol-relay listening on udp/{cfg.listen_port} for {', '.join(sorted(cfg.relay_macs))}")
    listen(cfg, sock, running,
           lambda mac: threading.Thread(target=run, args=(mac,), daemon=True).start())


if __name__ == "__main__":
    main()
