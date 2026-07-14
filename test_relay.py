import threading

import pytest

import relay
from relay import Config

HOST_MAC = "aa:00:00:00:00:01"
DEVICE_MAC = "bb:00:00:00:00:01"
DEVICE2_MAC = "bb:00:00:00:00:02"
UNLISTED_MAC = "cc:00:00:00:00:01"

DEVICE_ADDR = ("192.0.2.40", 22)
DEVICE2_ADDR = ("192.0.2.41", 22)

# Normalised form, as parse_magic_packet hands it to the relay internals.
DEVICE = "bb0000000001"
DEVICE2 = "bb0000000002"


@pytest.fixture
def cfg():
    return Config(
        host="host.example.com",
        host_mac=HOST_MAC,
        targets={DEVICE_MAC: DEVICE_ADDR, DEVICE2_MAC: DEVICE2_ADDR},
        broadcast="192.0.2.255",
        retry_every=0,
        max_retries=5,
        cooldown=0,
    )


def wol(mac):
    return relay.magic_packet(mac)


def address_of(mac, cfg):
    """Where a given MAC is expected to answer once it is awake."""
    return cfg.host if mac == cfg.host_mac else cfg.targets[mac][0]


class TestMagicPacket:
    def test_matches_spec(self):
        """A magic packet is FF*6 followed by the MAC 16 times."""
        pkt = wol(DEVICE_MAC)
        assert len(pkt) == 102
        assert pkt[:6] == b"\xff" * 6
        assert pkt[6:] == bytes.fromhex("bb0000000001") * 16

    def test_mac_notation_is_irrelevant(self):
        assert wol("AA:BB:CC:DD:EE:FF") == wol("aa-bb-cc-dd-ee-ff") == wol("aabbccddeeff")

    def test_rejects_garbage_mac(self):
        with pytest.raises(ValueError, match="MAC"):
            relay.magic_packet("not-a-mac")


class TestParseMagicPacket:
    def test_roundtrip(self):
        assert relay.parse_magic_packet(wol(DEVICE_MAC)) == "bb0000000001"

    def test_ignores_short_datagram(self):
        assert relay.parse_magic_packet(b"\xff" * 6) is None

    def test_ignores_missing_header(self):
        assert relay.parse_magic_packet(b"\x00" * 102) is None

    def test_ignores_inconsistent_repetition(self):
        broken = b"\xff" * 6 + bytes.fromhex("bb0000000001") * 15 + b"\x00" * 6
        assert relay.parse_magic_packet(broken) is None

    def test_tolerates_secureon_suffix(self):
        """Some senders append a SecureOn password."""
        assert relay.parse_magic_packet(wol(DEVICE_MAC) + b"\x01" * 6) == "bb0000000001"


class TestParsePort:
    def test_number(self):
        assert relay.parse_port("22", "X") == 22

    def test_icmp_means_ping(self):
        assert relay.parse_port("icmp", "X") is None

    def test_icmp_is_case_insensitive(self):
        assert relay.parse_port("ICMP", "X") is None

    @pytest.mark.parametrize("bad", ["ssh", "0", "65536", "-1", "22.5", ""])
    def test_rejects_nonsense(self, bad):
        with pytest.raises(ValueError, match="port number or 'icmp'"):
            relay.parse_port(bad, "X")


class TestParseTargets:
    def test_single_entry(self):
        assert relay.parse_targets("BB:00:00:00:00:01=192.0.2.40:22") == {
            "bb0000000001": ("192.0.2.40", 22)
        }

    def test_icmp_entry(self):
        assert relay.parse_targets("BB:00:00:00:00:01=192.0.2.40:icmp") == {
            "bb0000000001": ("192.0.2.40", None)
        }

    def test_mixed_entries_and_notations(self):
        raw = "BB:00:00:00:00:01=192.0.2.40:icmp, bb-00-00-00-00-02=host.example.com:47989"
        assert relay.parse_targets(raw) == {
            "bb0000000001": ("192.0.2.40", None),
            "bb0000000002": ("host.example.com", 47989),
        }

    def test_tolerates_trailing_comma(self):
        assert relay.parse_targets("BB:00:00:00:00:01=192.0.2.40:22,") == {
            "bb0000000001": ("192.0.2.40", 22)
        }

    def test_rejects_missing_address(self):
        with pytest.raises(ValueError, match="MAC=HOST:PORT"):
            relay.parse_targets("BB:00:00:00:00:01")

    def test_rejects_missing_port(self):
        with pytest.raises(ValueError, match="MAC=HOST:PORT"):
            relay.parse_targets("BB:00:00:00:00:01=192.0.2.40")

    def test_rejects_non_numeric_port(self):
        with pytest.raises(ValueError, match="port number or 'icmp'"):
            relay.parse_targets("BB:00:00:00:00:01=192.0.2.40:ssh")


class TestAlive:
    def test_port_uses_tcp_connect(self, monkeypatch):
        seen = []
        monkeypatch.setattr(relay.socket, "create_connection",
                            lambda addr, timeout: seen.append(addr) or _Closable())
        monkeypatch.setattr(relay, "ping", lambda h, t=2: pytest.fail("must not ping"))
        assert relay.alive("192.0.2.40", 22) is True
        assert seen == [("192.0.2.40", 22)]

    def test_none_port_uses_ping(self, monkeypatch):
        seen = []
        monkeypatch.setattr(relay.socket, "create_connection",
                            lambda *a, **k: pytest.fail("must not open a socket"))
        monkeypatch.setattr(relay, "ping", lambda h, t=2: seen.append(h) or True)
        assert relay.alive("192.0.2.40", None) is True
        assert seen == ["192.0.2.40"]

    def test_tcp_failure_is_not_alive(self, monkeypatch):
        monkeypatch.setattr(relay.socket, "create_connection",
                            lambda *a, **k: (_ for _ in ()).throw(OSError()))
        assert relay.alive("192.0.2.40", 22) is False


class _Closable:
    def close(self):
        pass


class TestPing:
    def test_returncode_zero_is_up(self, monkeypatch):
        monkeypatch.setattr(relay.subprocess, "run", lambda *a, **k: _Result(0))
        assert relay.ping("192.0.2.40") is True

    def test_returncode_nonzero_is_down(self, monkeypatch):
        monkeypatch.setattr(relay.subprocess, "run", lambda *a, **k: _Result(1))
        assert relay.ping("192.0.2.40") is False

    def test_missing_ping_binary_is_down(self, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError("ping")
        monkeypatch.setattr(relay.subprocess, "run", boom)
        assert relay.ping("192.0.2.40") is False

    def test_hanging_ping_is_down(self, monkeypatch):
        def boom(*a, **k):
            raise relay.subprocess.TimeoutExpired("ping", 4)
        monkeypatch.setattr(relay.subprocess, "run", boom)
        assert relay.ping("192.0.2.40") is False


class _Result:
    def __init__(self, returncode):
        self.returncode = returncode


class TestShouldRelay:
    def test_packet_for_listed_device(self, cfg):
        assert relay.should_relay(wol(DEVICE_MAC), cfg) == "bb0000000001"

    def test_packet_for_second_listed_device(self, cfg):
        assert relay.should_relay(wol(DEVICE2_MAC), cfg) == "bb0000000002"

    def test_uppercase_mac_from_sender(self, cfg):
        assert relay.should_relay(wol("BB:00:00:00:00:01"), cfg) is not None

    def test_ignores_unlisted_device(self, cfg):
        assert relay.should_relay(wol(UNLISTED_MAC), cfg) is None

    def test_ignores_own_host_packet(self, cfg):
        """Our own wake packet must not trigger us."""
        assert relay.should_relay(wol(HOST_MAC), cfg) is None

    def test_ignores_non_wol_traffic(self, cfg):
        assert relay.should_relay(b"some other udp datagram", cfg) is None


class TestWakeDevice:
    def test_already_up_sends_nothing(self, cfg, monkeypatch):
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: True)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.wake_device(DEVICE, cfg) is True
        assert sent == []

    def test_keeps_replaying_until_device_answers(self, cfg, monkeypatch):
        """HOST_PORT answering does not mean the host's WoL listener is up yet."""
        sent = []
        checks = {"n": 0}

        def alive(host, port):
            checks["n"] += 1
            return checks["n"] > 4      # up on the 5th check: 1 upfront + 3 replays

        monkeypatch.setattr(relay, "alive", alive)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.wake_device(DEVICE, cfg) is True
        assert sent == [DEVICE] * 4, "replay until it answers, then stop"

    def test_gives_up_after_max_retries(self, cfg, monkeypatch):
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: False)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.wake_device(DEVICE, cfg) is False
        assert len(sent) == cfg.max_retries

    def test_checks_the_devices_own_address(self, cfg, monkeypatch):
        seen = []
        monkeypatch.setattr(relay, "alive", lambda h, p: seen.append((h, p)) or True)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: None)
        relay.wake_device(DEVICE2, cfg)
        assert seen == [DEVICE2_ADDR]


class TestRelay:
    def test_does_nothing_when_host_is_up(self, cfg, monkeypatch):
        """The host's own listener already saw the original packet."""
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: True)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.relay(DEVICE_MAC, cfg) is False
        assert sent == []

    def test_wakes_host_then_device(self, cfg, monkeypatch):
        sent = []
        up = set()

        def send_wol(mac, broadcast):
            sent.append(mac)
            up.add(address_of(mac, cfg))

        monkeypatch.setattr(relay, "alive", lambda h, p: h in up)
        monkeypatch.setattr(relay, "send_wol", send_wol)
        assert relay.relay("bb0000000001", cfg) is True
        assert sent == [cfg.host_mac, "bb0000000001"], "host first, then device"

    def test_wakes_the_mac_that_was_asked_for(self, cfg, monkeypatch):
        sent = []
        up = set()
        monkeypatch.setattr(relay, "alive", lambda h, p: h in up)
        monkeypatch.setattr(
            relay, "send_wol",
            lambda m, b: (sent.append(m), up.add(address_of(m, cfg))),
        )
        relay.relay("bb0000000002", cfg)
        assert sent[-1] == "bb0000000002"

    def test_no_device_packet_when_host_never_wakes(self, cfg, monkeypatch):
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: False)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.relay(DEVICE_MAC, cfg) is False
        assert sent == [cfg.host_mac] * cfg.max_retries, "device packet must not go out"


class TestListen:
    def sock(self, *datagrams):
        queue = list(datagrams)

        class FakeSock:
            def recvfrom(self, _):
                if not queue:
                    raise StopIteration
                return queue.pop(0), ("192.0.2.77", 54321)

        return FakeSock()

    def test_passes_mac_to_sequence(self, cfg):
        seen = []
        with pytest.raises(StopIteration):
            relay.listen(cfg, self.sock(wol(DEVICE2_MAC)), threading.Event(), seen.append)
        assert seen == ["bb0000000002"]

    def test_ignores_repeat_while_relaying(self, cfg):
        seen = []
        with pytest.raises(StopIteration):
            relay.listen(cfg, self.sock(wol(DEVICE_MAC), wol(DEVICE_MAC), wol(DEVICE_MAC)),
                         threading.Event(), seen.append)
        assert len(seen) == 1

    def test_foreign_packets_do_not_spawn(self, cfg):
        seen = []
        with pytest.raises(StopIteration):
            relay.listen(cfg, self.sock(wol(UNLISTED_MAC), b"noise", wol(HOST_MAC)),
                         threading.Event(), seen.append)
        assert seen == []

    def test_our_own_replay_cannot_loop(self, cfg, monkeypatch):
        """We listen and send on port 9, so our replay comes straight back.

        It cannot loop: a replay only goes out once the host is up, and relay()
        exits immediately while the host is up.
        """
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: True)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.relay(DEVICE_MAC, cfg) is False
        assert sent == [], "a trigger while the host is up must send nothing"


class TestConfig:
    def env(self, **overrides):
        base = {
            "HOST": "host.example.com",
            "HOST_MAC": "AA:00:00:00:00:01",
            "RELAY_MACS": "BB:00:00:00:00:01=192.0.2.40:22",
        }
        return {**base, **overrides}

    def test_defaults(self):
        cfg = Config.from_env(self.env())
        assert cfg.listen_port == 9, "port 9 is where WoL senders actually send"
        assert cfg.host_port == 8006
        assert cfg.max_retries == 20

    def test_host_port_accepts_icmp(self):
        assert Config.from_env(self.env(HOST_PORT="icmp")).host_port is None

    def test_host_port_rejects_nonsense(self):
        with pytest.raises(ValueError, match="HOST_PORT"):
            Config.from_env(self.env(HOST_PORT="https"))

    def test_listen_port_can_be_overridden(self):
        assert Config.from_env(self.env(LISTEN_PORT="47009")).listen_port == 47009

    def test_broadcast_defaults_to_limited_broadcast(self):
        assert Config.from_env(self.env()).broadcast == "255.255.255.255"

    def test_broadcast_can_be_overridden(self):
        assert Config.from_env(self.env(BROADCAST="192.0.2.255")).broadcast == "192.0.2.255"

    def test_parses_target_mapping(self):
        cfg = Config.from_env(
            self.env(RELAY_MACS="BB:00:00:00:00:01=192.0.2.40:22, bb-00-00-00-00-02=192.0.2.41:22")
        )
        assert cfg.targets == {
            "bb0000000001": ("192.0.2.40", 22),
            "bb0000000002": ("192.0.2.41", 22),
        }

    def test_host_may_be_a_name(self):
        """HOST is only ever resolved for the health check."""
        assert Config.from_env(self.env()).host == "host.example.com"

    def test_missing_value_fails_loudly(self):
        with pytest.raises(KeyError):
            Config.from_env({"HOST": "host.example.com"})

    def test_empty_relay_macs_rejected(self):
        with pytest.raises(ValueError, match="RELAY_MACS"):
            Config.from_env(self.env(RELAY_MACS=""))

    def test_host_mac_in_relay_list_rejected(self):
        """Otherwise our own wake packet would trigger us endlessly."""
        with pytest.raises(ValueError, match="loop"):
            Config.from_env(self.env(RELAY_MACS="AA:00:00:00:00:01=192.0.2.10:22"))

    def test_broadcast_rejects_hostname(self):
        with pytest.raises(ValueError, match="BROADCAST"):
            Config.from_env(self.env(BROADCAST="broadcast.local"))

    def test_bad_mac_fails_loudly(self):
        with pytest.raises(ValueError, match="MAC"):
            Config.from_env(self.env(RELAY_MACS="BB:00:00:00:00=192.0.2.40:22"))
