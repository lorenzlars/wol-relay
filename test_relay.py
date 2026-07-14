import threading

import pytest

import relay
from relay import Config

HOST_MAC = "aa:00:00:00:00:01"
DEVICE_MAC = "bb:00:00:00:00:01"
DEVICE2_MAC = "bb:00:00:00:00:02"
UNLISTED_MAC = "cc:00:00:00:00:01"


@pytest.fixture
def cfg():
    return Config(
        host="host.example.com",
        host_mac=HOST_MAC,
        relay_macs=frozenset({DEVICE_MAC, DEVICE2_MAC}),
        broadcast="192.0.2.255",
        retry_every=0,
        max_retries=5,
        cooldown=0,
    )


def wol(mac):
    return relay.magic_packet(mac)


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


class TestRelay:
    def test_does_nothing_when_host_is_up(self, cfg, monkeypatch):
        """The host's own listener already saw the original packet."""
        sent = []
        monkeypatch.setattr(relay, "alive", lambda h, p: True)
        monkeypatch.setattr(relay, "send_wol", lambda m, b: sent.append(m))
        assert relay.relay(DEVICE_MAC, cfg) is False
        assert sent == []

    def test_wakes_host_then_replays_packet(self, cfg, monkeypatch):
        sent = []
        up = {"yes": False}

        def send_wol(mac, broadcast):
            sent.append(mac)
            if mac == cfg.host_mac:
                up["yes"] = True

        monkeypatch.setattr(relay, "alive", lambda h, p: up["yes"])
        monkeypatch.setattr(relay, "send_wol", send_wol)
        assert relay.relay("bb0000000001", cfg) is True
        assert sent == [cfg.host_mac, "bb0000000001"], "host first, then replay"

    def test_replays_the_mac_that_was_asked_for(self, cfg, monkeypatch):
        sent = []
        up = {"yes": False}
        monkeypatch.setattr(relay, "alive", lambda h, p: up["yes"])
        monkeypatch.setattr(
            relay, "send_wol",
            lambda m, b: (sent.append(m), up.__setitem__("yes", True)),
        )
        relay.relay("bb0000000002", cfg)
        assert sent[-1] == "bb0000000002"

    def test_gives_up_after_max_retries(self, cfg, monkeypatch):
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
                return queue.pop(0), ("192.0.2.77", 47009)

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


class TestConfig:
    def env(self, **overrides):
        base = {
            "HOST": "host.example.com",
            "HOST_MAC": "AA:00:00:00:00:01",
            "RELAY_MACS": "BB:00:00:00:00:01",
        }
        return {**base, **overrides}

    def test_defaults(self):
        cfg = Config.from_env(self.env())
        assert cfg.listen_port == 47009
        assert cfg.host_port == 8006
        assert cfg.max_retries == 20

    def test_broadcast_defaults_to_limited_broadcast(self):
        assert Config.from_env(self.env()).broadcast == "255.255.255.255"

    def test_broadcast_can_be_overridden(self):
        assert Config.from_env(self.env(BROADCAST="192.0.2.255")).broadcast == "192.0.2.255"

    def test_parses_mac_list(self):
        cfg = Config.from_env(self.env(RELAY_MACS="BB:00:00:00:00:01, bb-00-00-00-00-02"))
        assert cfg.relay_macs == frozenset({"bb0000000001", "bb0000000002"})

    def test_tolerates_trailing_comma(self):
        assert Config.from_env(self.env(RELAY_MACS="BB:00:00:00:00:01,")).relay_macs == \
            frozenset({"bb0000000001"})

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
            Config.from_env(self.env(RELAY_MACS="AA:00:00:00:00:01"))

    def test_broadcast_rejects_hostname(self):
        with pytest.raises(ValueError, match="BROADCAST"):
            Config.from_env(self.env(BROADCAST="broadcast.local"))

    def test_bad_mac_fails_loudly(self):
        with pytest.raises(ValueError, match="MAC"):
            Config.from_env(self.env(RELAY_MACS="BB:00:00:00:00"))
