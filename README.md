# wol-relay

Wakes a sleeping host before forwarding a Wake-on-LAN packet to a device behind it.

## The problem

Wake-on-LAN assumes the target can hear the packet: you broadcast a magic packet, the NIC
sees the pattern and powers the machine up. That assumption breaks the moment the target
sits *behind* something else.

Virtual machines are the common case. A VM has no real NIC — its virtual one only exists
while the guest runs, so nothing on the wire ever reacts to a magic packet addressed to it.
The usual answer is a listener on the hypervisor that catches the packet and starts the
guest. That works, but only while the hypervisor itself is awake.

If the host sleeps too, the chain falls apart:

- Nobody is listening, so the packet is lost.
- The sender addresses the guest, not the host, and usually has no idea the host even
  exists.
- Magic packets are fire-and-forget. Nothing retries once the host comes up.

wol-relay runs on a machine that is always on and closes that gap. It watches for packets
addressed to devices it knows are unreachable, wakes their host first, and replays the
packet once someone is there to hear it.

## How it works

The relay listens for magic packets and reacts only to MACs listed in `RELAY_MACS`. For
each one:

1. **If the host already answers, it does nothing.** The host's own listener saw the packet
   and can act on it — there is nothing to relay.
2. Otherwise it wakes the host: magic packet to `HOST_MAC`, repeated every `RETRY_EVERY`
   seconds until the host answers on `HOST_PORT`, at most `MAX_RETRIES` times.
3. Once the host is up, it **replays the original packet**, which the host's listener now
   receives.
4. A `COOLDOWN` follows before the next trigger is accepted.

If the host never comes up, the device packet is never sent.

The relay knows nothing about the devices beyond their MAC — no addresses, no ports, no
health checks. What happens after the packet is delivered is the host's business. This
keeps it agnostic about what runs behind the host: VMs, containers, or anything else with
a listener that can act on a magic packet.

### Ports

The relay listens and sends on **port 9** — where WoL senders and listeners conventionally
meet. It works with whatever already emits your magic packets: `wakeonlan`, `etherwake`,
your router's web interface, Home Assistant.

Listening where it sends means the relay hears its own packets. That cannot loop: the wake
packet uses `HOST_MAC`, which is barred from `RELAY_MACS`, and a replay only goes out once
the host is up — at which point a trigger exits straight away with "host already up".

Binding port 9 is privileged. In a container that means `NET_BIND_SERVICE`; nothing else.
If you would rather not grant it, point `LISTEN_PORT` at an unprivileged port your sender
also targets — Moonlight, for instance, transmits every magic packet to both 9 and 47009.

### No allowlist needed

Only deliberate senders emit magic packets — scanners, monitoring and discovery traffic
never do. So there is nothing to filter: packets for MACs the relay does not own are simply
ignored, and any client may wake a listed device without being registered anywhere.

## Requirements

- The relay must sit in the **same L2 segment** as the host — WoL is a broadcast.
- A listener on the host that acts on the replayed packet, e.g.
  [wakevm](https://github.com/nachobacanful/wakevm) for Proxmox.
- Guests must not be set to auto-start with the host, or the host will never be idle again.

Run it wherever something is always on — a container, a VM, a small always-on box. It needs
host networking to receive and send LAN broadcasts; from an isolated container network,
neither works. Binding the default port 9 needs `NET_BIND_SERVICE`, no other privileges.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `HOST` | yes | — | IP or hostname of the sleeping host |
| `HOST_MAC` | yes | — | MAC of the host NIC that has WoL armed |
| `RELAY_MACS` | yes | — | comma-separated MACs of devices allowed to wake the host |
| `BROADCAST` | no | `255.255.255.255` | destination address for magic packets |
| `HOST_PORT` | no | `8006` | TCP port used to check whether the host is up |
| `LISTEN_PORT` | no | `9` | port the relay expects magic packets on |
| `RETRY_EVERY` | no | `15` | seconds between attempts |
| `MAX_RETRIES` | no | `20` | attempts before giving up |
| `COOLDOWN` | no | `60` | lockout after a sequence |

MAC notation does not matter (`AA:BB:…`, `aa-bb-…`, `aabb…`), it gets normalised. `HOST`
may be a name — it is only ever resolved for the health check.

`HOST_PORT` should be something that answers once the host is ready to act on packets —
its management interface, SSH, whatever comes up reliably. The default suits Proxmox VE.

`HOST_MAC` inside `RELAY_MACS` is rejected at startup: the relay would see its own wake
packet and trigger itself.

With the defaults, waking gives up after five minutes.

## Run

```bash
docker run --network host \
  -e HOST=192.0.2.10 \
  -e HOST_MAC=aa:bb:cc:dd:ee:ff \
  -e RELAY_MACS=11:22:33:44:55:66 \
  ghcr.io/lorenzlars/wol-relay:1.0.0
```

Kubernetes manifests: see `apps/wol-relay/` in
[lorenzlars/k8s](https://github.com/lorenzlars/k8s).

## Development

```bash
pip install pytest ruff
pytest -v
ruff check .
```

The tests need neither root nor network nor a host to wake: magic packets are built to
spec, sockets are mocked.

## Release

Tagging `1.0.0` builds and pushes `ghcr.io/lorenzlars/wol-relay:1.0.0`. Pushes to `main`
land as `:edge`.
