# wireplug

[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

🔥 **Warning** - This is an early preview; the protocol is subject to change and the coordination server at wireplug.org may be unavailable at times.
Please make sure to run the latest version at all times.

---

`wireplug` is a minimalist connectivity coordinator for roaming [WireGuard®](https://www.wireguard.com) peers.
Unlike other alternatives in this space, `wireplug` is geared toward users who want to manage their keys and network topology manually, while still enjoying automatic endpoint updating and NAT traversal without having to run their own server.

![](https://github.com/alpn/wireplug/raw/main/.media/demo.gif)

## Background
In vanilla WireGuard settings, an interface must be configured (at minimum) with the following:

- `PrivateKey` - a `curve25519` private key
- `ListenPort` - a `UDP` port to listen on

Then, for each peer we must also configure:

- `PublicKey` - the peer's `curve25519` public key (derived from its own `PrivateKey`)
- `AllowedIPs` - a list of `IP` address ranges from which this peer is allowed to receive packets, and to which outbound packets may be routed
- `Endpoint` - an `IP:PORT` pair where the outer `UDP` packets are sent to and received from

Note that `PrivateKey`, `PublicKey`, and `AllowedIPs` are typically static: they define identities and the overlay topology, so you normally configure them once and leave them unchanged.

The `Endpoint`, however, could potentially change multiple times per day as peers move between networks. `wireplugd` (`wireplug`'s client) is a simple lightweight local daemon that monitors your network status and updates WireGuard `Endpoint`s, when needed, in order to maintain uninterrupted connectivity.

Coordination is handled by `wpcod`. By default, `wireplugd` connects to an instance run by the author at ***wireplug.org***.
Users may run their own instances, but a special effort has been made so they never have to. The protocol is deliberately simple and was designed so that clients share only the absolutely necessary information with the coordination server.

## Getting started
`wireplug` currently supports `Linux` kernel version `5.6` and later and `OpenBSD` version `6.8` and later, each using their respective in-kernel WireGuard implementations. It also supports `macOS`, which requires installing [`wireguard-go`](https://git.zx2c4.com/wireguard-go/about/) (the official userspace WireGuard implementation).

### Installation
On any of the supported platforms, start by installing `wireplugd`:

```
cargo install --git https://github.com/alpn/wireplug wireplugd
```

### Linux
1. Create a new WireGuard device:

```sh
ip link add dev wg0 type wireguard
```

2. Use `wireplugd` to create a config file with a randomly generated private key:

```sh
# This requires root access to write the config file to /etc
sudo wireplugd wg0 --generate-config
```

3. Edit the config file `/etc/wireplugd.wg0` as needed.

4. Run `wireplugd`:

```sh
sudo wireplugd wg0
```

### macOS
1. Install `wireguard-go`:

```sh
brew install wireguard-go
```

2. Use `wireplugd` to create a config file with a randomly generated private key:

```sh
# This requires root access to write the config file to /etc
sudo wireplugd wg0 --generate-config
```

3. Edit the config file `/etc/wireplugd.wg0` as needed.

4. Run `wireplugd`:
```sh
sudo wireplugd wg0
```

### OpenBSD
1. Follow the example in `man wg` to create a new WireGuard device using `ifconfig(8)` and `hostname.if(5)`.

2. Run `wireplugd`:

```sh
doas wireplugd wg0
```

## Features

### No Account, No Signup
No account or signup process is required to use the service.

### In-Kernel WireGuard Support

- [x] Linux
- [x] OpenBSD
- [ ] FreeBSD

### NAT Traversal

- [x] No mapping
- [x] Fixed mapping
- [ ] Destination-dependent mapping - UPnP IGD
- [ ] Destination-dependent mapping - NAT-PMP
- [ ] Destination-dependent mapping - PCP
- [ ] Relay server (last resort)

### LAN
If two peers are on the same local network, `wireplug` will attempt to connect them locally.

## Disclaimers and Credits
`WireGuard®` is a registered trademark of Jason A. Donenfeld.
`wireplug` is **not** an official WireGuard project.

This project has not received an independent security audit, and should be considered experimental software at this early point in its lifetime.

`wireplug` uses the [wireguard-control](https://github.com/tonarino/innernet/tree/main/wireguard-control) crate maintained by @tonarino
