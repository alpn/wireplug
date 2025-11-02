# wireplug

[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

`wireplug` is a minimalist connectivity coordinator for roaming [WireGuard®](https://www.wireguard.com) peers.
Unlike other alternatives in this space, `wireplug` is geared toward users who want to manage their keys and network topology manually while still enjoying automatic endpoint updating and NAT traversal without having to run their own server.

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

Coordination is handled by `wireplug-serverd`. By default, `wireplugd` connects to an instance run by the author at ***wireplug.org***.
Users may run their own instances, but a special effort has been made so they never have to. The protocol is deliberately simple and was designed so that clients share only the absolutely necessary information with the coordination server.

## Installation

```
cargo install [options] --git https://github.com/alpn/wireplug [client…]
```

## Usage

```
sudo wireplug <interface> [--config <CONFIG>]
```

## Features
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

`wireplug` uses the [wireguard-control crate](https://github.com/tonarino/innernet/tree/main/wireguard-control) crate maintained by @tonarino
