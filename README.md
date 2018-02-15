# dhcp-relay

`dhcp-relay` is intended as a replacement for ISC `dhcrelay` and
specifically it's
[OpenBSD descendant](https://man.openbsd.org/dhcrelay.8).

The motivation for this was the lack of support in `dhcrelay` for
interfaces on multiple IP subnets. `dhcrelay` assumed a single
primary address on an interface and would only relay DHCP requests
as that one DHCP gateway. `dhcp-relay` is designed to support this,
but also aims to be a better implementation of this part of the
DHCP protocol.

## Usage

```
usage: dhcp-relay [-vd] [-C circuit] [-R remote] [-H hoplim] -i interface
	destination ...
```

## Improvements over `dhcrelay`

- `dhcp-relay` supports acting as a DHCP gateway for all the IP
  subnets configured on the specified interface, not just the first
  network.
- The BPF filter used on the interface is restricted to accepting
  broadcast and multicast Ethernet packets, what the RFC calls "locally
  delivered datagrams". This stops the relay intercepting unicast
  packets, eg, DHCP INFORM packets from clients sent directly to their
  server, or packets from other DHCP relays.

## Missing `dhcrelay` features

- Support for operating on
  [enc(4)](https://man.openbsd.org/enc.4) interfaces

## To do

- Add all missing `dhcrelay` features
- Support use in a DHCP relay chain
- Get this into OpenBSD so I can stop using git
