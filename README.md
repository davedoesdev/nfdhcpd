For details about the original project, see the [upstream documentation](https://www.synnefo.org/docs/nfdhcpd/latest/index.html).

I've made the following enhancements:

- Added a DNS server. Define entries in each interface's binding file. DNS queries can optionally be forward to the system resolver.
- Allow subnet configuration to be made in binding files.

Here's a sample binding file (e.g. `/var/lib/nfdhcpd/tap0`):

```ini
MAC=52:54:00:12:34:56
IP=10.0.1.40
HOSTNAME=foobar
SUBNET=10.0.1.0/24
SUBNET6=fde5:824d:d315:3bb1::/64
NAMESERVERS=10.0.1.50
NAMESERVERS6=fde5:824d:d315:3bb1::1
ADDRESS:www.google.com.=10.0.1.3
ADDRESS:database.=10.0.1.1
ADDRESS6:www.google.com.=1234:5678:abcd:ef01:1234:5678:9abc:def0
```

This configures `tap0` like so:

- Expect packets to be sent from and delivered to MAC `52:54:00:12:34:56`.
- In DHCP responses, set the IPv4 address to `10.0.1.40`, the host name to `foobar`, the IPv4 subnet to `10.0.1.0/24` and a DNS server address of `10.0.1.50`. The DNS server address should be any unused address on this network. You can use the same address in multiple binding files.
- In IPv6 router advertisements (including responses to ICMPv6 router solicitations), set the prefix to `fde5:824d:d315:3bb1::/64` (a private address range) and the DNS server option to `fde5:824d:d315:3bb1::1`. You can use the same address in multiple binding files.

  The DNS server address should be any unused address on this network. The attached device (usually a VM) is assumed to be using Stateless Address Autoconfiguration (SLAAC), by combining the prefix with EUI-64.
- Add IPv4 and IPv6 DNS entries for `www.google.com` (obviously this is just an example).
- Add an IPv4 DNS entry for `database`. You could of course add an IPv6 entry if you wanted.

You can use DNS entries so multi-VM applications don't have to know which IP address each VM is configured with.

Here's an example global configuration file (`/etc/nfdhcp/nfdhcp.conf`):

```ini
[general]
pidfile = /var/run/nfdhcpd/nfdhcpd.pid
datapath = /var/lib/nfdhcpd # Where the client configuration will be read from
logdir = /var/log/nfdhcpd   # Where to write our logs
user = nobody # An unprivileged user to run as

## DHCP options
[dhcp]
enable_dhcp = yes
lease_lifetime = 604800 # 1 week
lease_renewal = 3600 	# 1 hour
dhcp_queue = 42 # NFQUEUE number to listen on for DHCP requests

## IPv6-related functionality
[ipv6]
enable_ipv6 = yes
ra_period = 300 # seconds
rs_queue = 43 # NFQUEUE number to listen on for router solicitations
ns_queue = 44 # NFQUEUE number to listen on for neighbor solicitations

[dns]
enable_dns = yes
dns_queue = 45 # NFQUEUE number to listen on for DNS queries
dns6_queue = 46 # NFQUEUE number to listen on for DNS queries over IPv6
ttl = 10
forward = yes

[addresses]
www.yahoo.co.uk. = 10.0.1.1

[addresses6]
www.yahoo.co.uk. = abab:abab:abab:abab:abab:abab:abab:abab
```

You can see we enabled forwarding of DNS queries to the system resolver. This is also configurable on a per-binding basis (`DNS_FORWARD=` in the binding file). Also, you can define some global DNS entries to be used by all bindings.

# Packet filtering rules

To get DHCP, DNS, IPv6 router solicitation and IPv6 neighbour solicitation packets into `nfdhcpd`, you need to configure some packet filtering rules.

The following are examples for a `tap0` interface.

## iptables rules

```shell
iptables -t mangle -A PREROUTING -m physdev --physdev-in tap+ -p udp --dport bootps -j NFQUEUE --queue-num 42
iptables -t mangle -A PREROUTING -m physdev --physdev-in tap+ -p udp --dport domain -j NFQUEUE --queue-num 45
```

The first rule puts all DHCP BOOTP packets onto one of `nfdhcpd`'s netfilter queues.
The second rule puts all DNS packets onto another netfilter queue.

## ip6tables rules

```shell
ip6tables -t mangle -A PREROUTING -m physdev --physdev-in tap+ -p udp --dport domain -j NFQUEUE --queue-num 46
ip6tables -t mangle -A PREROUTING -p ipv6-icmp -m physdev --physdev-in tap+ --icmpv6-type router-solicitation   -j NFQUEUE --queue-num 43
ip6tables -t mangle -A PREROUTING -p ipv6-icmp -m physdev --physdev-in tap+ --icmpv6-type neighbour-solicitation -j NFQUEUE --queue-num 44
```

The first rule puts all DNS packets onto a netfilter queue for `nfdhcpd`. 
The second rule puts all IPv6 router solicitation packets onto another netfilter queue.
The third rule puts all IPv6 neighbour solicitation packets onto another netfilter queue.

## ebtables rules

IPv6 addresses are resolved to MAC addresses using neighbour solicitations, which `nfdhcpd` handles.

However, IPv4 addresses are resolved to MAC addresses using ARP, which `nfdhcpd` doesn't handle. So you need to get `ebtables` to resolve the IPv4 DNS server address specified in the binding file to a MAC address:

```shell
ebtables -t nat -A PREROUTING -p ARP -i tap0 --arp-ip-dst 10.0.1.50 -j arpreply --arpreply-mac 11:22:33:44:55:66
```

You can resolve it to any unused MAC address on this network &mdash; `nfdhcpd` will pick up DNS packets to any destination.

# Isolation

You may also wish to ensure only packets sent by and destined for the allocated IP and MAC address can get through the interface.

For example, if we have allocated IP address `10.0.1.20` and MAC address `52:54:00:12:34:57` to interface `tap0` then we could do this:

```shell
iptables -A FORWARD -m physdev --physdev-in tap0 -s 10.0.1.20 -d 10.0.1.0/24 -j ACCEPT
iptables -A FORWARD -m physdev --physdev-out tap0 -s 10.0.1.0/24 -d 10.0.1.20 -j ACCEPT
iptables -A FORWARD -m physdev --physdev-in tap0 -j REJECT
iptables -A FORWARD -m physdev --physdev-out tap0 -j REJECT

ebtables -A FORWARD -i tap0 -s 52:54:00:12:34:57 -j ACCEPT
ebtables -A FORWARD -i tap0 -d 52:54:00:12:34:57 -j ACCEPT
ebtables -A FORWARD -i tap0 -j DROP
```



# Debian packages

The `debian` branch can make a `.deb` file for installing on Debian-based distributions like Ubuntu. Run the following command to make the package:

```shell
dpkg-buildpackage -us -uc
```

Note, however, that a couple of the package's dependencies currently have issues which means things aren't quite as smooth as they should be.

- `nfqueue-bindings` up to and including version 0.4 is missing a function which `nfdhcp` requires. Version 0.5 includes this and should ship with Ubuntu 14.10. In the meantime you could build version 0.5 from [source](https://launchpad.net/ubuntu/+source/nfqueue-bindings/0.5-1).

- `python-cap-ng` is missing all its files! This is a [known bug](https://bugs.launchpad.net/ubuntu/+source/libcap-ng/+bug/1244384) but please visit the bug page and say it affects you. If you remake the package from source, it does include all its files.

# Acknowledgements

I just extended this project a bit. The bulk of the work was done by the [Greek Research and Technology Network](https://code.grnet.gr/projects/nfdhcpd), in particular Alexandros Kosiaris, Apollon Oikonomopoulos, Costas Drogos and Faidon Liambotis.
