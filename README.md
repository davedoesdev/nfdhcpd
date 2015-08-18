# nfdhcpd

`nfdhcpd` is a daemon which processes packets placed on netfilter queues by iptables.

For details about the original project, see the [upstream documentation](https://www.synnefo.org/docs/nfdhcpd/latest/index.html).

`nfdhcpd` can process IPv4 DHCP, IPv6 DHCPv6 and IPv6 Router and Neighbour Solicitation messages. In addition, I've made the following enhancements:

- Added support for DNS A, AAAA and TXT records. Different DNS records can be defined in binding files for each network interface you use with `nfdhcpd`. You can also forward DNS queries to the system resolver.

- Allow subnet configuration to be defined in binding files.

- A custom notification protocol so your application knows when a binding file changes.

# Binding files

There's one binding file per network interface.

Here's a sample binding file (e.g. `/var/lib/nfdhcpd/tap0`):

```ini
MAC=52:54:00:12:34:56
IP=10.0.1.40
HOSTNAME=foobar
SUBNET=10.0.1.0/24
SUBNET6=fde5:824d:d315:3bb1::/64
GATEWAY=10.0.1.90
GATEWAY6=fde5:824d:d315:3bb1::90
GATEWAY6_MAC=7e:b7:70:3b:81:77
NAMESERVERS=10.0.1.50
NAMESERVERS6=fde5:824d:d315:3bb1::1
ADDRESS:www.google.com.=10.0.1.3
ADDRESS:database.=10.0.1.1
ADDRESS6:www.google.com.=1234:5678:abcd:ef01:1234:5678:9abc:def0
TXT:table.=Users
ADDRESS_LISTS=foo
NOTIFY_PORT=25000
NOTIFY_IP=10.0.1.51
NOTIFY_IP6=fde5:824d:d315:3bb1::2
```

This configures `tap0` like so:

- Expect packets to be sent from and delivered to MAC `52:54:00:12:34:56`.

- In DHCP responses, set the IPv4 address to `10.0.1.40`, the host name to `foobar`, the IPv4 subnet to `10.0.1.0/24` and a DNS server address of `10.0.1.50`. The DNS server address should be any unused address on this network. You can use the same address in multiple binding files.

- In IPv6 router advertisements (including responses to ICMPv6 router solicitations), set the prefix to `fde5:824d:d315:3bb1::/64` (a private address range) and the DNS server option to `fde5:824d:d315:3bb1::1`. The DNS server address should be any unused address on this network. You can use the same address in multiple binding files.

  The attached device (usually a VM) is assumed to have a link-local address derived using Stateless Address Autoconfiguration (SLAAC), by combining the prefix with EUI-64. 

- Add a gateway (`10.0.1.90`) for IPv4 traffic not on the subnet. This is optional.

- Add a gateway (`fde5:824d:d315:3bb1::90`) for IPv6 traffic outside the prefix. This is optional.

  Note you need to supply the MAC address for the gateway too (here `7e:b7:70:3b:81:77`). Even though `nfdhcpd` sets the gateway address (and the `R` flag) in router advertisements, some Linux guests ignore it and always use the link-local address for the default route. So `nfdhcpd` will respond to neighbour solicitations for its link-local address with the MAC address of the gateway that you supply.

- Add IPv4 and IPv6 DNS entries for `www.google.com` (obviously this is just an example).

- Add an IPv4 DNS entry for `database`. You could of course add an IPv6 entry if you wanted.

- Add a TXT DNS entry for `table`, value `Users`.

- Use a separate address list `foo` for other addresses. Address lists are files containing only `ADDRESS:`, `ADDRESS6:` and `TXT:` entries. They live alongside binding files and must be named `address_list_<name>`. So in this case `/var/lib/nfdhcpd/address_list_foo`. 

DNS entries and address lists are useful so multi-VM applications don't have to know which IP address each VM is configured with.

`nfdhcpd` re-reads binding files and address list files when they change so you can update DNS entries while your application is running. If you define `NOTIFY_PORT`, as above, then when a binding file changes, a UDP packet will be sent to your application. The packet's source address will be `NOTIFY_IP`/`NOTIFY_IP6`. Its destination address will be `IP`/the link-local SLAAC EUI-64.

Your application should send the packet back to let `nfdhcpd` know not to send it again.

# Global configuration

Here's an example global configuration file (`/etc/nfdhcpd/nfdhcpd.conf`):

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
dhcp6_queue = 43 # NFQUEUE number to listen on for DHCPv6 requests

## IPv6-related functionality
[ipv6]
enable_ipv6 = yes
ra_period = 300 # seconds
rs_queue = 44 # NFQUEUE number to listen on for router solicitations
ns_queue = 45 # NFQUEUE number to listen on for neighbor solicitations

[dns]
enable_dns = yes
dns_queue = 46 # NFQUEUE number to listen on for DNS queries
dns6_queue = 47 # NFQUEUE number to listen on for DNS queries over IPv6
ttl = 10
forward = yes

[notify]
enable_notify = yes
notify_period  = 60 # seconds
notify_queue = 48
notify6_queue = 49

[addresses]
www.yahoo.co.uk. = 10.0.1.1

[addresses6]
www.yahoo.co.uk. = abab:abab:abab:abab:abab:abab:abab:abab
```

You can see we enabled forwarding of DNS queries to the system resolver. This is also configurable on a per-binding basis (`DNS_FORWARD=` in the binding file). You can define some global DNS entries to be used by all bindings too.

# Packet filtering rules

To get DHCP, DNS, IPv6 router solicitation and IPv6 neighbour solicitation packets into `nfdhcpd`, you need to configure some packet filtering rules.

The following are examples for a `tap0` interface.

## iptables rules

```shell
iptables -t mangle -A PREROUTING -m physdev --physdev-in tap0 -p udp --dport bootps -j NFQUEUE --queue-num 42
iptables -t mangle -A PREROUTING -m physdev --physdev-in tap0 -p udp --dport domain -j NFQUEUE --queue-num 45
```

The first rule puts all DHCP BOOTP packets onto one of `nfdhcpd`'s netfilter queues.
The second rule puts all DNS packets onto another netfilter queue.

## ip6tables rules

```shell
ip6tables -t mangle -A PREROUTING -m physdev --physdev-in tap0 -p udp --dport domain -j NFQUEUE --queue-num 46
ip6tables -t mangle -A PREROUTING -p ipv6-icmp -m physdev --physdev-in tap0 --icmpv6-type router-solicitation   -j NFQUEUE --queue-num 43
ip6tables -t mangle -A PREROUTING -p ipv6-icmp -m physdev --physdev-in tap0 --icmpv6-type neighbour-solicitation -j NFQUEUE --queue-num 44
```

The first rule puts all DNS packets onto a netfilter queue for `nfdhcpd`. 
The second rule puts all IPv6 router solicitation packets onto another netfilter queue.
The third rule puts all IPv6 neighbour solicitation packets onto another netfilter queue.

## ebtables rules

IPv6 addresses are resolved to MAC addresses using neighbour solicitations, which `nfdhcpd` handles.

However, IPv4 addresses are resolved to MAC addresses using ARP, which `nfdhcpd` doesn't handle. So you need to get `ebtables` to resolve the IPv4 DNS server address specified in the binding file to a MAC address:

```shell
ebtables -t nat -A PREROUTING -p ARP -i tap0 --arp-ip-dst 10.0.1.50 -j arpreply --arpreply-mac 52:54:00:12:34:56
```

You can resolve it to any MAC address on this network &mdash; `nfdhcpd` will pick up DNS packets to any destination.

If you've defined `NOTIFY_IP` in your binding file then you should do something similar for that address.

# Fold

`nfdhcpd` is used by [Fold](https://github.com/davedoesdev/fold) to provide per-interface configuration in a virtual Ethernet switch environment. Fold adds isolation between IPv4 subnets and IPv6 prefixes.

# Debian packages

The `debian` branch can make a `.deb` file for installing on Debian-based distributions like Ubuntu. Run the following command to make the package:

```shell
dpkg-buildpackage -us -uc
```

A pre-made package, `nfdhcpd_0.20_all.deb` (compiled on Ubuntu 15.04), can be found in the `dist` directory.

Note that because of [this bug](https://bugs.launchpad.net/ubuntu/+source/libcap-ng/+bug/1244384), `nfdhcpd_0.20_all.deb` depends on `python-cap-ng` version 0.7.6, which you'll need to install manually from the [Ubuntu 15.10 package archive](http://packages.ubuntu.com/wily/amd64/python-cap-ng/download).

# Acknowledgements

The original work was done by the [Greek Research and Technology Network](https://code.grnet.gr/projects/nfdhcpd), in particular Alexandros Kosiaris, Apollon Oikonomopoulos, Costas Drogos and Faidon Liambotis.
