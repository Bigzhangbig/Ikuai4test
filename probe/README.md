# iKuai Capability Probe

A standalone diagnostic application for probing the actual capabilities exposed to iKuai 4.0 Docker App Market applications.

It intentionally does not depend on Tailscale.

The probe tests interfaces/routes, DNS and external TCP, configurable LAN TCP targets, TUN creation, NET_RAW, NET_ADMIN, IPv4-forwarding sysctl writability, iptables/nftables visibility, UPnP SSDP discovery, NAT-PMP, PCP, resolver/cgroup data and more.

Two packages are produced from the same image:

1. Bridge probe — uses doc_app_default and publishes a Web UI port.
2. Host probe — requests network_mode: host to directly test whether iKuai accepts/provides host networking.

Host installation or startup failure is itself a useful test result.
