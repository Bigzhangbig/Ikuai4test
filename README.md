# Ikuai4test

Experimental iKuai 4.0 native-app packaging for Tailscale.

This repository builds upstream Tailscale as static Linux binaries and packages them as an iKuai 4.0 native `.ipkg` application. It also includes a small diagnostic probe used to test whether an app-market native process can open `/dev/net/tun` and create a temporary TUN interface.

> This is an experimental compatibility project. Test on a non-production router first.

## Build

Open **Actions → Build iKuai Tailscale IPKG → Run workflow**.

- `tailscale_ref=latest` resolves the latest stable Tailscale GitHub release.
- You can also enter an explicit tag such as `v1.102.5`.
- The workflow builds both `x86_64` and `aarch64` binaries and produces one iKuai `.ipkg` artifact.

The first build target is intentionally conservative: validate native execution and TUN support before enabling subnet-router or exit-node automation.
