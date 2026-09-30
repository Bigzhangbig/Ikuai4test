# Ikuai4test

Experimental iKuai 4.0 native-app packaging for Tailscale.

This repository builds upstream Tailscale as static Linux binaries and packages them as an iKuai 4.0 native `.ipkg` application.

> This is an experimental compatibility project. Test on a non-production router first.

## Build

Open **Actions → Build iKuai Tailscale IPKG → Run workflow**.

- `tailscale_ref=latest` resolves the latest stable Tailscale GitHub release.
- You can also enter an explicit tag such as `v1.102.5`.
- The workflow builds both `x86_64` and `aarch64` binaries with `CGO_ENABLED=0`.
- It packages them as a native iKuai application with `manifest.json` `type: "0"`.
- The workflow validates the generated tar/gzip package and uploads the `.ipkg` plus `SHA256SUMS` as a GitHub Actions artifact.

## First-stage runtime test

The package intentionally uses kernel TUN mode only:

```
tailscaled --tun=tailscale0
```

The start script records whether `/dev/net/tun` exists and then starts `tailscaled`. If iKuai does not expose a usable TUN device or the app process lacks the required permission, the failure should appear in the application run log.

Configuration fields currently exposed by the iKuai app package:

- `TS_HOSTNAME`
- `TS_AUTHKEY` (optional; use a disposable/revocable key while testing)
- `TS_ACCEPT_DNS` (defaults to `0`)

State is stored under the application's own `app/data/tailscale` directory.

The first build does **not** automatically enable subnet routing, exit-node mode, userspace-networking fallback, or firewall changes. Those should be added only after native execution and TUN support are confirmed.
