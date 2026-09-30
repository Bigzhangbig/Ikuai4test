# Ikuai4test

Experimental iKuai 4.0 Tailscale packaging test.

## Important finding

On the current iKuai 4.0 local-install path, `manifest.json` rejects native app `type: "0"` and reports that only Docker applications are supported.

So this repository now uses a **Docker application package (`type: "1"`) for local installation**.

This does **not** mean iKuai has no native applications. Public examples such as rtp2httpd use a native package type when distributed through the official App Market. The limitation found here is specifically the local-upload installer path on the tested firmware.

## Build

Open **Actions → Build iKuai Tailscale Docker IPKG → Run workflow**.

- `tailscale_ref=latest` resolves the latest stable Tailscale release.
- You can also enter an explicit tag such as `v1.102.5`.
- GitHub Actions builds `tailscale`, `tailscaled`, and `containerboot` from the upstream Tailscale source with `CGO_ENABLED=0`.
- It builds an offline linux/amd64 Docker image and embeds it as `docker_image.tar.gz`.
- The final package uses iKuai App Market Docker format with `manifest.json` `type: "1"`.

## First test target

The Docker package requests:

- `NET_ADMIN`
- `NET_RAW`
- TUN character-device permission (`c 10:200 rwm`)
- persistent state under the app data directory

The container starts Tailscale with `TS_USERSPACE=false`, so it will test whether iKuai's Docker app environment can actually provide `/dev/net/tun`.

For the first install:

1. Use a disposable or revocable Tailscale auth key.
2. Leave advertised routes empty.
3. Leave extra arguments empty.
4. Start the app and inspect its application/container logs.
5. If it joins the tailnet, visit `http://<iKuai-LAN-IP>:41641/healthz`; a healthy node should return HTTP 200.

The initial Docker package uses iKuai's `doc_app_default` network, not host networking. Subnet routing, exit-node mode, and access to the iKuai host itself must be tested separately after basic TUN connectivity works.
