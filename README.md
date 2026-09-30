# Ikuai4test

Experimental iKuai 4.0 Tailscale packaging test.

## Findings so far

1. The iKuai 4.0 **local-install** path rejects native `type: "0"` packages and only accepts Docker applications (`type: "1"`).
2. The Docker package can run Tailscale 1.102.5 in **kernel TUN mode** (`TS_USERSPACE=false`) and the node successfully joins the tailnet.
3. iKuai Docker does not provide a reliable host-network path for this use case. Public rtp2httpd discussion explicitly calls out the lack of host mode on iKuai Docker, while iKuai's own Docker documentation exposes iKuai-managed container interfaces rather than host networking.
4. Therefore the next useful experiment is **Subnet Router over the existing iKuai Docker bridge**, not another host-mode package.

## Current package revision

The package version is now **1.102.5.2**:

- upstream Tailscale version: `1.102.5`
- iKuai package revision: `.2`

Future package changes should increment the package revision instead of reusing the same version.

## Build

Open **Actions → Build iKuai Tailscale Docker IPKG → Run workflow**.

- `tailscale_ref=latest` resolves the latest stable Tailscale release.
- GitHub Actions builds `tailscale`, `tailscaled`, and `containerboot` from upstream source with `CGO_ENABLED=0`.
- The workflow builds an offline linux/amd64 Docker image and embeds it as `docker_image.tar.gz`.
- The final package uses iKuai App Market Docker format with `manifest.json` `type: "1"`.
- GitHub Actions dependencies are kept on their current major versions (checkout v7, setup-go v7, upload-artifact v7).

## Stage 2: subnet-router test

The package keeps:

- `NET_ADMIN`
- `NET_RAW`
- TUN character-device permission (`c 10:200 rwm`)
- persistent Tailscale state
- `TS_USERSPACE=false`

Set `TS_ROUTES` to the LAN CIDR you want to reach from the tailnet, for example:

```
192.168.1.0/24
```

Multiple routes can be comma-separated.

When `TS_ROUTES` is non-empty, Tailscale's `containerboot` attempts to enable the required IP forwarding. After the node advertises the route, approve it in:

**Tailscale Admin → Machines → ikuai → Edit route settings**

Linux subnet-route SNAT is enabled by default, so LAN devices normally do not need an explicit return route to `100.64.0.0/10`.

## Health / metrics

The previous iKuai-LAN port mapping was removed because kernel-mode Tailscale and Docker host port publishing are not a reliable combination here.

From another tailnet device, use the Tailscale IP directly:

```
http://<ikuai-tailscale-ip>:9002/healthz
http://<ikuai-tailscale-ip>:9002/metrics
```

The current stage intentionally does not enable Exit Node mode and does not modify iKuai's own UPnP/NAT settings.
