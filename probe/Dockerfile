FROM alpine:3.22
RUN apk add --no-cache ca-certificates iproute2 iptables ip6tables nftables
COPY ikuai-cap-probe /usr/local/bin/ikuai-cap-probe
RUN chmod 0755 /usr/local/bin/ikuai-cap-probe
ENTRYPOINT ["/usr/local/bin/ikuai-cap-probe"]
