# DNS logger for the sandbox network: answers NXDOMAIN for everything and logs each query.
FROM alpine:3.20
RUN apk add --no-cache dnsmasq
ENTRYPOINT ["dnsmasq", "--no-daemon", "--no-resolv", "--log-queries", "--log-facility=-", "--address=/#/"]
