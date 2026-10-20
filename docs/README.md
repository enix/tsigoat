# tsigoat documentation

| Document | For |
| --- | --- |
| [Configuration](configuration.md) | Every setting of the configuration file, and the update policy |
| [Clients](clients.md) | Setting up cert-manager, lego and Traefik, certbot and nsupdate |
| [PowerDNS](powerdns.md) | What tsigoat needs from PowerDNS, and how it writes to it |
| [Hosted DNS providers](providers.md) | How tsigoat writes to the APIs of hosted providers, and what it turns down |
| [Cloudflare](cloudflare.md), [OVHcloud](ovh.md), [Scaleway](scaleway.md) | The credentials to create for each provider, and what it does its own way |
| [RFC 2136 servers](rfc2136.md) | Relaying the updates to BIND or another name server, with the keys and the policy of tsigoat |
| [Webhooks](webhook.md) | Applying the updates with a script of yours, for the providers that tsigoat does not support |
| [Operations](operations.md) | Command line, images, Kubernetes, logs, metrics and alerts |
| [Security](security.md) | What tsigoat protects, its limits, and how to harden a deployment |
| [Architecture](architecture.md) | How a request flows through tsigoat, and how it is tested |
| [Helm chart](../chart/README.md) | Installing tsigoat in Kubernetes, and the values of the chart |

[examples/](../examples) holds an annotated configuration, values files for
the chart and a cert-manager ClusterIssuer. [CONTRIBUTING.md](../CONTRIBUTING.md)
covers the development workflow.
