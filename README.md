# tsigoat

The RFC 2136 to anything proxy.

tsigoat receives DNS UPDATE messages ([RFC 2136][rfc2136]), authenticates them
with TSIG ([RFC 8945][rfc8945]) and applies the changes through the API of a
DNS provider. ACME DNS-01 clients such as cert-manager, lego or certbot can then
solve their challenges without ever holding the provider credentials, even when
the provider does not speak RFC 2136.

```text
cert-manager, lego,     DNS UPDATE              HTTP API
certbot, nsupdate...  ─── + TSIG ──► tsigoat ───────────► PowerDNS
```

> [!WARNING]
> The project is being restarted and has no release yet. The core has been
> rewritten, but the documentation and the deployment manifests are still to
> come. PowerDNS is the only backend, and tsigoat runs as a single instance.

## Development quick start

With [Nix][nix] and [direnv][direnv], `direnv allow` provides every tool.
Otherwise install Go, [Task][task] and Docker (or Podman) for [Dagger][dagger].

```sh
task dev        # PowerDNS with the example.test. zone, on localhost
task dev:run    # tsigoat on 127.0.0.1:10053, prints the TSIG key to use
```

Then, from another terminal:

```sh
nsupdate -y "hmac-sha256:dev.:<key printed by task dev:run>" <<EOF
server 127.0.0.1 10053
zone example.test.
update add hello.example.test. 60 TXT "world"
send
EOF
dig +tcp @127.0.0.1 -p 5300 hello.example.test. TXT
```

`task --list` shows every task; [CONTRIBUTING.md](CONTRIBUTING.md) explains
the toolchain and the conventions.

## License

MIT, see [LICENSE](LICENSE).

[rfc2136]: https://www.rfc-editor.org/rfc/rfc2136
[rfc8945]: https://www.rfc-editor.org/rfc/rfc8945
[nix]: https://nixos.org/
[direnv]: https://direnv.net/
[task]: https://taskfile.dev/
[dagger]: https://dagger.io/
