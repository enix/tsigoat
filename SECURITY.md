# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/enix/tsigoat/security/advisories/new),
not in public issues.

Include what you can of: the affected version or commit, the configuration,
the DNS messages or requests that trigger the issue, and its impact. We will
acknowledge the report, keep you informed of the fix, and credit you in the
advisory unless you prefer otherwise.

## Supported versions

No version has been released yet. Once releases start, security fixes target
the latest minor release.

## Verifying releases

Releases sign every image, and the checksums of their archives, with cosign
keyless. GitHub attests the build provenance of the archives, and every image
carries a CycloneDX SBOM as a cosign attestation. Before deploying a release:

```sh
cosign verify ghcr.io/enix/tsigoat:<version> \
  --certificate-identity-regexp '^https://github.com/enix/tsigoat/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/enix/tsigoat/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify tsigoat-v<version>-linux-amd64.tar.gz --owner enix
```

## Security model

[docs/security.md](docs/security.md) describes what tsigoat protects and what
it does not: TSIG authenticates the updates without encrypting them, keys are
restricted by policy, and HMAC-MD5 and HMAC-SHA1 remain available only to the
keys that opt into them. It ends with advice to harden a deployment.
