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

Releases sign every image, the Helm chart, and the checksums of their
archives and deb and rpm packages, with cosign keyless. GitHub attests the
build provenance of the archives and packages, and every image carries a
CycloneDX SBOM as a cosign attestation.
Before deploying a release, check that the release workflow signed it, on
the tag of its version:

```sh
identity='https://github.com/enix/tsigoat/.github/workflows/release.yaml@refs/tags/v<version>'
issuer='https://token.actions.githubusercontent.com'
cosign verify ghcr.io/enix/tsigoat:<version> \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
cosign verify-attestation --type cyclonedx ghcr.io/enix/tsigoat:<version> \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
cosign verify ghcr.io/enix/charts/tsigoat:<version> \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
gh attestation verify tsigoat-v<version>-linux-amd64.tar.gz --repo enix/tsigoat \
  --signer-workflow enix/tsigoat/.github/workflows/release.yaml \
  --source-ref refs/tags/v<version>
```

## Security model

[docs/security.md](docs/security.md) describes what tsigoat protects and what
it does not: TSIG authenticates the updates without encrypting them, keys are
restricted by policy, and HMAC-MD5 and HMAC-SHA1 remain available only to the
keys that opt into them. It ends with advice to harden a deployment.
