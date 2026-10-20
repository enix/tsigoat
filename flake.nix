{
  description = "tsigoat dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # GoReleaser pinned independently of nixpkgs so the dev/e2e
        # build path can adopt new releases as soon as upstream ships
        # them. Grabs the upstream binary release rather than rebuilding
        # via `buildGoModule` — same trade-off as goSizeAnalyzer above.
        #
        # Bump procedure (Renovate refreshes `version` but cannot
        # recompute the four per-arch hashes on a `fetchurl` bump):
        #   1. update `version` below
        #   2. curl -sL https://github.com/goreleaser/goreleaser/releases/download/v<v>/checksums.txt
        #   3. for each `goreleaser_<OS>_<arch>.tar.gz` line, convert:
        #      `hash = "sha256-$(echo <hex> | xxd -r -p | base64)"`
        goreleaser = let
          # goreleaser version
          version = "2.18.3";
          assets = {
            "x86_64-linux"   = { suffix = "Linux_x86_64";  hash = "sha256-uN7kcovKGroNcagyoXzQo3mfdTcoeOf/o2rvI0O84Lw="; };
            "aarch64-linux"  = { suffix = "Linux_arm64";   hash = "sha256-+nARp/jeO1BDJrhVLPIccI7TCJUZsB03LaMu9OjSmNc="; };
            "x86_64-darwin"  = { suffix = "Darwin_x86_64"; hash = "sha256-28OTR9nKJaLam8wDYz85EwuzpnyfKg2oa6FbiwC/hs4="; };
            "aarch64-darwin" = { suffix = "Darwin_arm64";  hash = "sha256-ghxYq4wx1XuzMcq58acD6zZzv/T84Nucw8SgOK8U928="; };
          };
          asset = assets.${system} or (throw "goreleaser: unsupported system ${system}");
        in pkgs.stdenvNoCC.mkDerivation {
          pname = "goreleaser";
          inherit version;
          src = pkgs.fetchurl {
            url = "https://github.com/goreleaser/goreleaser/releases/download/v${version}/goreleaser_${asset.suffix}.tar.gz";
            hash = asset.hash;
          };
          sourceRoot = ".";
          installPhase = ''
            install -Dm755 goreleaser $out/bin/goreleaser
          '';
        };
      in {
        devShells.default = pkgs.mkShell {
          # Go is intentionally unpinned: GOTOOLCHAIN=auto downloads the
          # toolchain declared in go.mod, the single source of truth.
          #
          # The Dagger CLI is deliberately not a Nix package: its version must
          # equal dagger.json's engineVersion, so scripts/dagger-cli.sh reads
          # it from there and fetches the matching binary into a cache.
          shellHook = ''
            export GOTOOLCHAIN=auto
            if daggerBin=$(${./scripts/dagger-cli.sh}); then
              PATH="$daggerBin:$PATH"
            else
              echo "warning: Dagger CLI unavailable; 'task lint:*' / 'test:*' will fail" >&2
            fi
          '';

          packages = [
            goreleaser
          ] ++ (with pkgs; [
            go
            go-task
            cosign
            dnsutils   # dig and nsupdate, to poke at the dev server
            bind       # tsig-keygen
            jq
            goda
            graphviz   # `dot`, used by `task analysis:graph`
            xdg-utils  # `xdg-open`, used by `task analysis:graph`
          ]);
        };
      });
}
