#!/bin/bash

[ -d hack ] || {
  echo "Run this script from the project root with: ./hack/$(basename $0)" >&2
  exit 1
}

[ -d .keyring ] && {
  echo "Development keyring already exists." >&2
}

set -xe

mkdir .keyring

NAME=$(dnssec-keygen -K .keyring/ -a RSASHA256 demo)
ln -sr .keyring/$NAME.key     .keyring/rsasha256.key
ln -sr .keyring/$NAME.private .keyring/rsasha256.private

NAME=$(dnssec-keygen -K .keyring/ -a RSASHA512 demo)
ln -sr .keyring/$NAME.key     .keyring/rsasha512.key
ln -sr .keyring/$NAME.private .keyring/rsasha512.private

NAME=$(dnssec-keygen -K .keyring/ -a ECDSAP256SHA256 demo)
ln -sr .keyring/$NAME.key     .keyring/ecdsap256sha256.key
ln -sr .keyring/$NAME.private .keyring/ecdsap256sha256.private

NAME=$(dnssec-keygen -K .keyring/ -a ECDSAP384SHA384 demo)
ln -sr .keyring/$NAME.key     .keyring/ecdsap384sha384.key
ln -sr .keyring/$NAME.private .keyring/ecdsap384sha384.private

NAME=$(dnssec-keygen -K .keyring/ -a ED25519 demo)
ln -sr .keyring/$NAME.key     .keyring/ed25519.key
ln -sr .keyring/$NAME.private .keyring/ed25519.private
