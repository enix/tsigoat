module github.com/enix/tsigoat

go 1.26.0

// The toolchain of the tests and of the releases alike, which the golang image
// of dagger/base.go matches (task check:toolchain).
toolchain go1.27.2

require (
	github.com/KimMachineGun/automemlimit v1.0.0
	github.com/miekg/dns v1.1.73
	github.com/prometheus/client_golang v1.25.0
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto/x509roots/fallback v0.0.0-20261016151342-0ae6809b7559
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
