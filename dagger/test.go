package main

import (
	"context"
	"fmt"
	"strings"
)

// coverageFloors are the minimum statement coverages of the packages that
// hold the protocol and security logic, in percent.
var coverageFloors = map[string]int{
	"github.com/enix/tsigoat/internal/update": 90,
	"github.com/enix/tsigoat/internal/zone":   90,
	"github.com/enix/tsigoat/internal/auth":   90,
}

// Test runs the unit tests through gotestsum, with the race detector, a
// shuffled order and a coverage profile, then checks the coverage floors.
// The race detector requires CGO, which pulls gcc and musl-dev on Alpine.
func (m *Tsigoat) Test(ctx context.Context) (string, error) {
	floors := make([]string, 0, len(coverageFloors))
	for pkg, floor := range coverageFloors {
		floors = append(floors, fmt.Sprintf("%s=%d", pkg, floor))
	}
	return goBase(m.Source).
		WithExec([]string{"apk", "add", "--no-cache", "gcc", "musl-dev"}).
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithEnvVariable("COVERAGE_FLOORS", strings.Join(floors, " ")).
		// One shell, so that the output holds both the tests and the floors.
		WithExec([]string{"sh", "-euc", `
gotestsum --format=pkgname-and-test-fails --junitfile=/tmp/junit.xml -- \
  -race -shuffle=on -coverprofile=/tmp/coverage.out ./...
` + coverageFloorScript}).
		Stdout(ctx)
}

// coverageFloorScript computes the statement coverage of every package from
// the profile, and fails when a package of COVERAGE_FLOORS falls below its
// floor.
const coverageFloorScript = `
awk 'NR > 1 {
  split($1, location, ":"); pkg = location[1]; sub(/\/[^\/]*$/, "", pkg)
  total[pkg] += $2; if ($3 > 0) covered[pkg] += $2
} END {
  for (pkg in total) printf "%s %.1f\n", pkg, 100 * covered[pkg] / total[pkg]
}' /tmp/coverage.out | sort > /tmp/coverage.txt
status=0
for entry in $COVERAGE_FLOORS; do
  pkg=${entry%=*}; floor=${entry#*=}
  coverage=$(awk -v pkg="$pkg" '$1 == pkg { print $2 }' /tmp/coverage.txt)
  if awk -v c="${coverage:-0}" -v f="$floor" 'BEGIN { exit !(c < f) }'; then
    echo "coverage of $pkg is ${coverage:-0}%, below its floor of $floor%"
    status=1
  else
    echo "coverage of $pkg is $coverage% (floor $floor%)"
  fi
done
exit $status
`

// Fuzz runs every fuzz target of the module in turn, each for the given time.
// Targets are discovered with `go test -list`, so that new ones run without
// touching the pipeline.
func (m *Tsigoat) Fuzz(
	ctx context.Context,
	// Time given to each target, as a Go duration or a number of runs such
	// as "1000x".
	// +optional
	// +default="1m"
	fuzztime string,
) (string, error) {
	return goBase(m.Source).
		WithEnvVariable("FUZZTIME", fuzztime).
		WithExec([]string{"sh", "-euc", `
for pkg in $(go list ./...); do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $target ($pkg)"
    go test -run '^$' -fuzz "^$target\$" -fuzztime "$FUZZTIME" "$pkg"
  done
done
`}).
		Stdout(ctx)
}

// Mutation runs gremlins on the packages that hold the protocol and security
// logic: it alters their code and reports the alterations that no test
// notices. The report is informational; it fails only when gremlins does.
func (m *Tsigoat) Mutation(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"go", "install", "github.com/go-gremlins/gremlins/cmd/gremlins@" + gremlinsModule}).
		// The report goes through a file rather than a pipe, so that the status
		// of gremlins survives grep, which keeps the alterations left alive.
		WithExec([]string{"sh", "-euc", `
status=0
for pkg in ./internal/update ./internal/zone ./internal/auth; do
  echo "== $pkg"
  gremlins unleash --workers 4 --timeout-coefficient 10 "$pkg" >/tmp/gremlins.txt || status=$?
  grep -Ev '^ +KILLED ' /tmp/gremlins.txt || true
done
exit "$status"
`}).
		Stdout(ctx)
}
