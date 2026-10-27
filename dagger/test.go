package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/tsigoat/internal/dagger"
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
func (m *Tsigoat) Test(ctx context.Context) (string, error) {
	return verdict(ctx, m.TestReport(), "the unit tests")
}

// TestReport runs the unit tests as Test does, but returns their report
// whatever their outcome, for CI to keep it when they fail: output.txt,
// junit.xml, coverage.out (the profile), coverage.txt (the coverage of each
// package) and status, the exit status of the run. The race detector
// requires CGO, which pulls gcc and musl-dev on Alpine.
func (m *Tsigoat) TestReport() *dagger.Directory {
	floors := make([]string, 0, len(coverageFloors))
	for pkg, floor := range coverageFloors {
		floors = append(floors, fmt.Sprintf("%s=%d", pkg, floor))
	}
	return goBase(m.Source).
		WithExec([]string{"apk", "add", "--no-cache", "gcc", "musl-dev"}).
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithEnvVariable("COVERAGE_FLOORS", strings.Join(floors, " ")).
		// The output goes to the log as the tests run, and to the report; the
		// status leaves the pipeline through its file.
		WithExec([]string{"sh", "-uc", `
mkdir -p /report
{
  gotestsum --format=pkgname-and-test-fails --junitfile=/report/junit.xml -- \
    -race -shuffle=on -coverprofile=/report/coverage.out ./...
  status=$?
  if [ -s /report/coverage.out ]; then
    floors=0
    (` + coverageFloorScript + `) || floors=$?
    if [ "$status" -eq 0 ]; then status=$floors; fi
  fi
  echo "$status" >/report/status
} 2>&1 | tee /report/output.txt
`}).
		Directory("/report")
}

// verdict returns the output of a report, and an error when its status is
// not zero.
func verdict(ctx context.Context, report *dagger.Directory, what string) (string, error) {
	output, err := report.File("output.txt").Contents(ctx)
	if err != nil {
		return "", err
	}
	status, err := report.File("status").Contents(ctx)
	if err != nil {
		return output, err
	}
	if strings.TrimSpace(status) != "0" {
		return output, fmt.Errorf("%s failed (status %s):\n%s", what, strings.TrimSpace(status), output)
	}
	return output, nil
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
}' /report/coverage.out | sort > /report/coverage.txt
status=0
for entry in $COVERAGE_FLOORS; do
  pkg=${entry%=*}; floor=${entry#*=}
  coverage=$(awk -v pkg="$pkg" '$1 == pkg { print $2 }' /report/coverage.txt)
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
// touching the pipeline. A package that does not build fails the run, rather
// than read as one without targets, and so does a run that finds none.
func (m *Tsigoat) Fuzz(
	ctx context.Context,
	// Time given to each target, as a Go duration or a number of runs such
	// as "1000x".
	// +optional
	// +default="1m"
	fuzztime string,
) (string, error) {
	return verdict(ctx, m.FuzzReport(fuzztime), "the fuzzing")
}

// FuzzReport runs the fuzz targets as Fuzz does, every one even after a
// failure, and returns their report whatever their outcome, for CI to keep
// it: output.txt, status, the exit status of the run, and corpus, the inputs
// that made a target fail, at the paths where `go test` reads them
// (<package>/testdata/fuzz/<target>/), to commit as regression cases.
func (m *Tsigoat) FuzzReport(
	// Time given to each target, as a Go duration or a number of runs such
	// as "1000x".
	// +optional
	// +default="1m"
	fuzztime string,
) *dagger.Directory {
	return goBase(m.Source).
		WithEnvVariable("FUZZTIME", fuzztime).
		// The output goes to the log as the targets run, and to the report;
		// the status leaves the pipeline through its file.
		WithExec([]string{"sh", "-uc", `
mkdir -p /report/corpus
touch /tmp/start
{
  status=0
  count=0
  for pkg in $(go list ./...); do
    if ! listed=$(go test -list '^Fuzz' "$pkg" 2>&1); then
      printf '%s\n' "$listed"
      status=1
      continue
    fi
    for target in $(printf '%s\n' "$listed" | grep '^Fuzz' || true); do
      echo "== $target ($pkg)"
      go test -run '^$' -fuzz "^$target\$" -fuzztime "$FUZZTIME" "$pkg" || status=1
      count=$((count + 1))
    done
  done
  echo "== $count fuzz targets"
  if [ "$count" -eq 0 ]; then
    echo "no fuzz target found"
    status=1
  fi
  # A failing input lands in testdata/fuzz of its package.
  failing=$(find . -path '*/testdata/fuzz/*' -type f -newer /tmp/start)
  if [ -n "$failing" ]; then
    echo "== failing inputs, in the corpus of the report:"
    printf '%s\n' "$failing"
    tar -cf - $failing | tar -xf - -C /report/corpus
  fi
  echo "$status" >/report/status
} 2>&1 | tee /report/output.txt
`}).
		Directory("/report")
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
