package main

import (
	"context"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// Fixtures of the test of the example webhook, which only exist inside its
// container.
const (
	webhookKeySecret = "d2ViaG9vay1leGFtcGxlLWtleS1vZi0zMi1ieXRlcyE=" // gitleaks:allow (throwaway)
	webhookSecret    = "signature-secret-of-the-test"                 // gitleaks:allow (throwaway)
	webhookPassword  = "password-of-the-test"                         // gitleaks:allow (throwaway)
	webhookToken     = "token-of-the-test"                            // gitleaks:allow (throwaway)
	// webhookValue is the value of an ACME challenge, which the acme rules of
	// the zones allow.
	webhookValue = "pwv1DlMc4agXVh8vXVtmRdToBr7PWMzF6M9rgEWgkKg" // gitleaks:allow (fixture)
)

// TestWebhookExample runs the example of examples/webhook behind tsigoat, once
// per authentication: signature, basic and bearer. nsupdate adds the value of
// an ACME challenge through tsigoat, then deletes it; tsigoat posts the
// updates to the example, which hands them to a command that records them. An
// update to an endpoint with another secret fails, and the example refuses
// replayed requests, after a restart too, a request without length, and a
// client that sends its bytes one by one.
func (m *Tsigoat) TestWebhookExample(ctx context.Context) (string, error) {
	replacer := strings.NewReplacer(
		"@KEY@", webhookKeySecret,
		"@SECRET@", webhookSecret,
		"@PASSWORD@", webhookPassword,
		"@TOKEN@", webhookToken,
		"@VALUE@", webhookValue,
	)
	return dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "python3", "bind-tools"}).
		WithFile("/usr/local/bin/tsigoat", m.binary()).
		WithFile("/webhook/webhook.py", m.Source.File("examples/webhook/webhook.py")).
		WithNewFile("/test/config.yaml", replacer.Replace(webhookExampleConfig)).
		WithNewFile("/test/record.sh", webhookRecordScript, dagger.ContainerWithNewFileOpts{Permissions: 0o755}).
		WithNewFile("/test/run.sh", replacer.Replace(webhookExampleScript)).
		WithExec([]string{"sh", "-eu", "/test/run.sh"}).
		Stdout(ctx)
}

// webhookExampleConfig serves a zone per authentication, and one whose
// endpoint expects another signature secret.
const webhookExampleConfig = `keys:
  - name: acme.
    secret: @KEY@
backends:
  - name: signature
    type: webhook
    webhook:
      url: http://127.0.0.1:8053/
      signature: {secret: @SECRET@}
  - name: basic
    type: webhook
    webhook:
      url: http://127.0.0.1:8054/
      basicAuth: {username: tsigoat, password: @PASSWORD@}
  - name: bearer
    type: webhook
    webhook:
      url: http://127.0.0.1:8055/
      bearer: {token: @TOKEN@}
      headers:
        - {name: X-Tenant, value: dns}
  - name: wrong
    type: webhook
    webhook:
      url: http://127.0.0.1:8053/
      signature: {secret: not-the-secret}
zones:
  - name: signature.test.
    backend: signature
    policy: [{key: acme., acme: [signature.test.]}]
  - name: basic.test.
    backend: basic
    policy: [{key: acme., acme: [basic.test.]}]
  - name: bearer.test.
    backend: bearer
    policy: [{key: acme., acme: [bearer.test.]}]
  - name: wrong.test.
    backend: wrong
    policy: [{key: acme., acme: [wrong.test.]}]
`

// webhookRecordScript records the operations that the example hands to it.
const webhookRecordScript = `#!/bin/sh
printf '%s\n' "$*" >> /tmp/operations.log
`

const webhookExampleScript = `
python3 -I -m py_compile /webhook/webhook.py

endpoint() {
  name=$1 port=$2
  shift 2
  env TSIGOAT_WEBHOOK_LISTEN=127.0.0.1:$port TSIGOAT_WEBHOOK_COMMAND="/test/record.sh $name" "$@" \
    python3 -I /webhook/webhook.py 2>> /tmp/$name.log &
  eval "pid_$name=\$!"
}
endpoint signature 8053 TSIGOAT_WEBHOOK_SECRET=@SECRET@
endpoint basic 8054 TSIGOAT_WEBHOOK_USERNAME=tsigoat TSIGOAT_WEBHOOK_PASSWORD=@PASSWORD@
endpoint bearer 8055 TSIGOAT_WEBHOOK_TOKEN=@TOKEN@
for port in 8053 8054 8055; do
  for i in $(seq 1 50); do nc -z 127.0.0.1 $port && break; sleep 0.1; done
done
tsigoat serve --config /test/config.yaml --listen 127.0.0.1:5353 2> /tmp/tsigoat.log &
for i in $(seq 1 50); do nc -z 127.0.0.1 5353 && break; sleep 0.1; done

update() {
  nsupdate -y hmac-sha256:acme.:@KEY@ <<COMMANDS
server 127.0.0.1 5353
zone $1.test.
update add _acme-challenge.$1.test. 60 TXT "@VALUE@"
send
update delete _acme-challenge.$1.test. TXT "@VALUE@"
send
COMMANDS
}

fail() {
  echo "== $1"
  for log in /tmp/*.log; do echo "--- $log"; cat "$log"; done
  exit 1
}

for name in signature basic bearer; do
  echo "== $name"
  update $name || fail "the update through the $name endpoint failed"
done

cat > /tmp/expected.log <<EXPECTED
signature add signature.test. _acme-challenge.signature.test. TXT 60 "@VALUE@"
signature delete-record signature.test. _acme-challenge.signature.test. TXT "@VALUE@"
basic add basic.test. _acme-challenge.basic.test. TXT 60 "@VALUE@"
basic delete-record basic.test. _acme-challenge.basic.test. TXT "@VALUE@"
bearer add bearer.test. _acme-challenge.bearer.test. TXT 60 "@VALUE@"
bearer delete-record bearer.test. _acme-challenge.bearer.test. TXT "@VALUE@"
EXPECTED
diff -u /tmp/expected.log /tmp/operations.log || fail "unexpected operations"

echo "== another secret"
if update wrong > /tmp/wrong.log 2>&1; then fail "an update succeeded with the wrong secret"; fi
grep -q SERVFAIL /tmp/wrong.log || fail "the update with the wrong secret did not get SERVFAIL"
grep -q "bad signature" /tmp/signature.log || fail "the endpoint did not refuse the wrong signature"

echo "== replays, across a restart too"
# post sends a signed request without operations, its timestamp ahead of the
# clock by $2 seconds, and checks that the endpoint answers $3.
cat > /tmp/post.py <<'PYTHON'
import hashlib, hmac, json, sys, time, urllib.error, urllib.request

request_id, ahead, expected = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
body = json.dumps({"version": 1, "id": request_id,
                   "zone": "signature.test.", "key": "", "operations": []}).encode()
timestamp = str(int(time.time()) + ahead)
mac = hmac.new(b"@SECRET@", timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
request = urllib.request.Request("http://127.0.0.1:8053/", body, {
    "Content-Type": "application/json",
    "X-Tsigoat-Timestamp": timestamp,
    "X-Tsigoat-Signature": "sha256=" + mac,
})
try:
    status = urllib.request.urlopen(request, timeout=5).status
except urllib.error.HTTPError as error:
    status = error.code
assert status == expected, (request_id, ahead, status, expected)
PYTHON
post() {
  python3 -I /tmp/post.py "$@" || fail "the endpoint did not answer $3 to request $1"
}
replayed=0123456789abcdef0123456789abcdef
ahead=fedcba9876543210fedcba9876543210
post $replayed 0 204
post $replayed 0 409
# A clock two minutes ahead, within the margin of the timestamps.
post $ahead 120 204
kill "$pid_signature"
wait "$pid_signature" 2>/dev/null || true
endpoint signature 8053 TSIGOAT_WEBHOOK_SECRET=@SECRET@
for i in $(seq 1 50); do nc -z 127.0.0.1 8053 && break; sleep 0.1; done
post $replayed 0 409
post $ahead 120 409
grep -q "refused: replay" /tmp/signature.log || fail "the endpoint did not log the replays"

echo "== a request without length, a client that sends its bytes one by one"
python3 -I - <<'PYTHON' || fail "the endpoint served a request without length or a slow client"
import socket, time

with socket.create_connection(("127.0.0.1", 8053), timeout=5) as conn:
    conn.sendall(b"POST / HTTP/1.0\r\nHost: endpoint\r\n\r\n")
    status = int(conn.recv(64).split(b" ")[1])
assert status == 411, status

start = time.monotonic()
with socket.create_connection(("127.0.0.1", 8053), timeout=30) as conn:
    conn.sendall(b"POST / HTTP/1.0\r\n")
    try:
        while time.monotonic() - start < 25:
            conn.sendall(b"X")
            time.sleep(1)
    except OSError:
        pass
elapsed = time.monotonic() - start
assert elapsed < 15, elapsed
PYTHON
post 00112233445566778899aabbccddeeff 0 204
echo "== OK"
`
