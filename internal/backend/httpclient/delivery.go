package httpclient

import (
	"context"
	"net/http/httptrace"
	"sync/atomic"
)

// Delivery tells whether a request may have left whole, which the server
// may then apply whatever happens next. It is safe for concurrent use, as
// the transport writes the request apart from the caller.
type Delivery struct {
	started, failed, sent atomic.Bool
}

// Trace returns ctx with a trace that informs d, for the request to carry.
func (d *Delivery) Trace(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		// A transport that writes a request again starts with its headers.
		WroteHeaders: func() {
			d.started.Store(true)
			d.failed.Store(false)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				d.failed.Store(true)
				return
			}
			d.sent.Store(true)
		},
	})
}

// Left reports whether a request that failed may have left whole: its write
// ended without error, or the transport gave up on it while it wrote it.
// Over HTTP/2, the transport tells that the write ended once the last bytes
// went, but does not wait for that when it gives up on a request, after a
// cancellation or a timeout: a request whose write started, and did not
// fail, may have left whole.
func (d *Delivery) Left() bool {
	return d.sent.Load() || d.started.Load() && !d.failed.Load()
}
