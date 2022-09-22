package httpsig

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"
)

// NewVerifyMiddleware returns a configured http server middleware that can be used to wrap
// multiple handlers for http message signature and digest verification.
//
// Use the `WithVerify*` option funcs to configure signature verification algorithms that map
// to their provided key ids.
//
// Requests with missing signatures, malformed signature headers, expired signatures, or
// invalid signatures are rejected with a `400` response. Only one valid signature is required
// from the known key ids. However, only the first known key id is checked.
func NewVerifyMiddleware(opts ...verifyOption) func(http.Handler) http.Handler {

	// TODO: form and multipart support
	v := verifier{
		nowFunc: time.Now,
	}

	for _, o := range opts {
		o.configureVerify(&v)
	}

	serveErr := func(rw http.ResponseWriter) {
		// TODO: better error and custom error handler
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusBadRequest)

		_, _ = rw.Write([]byte("invalid required signature"))
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

			msg, err := messageFromRequest(r)
			if err != nil {
				serveErr(rw)
				return
			}

			err = v.Verify(msg)
			if err != nil {
				serveErr(rw)
				return
			}

			b := &bytes.Buffer{}
			if r.Body != nil {
				n, err := b.ReadFrom(r.Body)
				if err != nil {
					serveErr(rw)
					return
				}

				defer r.Body.Close()

				if n != 0 {
					r.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
				}
			}

			// Check the digest if set. We only support id-sha-256 for now.
			// TODO: option to require this?
			if dig := r.Header.Get("Digest"); dig != "" {
				if !verifyDigest(b.Bytes(), dig) {
					serveErr(rw)
				}
			}

			h.ServeHTTP(rw, r)
		})
	}
}