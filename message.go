package httpsig

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	nurl "net/url"
)

var errContentDigestDoesNotExist = errors.New("content digest header not present")
var errContentDigestMismatch = errors.New("content digest header does not match computed value")

// message is a minimal representation of an HTTP request or response, containing the values
// needed to construct a signature.
type message struct {
	Method    string
	Authority string
	URL       *nurl.URL
	Header    http.Header

	// Used to generate Content-digest
	Body []byte
}

func (m message) contentDigestSHA512() string {
	return calcDigest(m.Body)
}

// Sets the Content-Digest header with the contents of message body
func (m message) setContentDigest() {
	m.Header.Add("content-digest", m.contentDigestSHA512())
}

func (m message) verifyContentDigest() error {
	// Retrieve request's content digest header
	digest := m.Header.Get("content-digest") 
	if digest == "" {
		return errContentDigestDoesNotExist
	}

	// Perform our own calculation of content digest for comparison
	expectedDigest := m.contentDigestSHA512()

	result := subtle.ConstantTimeCompare([]byte(digest), []byte(expectedDigest))
	if result != 1 {
		return errContentDigestMismatch
	}

	return nil
}

func messageFromRequest(r *http.Request) (*message, error) {
	hdr := r.Header.Clone()

	// For incoming requests, the Host header is promoted to the Request.Host field and removed from the Header map.
	// Need to reset header
	hdr.Set("Host", r.Host)

	b := &bytes.Buffer{}

	if r.Body != nil {
		bodyCopy, err := r.GetBody()
		if err != nil {
			return nil, fmt.Errorf("unable to copy request body; %w", err)
		}

		n, err := b.ReadFrom(bodyCopy)
		if err != nil {
			return nil, fmt.Errorf("unable to read request body; %w", err)
		}

		defer r.Body.Close()

		if n != 0 {
			r.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
		}
	}

	return &message{
		Method:    r.Method,
		Authority: r.Host,
		URL:       r.URL,
		Header:    hdr,
		Body: b.Bytes(),
	},
	nil
}
