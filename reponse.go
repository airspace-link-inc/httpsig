package httpsig

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Minimal representation of an HTTP response, containing the values needed to validate a signature
type response struct {
	Status int 
	Headers http.Header
	Body []byte
}

// The @status derived component refers to the three-digit numeric HTTP
// status code of a response message as defined in [HTTP], Section 15.
// The component value is the serialized three-digit integer of the HTTP
// status code, with no descriptive text.  If used, the @status
// component identifier MUST occur only once in the covered components.
func (resp response) CanonicalizeStatus() []byte {
	// TODO(JS): Should we be validating code only 3 digits?
	return []byte(fmt.Sprintf("\"@status\": %d\n", resp.Status))
}

func (resp response) verifyContentDigest() error {
	// Retrieve request's content digest header
	digest := resp.Headers.Get("content-digest") 
	if digest == "" {
		return errContentDigestDoesNotExist
	}

	// Perform our own calculation of content digest for comparison
	expectedDigest := calcDigest([]byte(resp.Body))

	result := subtle.ConstantTimeCompare([]byte(digest), []byte(expectedDigest))
	if result != 1 {
		return errContentDigestMismatch
	}

	return nil
}

// Converts an HTTP request to a more generalized response struct
func responseFromHTTP(resp *http.Response) (*response, error) {
	b := &bytes.Buffer{}

	if resp.Body != nil {
		defer resp.Body.Close()
	
		n, err := b.ReadFrom(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read request body; %w", err)
		}

		if n != 0 {
			resp.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
		}
	}

	return &response{
		Status: resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body: b.Bytes(),
	},
	nil
}
