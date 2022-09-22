package httpsig

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var errSignatureMismatch = errors.New("signature ids do not match")


type Verifier struct {
	SignatureHeaderLabel string
	InputHeaderLabel string 
}

func (v Verifier) Verify(httpResp http.Response, pubKey *rsa.PublicKey) error {
	// Generate a generic response object to use for verification
	resp, err := responseFromHTTP(&httpResp)
	if err != nil {
		return err
	}

	return verify(
		*resp, 
		verifyRsa256(pubKey).verifier(), 
		v.SignatureHeaderLabel, 
		v.InputHeaderLabel,
	)
}

// Constructs the signature base of a message and writes it to a buffer
// This is the portion of the message that is signed
func constructSignatureBase(buf io.Writer, resp response, sp signatureParams) error {
	// canonicalize headers
	for _, component := range sp.coveredComponents {

		var value []byte
		var err error

		switch component {
			case "@status":
				value = resp.CanonicalizeStatus()
			default: 
				value, _, err = canonicalizeHeader(component, resp.Headers)
		}

		_, err = buf.Write(value)
		if err != nil {
			return fmt.Errorf("faild to write component's %s value %s to buffer. %w", component, value, err)
		}
	}

	if _, err := buf.Write(canonicalizeSignatureParams(&sp)); err != nil {
		return err
	}

	return nil
}

// Verifies the integrity of the response body 
func verifyResponseBody(resp response) error {
	// Not all implementations of message signing require the existance of the content-digest header
	// Only perform validation if it exists 
	if resp.Headers.Get("content-digest") == "" {
		return nil 
	}

	return resp.verifyContentDigest()
}

// TODO: Create an interface that satisfies both message and response, to make true generic handler, call it "Verifyable"
func verify(resp response, verifier verImpl, signatureHeaderLabel, inputHeaderLabel string) error {
	// Check for existence of "Signature" header
	// This indicates that the message has been signed
	sigHdr := resp.Headers.Get(signatureHeaderLabel)
	if sigHdr == "" {
		return errNotSigned
	}

	// Check for existence of "Signature-Input" header
	// This will allow us to replicate signature & validate authenticity
	paramHdr :=  resp.Headers.Get(inputHeaderLabel)
	if paramHdr == "" {
		return errNotSigned
	}

	// Validate response body early on to ensure message integrity
	err := verifyResponseBody(resp)
	if err != nil {
		return err
	}

	// Parse signatre input fields to determine how to generate signature base
	// EX: signature-input=("@status" "content-type" "content-digest" "authorization" );created=1663170265
	signatureInputParts := strings.SplitN(paramHdr, "=", 2)
	if len(signatureInputParts) != 2 {
		return errMalformedSignatureInput
	}

	// ID that corresponds to the signature created. This will need to match the one 
	// On the signature once parsed
	signatureID := signatureInputParts[0]

	signatureParams, err := parseSignatureParams(signatureInputParts[1])
	if err != nil {
		return errMalformedSignatureInput
	}

	// Signatures must not be expired! Save CPU cycles by failing fase here
	if signatureParams.expires != nil && signatureParams.expires.After(time.Now()) {
		return errSignatureExpired
	}
	
	// Recreate signature base and write to bufffer
	// Used to verify provided signature in the request header
	constructSignatureBase(verifier.w, resp, signatureParams)

	// Parse signature header
	id, encodedSig, err := parseSignature(sigHdr)
	if err != nil {
		return err
	}

	// Signatures are base64 encoded before transit, decode to verify
	signature, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return errMalformedSignature
	}

	// The signature ID on the signature-input and signature headers must match
	// To indicate we are looking at the same signature
	if id != signatureID {
		return errSignatureMismatch
	}

	// Verify computed sig matches the one provided in the header
	err = verifier.verify([]byte(signature))
	if err != nil {
		return errInvalidSignature
	}

	return nil
}
