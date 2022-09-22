// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"
)

//
type HttpSigningConfigs struct {
	// Set of derived components that will be used to sign the outbound message
	// An exaustive list can be found in section 2.2 of the spec
	// Ex: ["@query", "@path", "@method"]
	DerivedComponents map[string]struct{}
	// Set of required HTTP headers that must be present and included in the signature
	// If header is not provided in request this will result in an error before being sent 
	Headers map[string]struct{}

	InputHeaderLabel string
	SignatureHeaderLabel string
	SignatureLabel string

	PubKey *rsa.PublicKey
}

func sliceHas(haystack []string, needle string) bool {
	for _, n := range haystack {
		if n == needle {
			return true
		}
	}

	return false
}

// NewSignTransport returns a new client transport that wraps the provided transport with
// http message signing and body digest creation.
//
// Use the various `WithSign*` option funcs to configure signature algorithms with their provided
// key ids. You must provide at least one signing option. A signature for every provided key id is
// included on each request. Multiple included signatures allow you to gracefully introduce stronger
// algorithms, rotate keys, etc.
func NewSignTransport(transport http.RoundTripper, params HttpSigningConfigs, opts ...signOption) http.RoundTripper {
	s := signer{
		key:    sigHolder{},
		nowFunc: time.Now,

		configs: params,
	}

	for _, o := range opts {
		o.configureSign(&s)
	}

	// TODO(JS): Determine if the lang spec requires "content-type", "content-length
	// TODO: normalize required headers? lowercase

	return rt(func(r *http.Request) (*http.Response, error) {
		// Clone incoming HTTP request, to prevent modificatioon
		// Requirement of http.RoundTrip() is Callers should not mutate or reuse the 
		// request until the Response's Body has been closed.
		nr := r.Clone(r.Context())

		msg, err := messageFromRequest(nr)
		if err != nil {
			return nil, fmt.Errorf("unable to deserialize request; %w", err)
		}

		// Always set a digest (for now)
		msg.setContentDigest()
		// Since headers are separate need to set it here too
		nr.Header.Set("content-digest", msg.contentDigestSHA512())

		hdr, err := s.Sign(msg)
		if err != nil {
			return nil, err
		}

		for k, v := range hdr {
			nr.Header[k] = v
		}

		return transport.RoundTrip(nr)
	})
}

type rt func(*http.Request) (*http.Response, error)

func (r rt) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }



type signOption interface {
	configureSign(s *signer)
}

type verifyOption interface {
	configureVerify(v *verifier)
}

type signOrVerifyOption interface {
	signOption
	verifyOption
}

type optImpl struct {
	s func(s *signer)
	v func(v *verifier)
}

// Configures the signer 
// Adds default headers if they are not present 
// Adds default label of "sig1" if not set in configs
func (o *optImpl) configureSign(s *signer) { 
	o.s(s) 

	if len(s.configs.Headers) == 0 {
		s.configs.Headers = map[string]struct{}{
			"content-type": {}, 
			"content-length": {},
		}
	}

	if s.configs.SignatureLabel == "" {
		s.configs.SignatureLabel = "sig1"
	}
}

func (o *optImpl) configureVerify(v *verifier) { o.v(v) }


// WithSignRsaPssSha512 adds signing using `rsa-pss-sha512` with the given private key
// using the given key id.
func WithSignRsaPssSha512(keyID string, pk *rsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.key = signRsaPssSha512(pk) },
	}
}

// WithVerifyRsaPssSha512 adds signature verification using `rsa-pss-sha512` with the
// given public key using the given key id.
func WithVerifyRsaPssSha512(keyID string, pk *rsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.key = verifyRsaPssSha512(pk) },
	}
}

// WithSignEcdsaP256Sha256 adds signing using `ecdsa-p256-sha256` with the given private key
// using the given key id.
func WithSignEcdsaP256Sha256(keyID string, pk *ecdsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.key = signEccP256(pk) },
	}
}

// WithVerifyEcdsaP256Sha256 adds signature verification using `ecdsa-p256-sha256` with the
// given public key using the given key id.
func WithVerifyEcdsaP256Sha256(keyID string, pk *ecdsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.key = verifyEccP256(pk) },
	}
}

// WithHmacSha256 adds signing or signature verification using `hmac-sha256` with the
// given shared secret using the given key id.
func WithHmacSha256(keyID string, secret []byte) signOrVerifyOption {
	return &optImpl{
		s: func(s *signer) { s.key = signHmacSha256(secret) },
		v: func(v *verifier) { v.key = verifyHmacSha256(secret) },
	}
}

// WithSignEcdsaP256Sha256 adds signing using `ecdsa-p256-sha256` with the given private key
// using the given key id.
func WithSignRSA256(pk *rsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.key = signRsa256(pk) },
	}
}