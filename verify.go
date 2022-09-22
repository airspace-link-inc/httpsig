// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Parses the signature id and signature value
func parseSignature(in string) (string, string, error) {
	var signature string

	// ["sig1", "":asjfgnaslkdbnvakjsfb.ksjdbnv as;kdvbj=:"]
	sParts := strings.SplitN(in, "=", 2)
	
	if len(sParts) != 2 {
		return "", signature, errMalformedSignature
	}

	sig := sParts[1]
	n := len(sig)

	// Prevent index out of bounds 
	if n < 2 {
		return  "", signature, errMalformedSignature
	}

	// Signature must be wrapped by colons, EX: ":<sig val>:"
	if sig[0] != ':' && sig[n - 1] != ':' {
		return  "", signature, errMalformedSignature
	}

	signature = strings.Trim(sig, ":")

	if signature == "" {
		return  "", signature, errMalformedSignature
	}

	return sParts[0], signature, nil
}

type verImpl struct {
	w      io.Writer
	verify func([]byte) error
}

type verHolder struct {
	alg      string
	verifier func() verImpl
}

type verifier struct {
	configs HttpSigningConfigs

	key verHolder

	// For testing
	nowFunc func() time.Time
}

// XXX: note about fail fast.
func (v *verifier) Verify(msg *message) error {
	// Check for existence of "Signature" header
	// This indicates that the message has been signed
	sigHdr := msg.Header.Get(v.configs.SignatureHeaderLabel)
	if sigHdr == "" {
		return errNotSigned
	}

	// Check for existence of "Signature-Input" header
	// This will allow us to replicate signature & validate authenticity
	paramHdr :=  msg.Header.Get(v.configs.InputHeaderLabel)
	if paramHdr == "" {
		return errNotSigned
	}

	// Should look like "sig1=:asjfgnaslkdbnvakjsfb.ksjdbnv as;kdvbj=:"
	sigParts := strings.Split(sigHdr, ", ")

	// Should look like:
	// 'sig1=("@method" "@path" "@query" "authorization" "content-type" "content-digest");created=1657133676'​
	paramParts := strings.Split(paramHdr, ", ")

	// Verify num sigs matches num inputs
	// Check only pertains to multisig
	if len(sigParts) != len(paramParts) {
		return errMalformedSignature
	}

	var sigID string
	var params signatureParams
	var err error

	for _, p := range paramParts {
		pParts := strings.SplitN(p, "=", 2)
		if len(pParts) != 2 {
			return errMalformedSignature
		}
		
		params, err = parseSignatureParams(pParts[1])
		if err != nil {
			return errMalformedSignature
		}

		sigID = pParts[0]
	}

	id, signature, err := parseSignature(sigHdr)
	if err != nil {
		return err
	}

	if id != sigID {
		return errMalformedSignature
	}

	// expectedAlgorithm := v.key.alg
	// if expectedAlgorithm != "" && *params.alg != "" && 
	// 	expectedAlgorithm != *params.alg {
	// 	return errAlgMismatch
	// }

	// Signatures are base64 encoded before transit, decode to verify
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errMalformedSignature
	}

	verifier := v.key.verifier()

	// canonicalize headers
	for _, component := range params.coveredComponents {

		var value []byte 
		if len(component) > 1 && component[0] == '@' {
			value, err = canonicalizeDerivedComponent(component, *msg)
			if err != nil {
				return err
			}
		} else {
			value, _, err = canonicalizeHeader(component, msg.Header)
		}

		_, err = verifier.w.Write(value)
		if err != nil {
			return fmt.Errorf("faild to write component's %s value %s to buffer. %w", component, value, err)
		}
	}

	if _, err := verifier.w.Write(canonicalizeSignatureParams(&params)); err != nil {
		return err
	}

	err = verifier.verify(sig)
	if err != nil {
		return errInvalidSignature
	}

	// Check signatures are not expired 
	if params.expires != nil && params.expires.After(time.Now()) {
		return errSignatureExpired
	}

	return nil
}

func parseSignatureInputHeader(headerValue string) (string, signatureParams, error) {
	var params signatureParams
	var signatureID string

	// Should look like:
	// 'sig1=("@method" "@path" "@query" "authorization" "content-type" "content-digest");created=1657133676'​

	// Split into two parts the signature and the corresponding label
	// ["sig1", "("@method" "@path" "@query" "authorization" "content-type" "content-digest");created=1657133676"]
	pParts := strings.SplitN(headerValue, "=", 2)
	if len(pParts) != 2 {
		return signatureID, params, errMalformedSignature
	}

	signatureID = pParts[0]

	// Parse signature input into signature params
	params, err := parseSignatureParams(pParts[1])
	if err != nil {
		return signatureID, params, errMalformedSignature
	}

	
	return signatureID, params, nil
}

// XXX use vice here too.

var (
	errNotSigned          = errors.New("signature headers not found")
	errMalformedSignature = errors.New("unable to parse signature headers")
	errUnknownKey         = errors.New("unknown key id")
	errAlgMismatch        = errors.New("algorithm mismatch for key id")
	errSignatureExpired   = errors.New("signature expired")
	errInvalidSignature   = errors.New("invalid signature")
)

// These error checking funcs aren't needed yet, so don't export them

/*

func IsNotSignedError(err error) bool          { return errors.Is(err, notSignedError) }
func IsMalformedSignatureError(err error) bool { return errors.Is(err, malformedSignatureError) }
func IsUnknownKeyError(err error) bool         { return errors.Is(err, unknownKeyError) }
func IsAlgMismatchError(err error) bool        { return errors.Is(err, algMismatchError) }
func IsSignatureExpiredError(err error) bool   { return errors.Is(err, signatureExpiredError) }
func IsInvalidSignatureError(err error) bool   { return errors.Is(err, invalidSignatureError) }

*/

func verifyRsaPssSha512(pk *rsa.PublicKey) verHolder {
	return verHolder{
		alg: "rsa-pss-sha512",
		verifier: func() verImpl {
			h := sha512.New()

			return verImpl{
				w: h,
				verify: func(s []byte) error {
					b := h.Sum(nil)

					return rsa.VerifyPSS(pk, crypto.SHA512, b, s, nil)
				},
			}
		},
	}
}

func verifyEccP256(pk *ecdsa.PublicKey) verHolder {
	return verHolder{
		alg: "ecdsa-p256-sha256",
		verifier: func() verImpl {
			h := sha256.New()

			return verImpl{
				w: h,
				verify: func(s []byte) error {
					b := h.Sum(nil)

					if !ecdsa.VerifyASN1(pk, b, s) {
						return errInvalidSignature
					}

					return nil
				},
			}
		},
	}
}

func verifyHmacSha256(secret []byte) verHolder {
	// TODO: add alg
	return verHolder{
		alg: "hmac-sha256",
		verifier: func() verImpl {
			h := hmac.New(sha256.New, secret)

			return verImpl{
				w: h,
				verify: func(in []byte) error {
					if !hmac.Equal(in, h.Sum(nil)) {
						return errInvalidSignature
					}
					return nil
				},
			}
		},
	}
}

func verifyRsa256(pub *rsa.PublicKey) verHolder {
	// TODO: add alg
	return verHolder{
		alg: "SASSA-PKCS1-v1_5 using SHA-256",
		verifier: func() verImpl {
			h := sha256.New()

			return verImpl{
				w: h,
				verify: func(signature []byte) error {

					hashed := h.Sum(nil)
					
					return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
				},
			}
		},
	}
}