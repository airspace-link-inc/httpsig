package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type sigImpl struct {
	w    io.Writer
	sign func() ([]byte, error)
}

type sigHolder struct {
	alg    string
	signer func() sigImpl
}

func signRsaPssSha512(pk *rsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "rsa-pss-sha512",
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)

					return rsa.SignPSS(rand.Reader, pk, crypto.SHA512, b, nil)
				},
			}
		},
	}
}

func signEccP256(pk *ecdsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "ecdsa-p256-sha256",
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)

					return ecdsa.SignASN1(rand.Reader, pk, b)
				},
			}
		},
	}
}

func signHmacSha256(secret []byte) sigHolder {
	// TODO: add alg description
	return sigHolder{
		signer: func() sigImpl {
			h := hmac.New(sha256.New, secret)

			return sigImpl{
				w:    h,
				sign: func() ([]byte, error) { 
					return h.Sum(nil), nil
				},
			}
		},
	}
}

func signRsa256(pk *rsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "SASSA-PKCS1-v1_5 using SHA-256",
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					// crypto/rand.Reader is a good source of entropy for blinding the RSA
					// operation.
					rng := rand.Reader

					hashed := h.Sum(nil)

					signature, err := rsa.SignPKCS1v15(rng, pk, crypto.SHA256, hashed[:])
					if err != nil {
						return nil, err
					}

					return signature, nil
				},
			}
		},
	}
}
