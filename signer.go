// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

type signer struct {
	configs HttpSigningConfigs

	key  sigHolder

	// For testing
	nowFunc func() time.Time
}

func (s *signer) Sign(msg *message) (http.Header, error) {
	// Houses all the canonicalized components in the order they were proccessed
	// This is what will eventually be signed 
	var b bytes.Buffer

	numComponents := len(s.configs.DerivedComponents) + len(s.configs.Headers)

	// Ordered list of component names in the order they were proccessed
	items := make([]string, 0, numComponents)

	for component := range s.configs.DerivedComponents {
		// 
		value, err := canonicalizeDerivedComponent(component, *msg)
		if err != nil {
			return nil, err
		}

		_, err = b.Write(value)
		if err != nil {
			return nil, fmt.Errorf("faild to write component's %s value %s to buffer. %w", component, value, err)
		}

		items = append(items, component)
	}

	// canonicalize headers
	for header := range s.configs.Headers {
	
		value, name, err := canonicalizeHeader(header, msg.Header)
		if err != nil {
			return nil, err
		}

		_, err = b.Write(value)
		if err != nil {
			return nil, fmt.Errorf("faild to write header's %s value %s to buffer. %w", header, value, err)
		}

		// Should I kick back the header's normalized name?
		items = append(items, name)
	}

	// Sanity check, make sure all components have been cannonicalized
	if len(items) != numComponents {
		return nil, fmt.Errorf("component mismatch")
	}

	now := s.nowFunc()

	sp := &signatureParams{
		id: s.configs.SignatureLabel,
		coveredComponents:   items,
		created: &now,
	}
	
	// Generate Derived component @signature-params, this is a required component consiting of
	// all components used to generate message signature
	sigParams := canonicalizeSignatureParams(sp)

	_, err := b.Write(sigParams)
	if err != nil {
		return nil, fmt.Errorf("faild to write component's %s value %s to buffer. %w", "@signature-params", sigParams, err)
	}

	items = append(items, "@signature-params")
	
	// Sign message
	signer := s.key.signer()
	if _, err := signer.w.Write(b.Bytes()); err != nil {
		return nil, err
	}

	signature, err := signer.sign()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return s.generateSignedMessageHeaders(*sp, base64.StdEncoding.EncodeToString(signature)), nil
}

func (s signer) generateSignedMessageHeaders(params signatureParams, signature string) http.Header {
	// Default header names 
	sigInputLabel := "signature-input"
	sigLabel := "signature"

	// Override default if config is set
	if s.configs.SignatureHeaderLabel != "" {
		sigLabel = s.configs.SignatureHeaderLabel
	}

	// Override default if config is set
	if s.configs.InputHeaderLabel != "" {
		sigInputLabel = s.configs.InputHeaderLabel
	}

	headers := http.Header{}

	// Use Add() to correctly canonicalize header, Ex: "content-digest" -> "Content-Digest"
	headers.Add(sigInputLabel, fmt.Sprintf("%s=%s", s.configs.SignatureLabel, params.normalizeValues()))
	headers.Add(sigLabel, fmt.Sprintf("%s=:%s:", s.configs.SignatureLabel, signature))

	return headers
}
