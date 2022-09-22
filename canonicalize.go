// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	nurl "net/url"
	"strconv"
	"strings"
	"time"
)

// Section 2.1 covers canonicalizing headers.
// Section 2.4 step 2 covers using them as input.
func canonicalizeHeader(name string, hdr http.Header) ([]byte, string, error) {
	// XXX: Structured headers are not considered, and they should be :)
	headerValues := hdr.Values(name)

	// 1. Create an ordered list of the field values of each instance of
	// the field in the message, in the order that they occur (or will
	// occur) in the message.
	vc := make([]string, len(headerValues))

	for i, val := range headerValues {
		// 2.  Strip leading and trailing whitespace from each item in the list.
		// Note that since HTTP field values are not allowed to contain
		// leading and trailing whitespace, this will be a no-op in a
		// compliant implementation.
		val = strings.TrimSpace(val)

		// 3.  Remove any obsolete line-folding within the line and replace it
		// with a single space (" "), as discussed in Section 5.2 of
		// [HTTP1].  Note that this behavior is specific to [HTTP1] and does
		// not apply to other versions of the HTTP specification.
		vc[i] = strings.ReplaceAll(val, "\n", " ")
	}

	// 4. Concatenate the list of values together with a single comma (",")
    // and a single space (" ") between each item.
	name = strings.ToLower(name)

	return []byte(fmt.Sprintf("\""+name+"\": %s\n", strings.Join(vc, ", "))), name, nil
}

// The @method derived component refers to the HTTP method of a request
// message.  The component value is canonicalized by taking the value of
// the method as a string.  Note that the method name is case-sensitive
// as per [HTTP], Section 9.1, and conventionally standardized method
// names are uppercase US-ASCII.  If used, the @method component
// identifier MUST occur only once in the covered components.
//
// For example, the following request message:
// POST /path?param=value HTTP/1.1
// Host: www.example.com
// Would result in the following @method component value: "@method": POST
func canonicalizeMethod(method string) []byte {
	// Section 2.3.2 covers canonicalization of the method.
	// Section 2.4 step 2 covers using it as input.

	// Method should always be caps.
	return []byte(fmt.Sprintf("\"@method\": %s\n", strings.ToUpper(method)))
}


func canonicalizeAuthority(authority string) []byte {
	// Section 2.3.4 covers canonicalization of the authority.
	// Section 2.4 step 2 covers using it as input.
	// _, err := fmt.Fprintf(out, "\"@authority\": %s\n", authority)
	return []byte(fmt.Sprintf("\"@authority\": %s\n", authority))
}

func canonicalizePath(url nurl.URL) []byte {
	// Section 2.3.7 covers canonicalization of the path.
	// Section 2.4 step 2 covers using it as input.
	return []byte(fmt.Sprintf("\"@path\": %s\n", url.Path))
}

// The @query derived component refers to the query component of the
// HTTP request message.  The component value is the entire normalized
// query string defined by [RFC3986], including the leading ? character.
// The value is normalized according to the rules in [HTTP],
// Section 4.2.3.  Namely, percent-encoded octets are decoded.  If used,
// the @query component identifier MUST occur only once in the covered
// components.
//
// For example, the following request message:
//
// POST /path?param=value&foo=bar&baz=batman HTTP/1.1
// Host: www.example.com
//
// Would result in the following @query component value:
// ?param=value&foo=bar&baz=batman
//
// And the following signature base line:
//
// "@query": ?param=value&foo=bar&baz=batman
//
// Section 2.3.8 covers canonicalization of the query.
// Section 2.4 step 2 covers using it as input.
func canonicalizeQuery(url nurl.URL) ([]byte, error) {
	// Get query strings without the ?s
	rawQuery := url.RawQuery

	// If the query string is absent from the request message, the value is
	// the leading ? character alone: ?
    // Resulting in the following signature base line:
    //   "@query": ?
	rawQuery = "?" + url.RawQuery

	// The value is normalized according to the rules in [HTTP], Section 4.2.3. 
	// Namely, percent-encoded octets are decoded.
	query, err := nurl.QueryUnescape(rawQuery)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to canonicalize query component of the http request. %w", err)
	}

	return []byte(fmt.Sprintf("\"@query\": %s\n", query)), nil
}


func canonicalizeSignatureParams(sp *signatureParams) []byte {
	// Section 2.3.1 covers canonicalization of the signature parameters
	return []byte(fmt.Sprintf("\"@signature-params\": %s", sp.normalizeValues()))

}


// HTTP Message Signatures have metadata properties that provide
//    information regarding the signature's generation and verification,
//    such as the set of covered components, a timestamp, identifiers for
//    verification key material, and other utilities.

//    The signature parameters component name is @signature-params.  This
//    message component's value is REQUIRED as part of the signature base
//    (Section 2.4) but the component identifier MUST NOT be enumerated
//    within the set of covered components itself.

//    The signature parameters component value is the serialization of the
//    signature parameters for this signature, including the covered
//    components set with all associated parameters.  These parameters
//    include any of the following:

//    *  created: Creation time as an Integer UNIX timestamp value.  Sub-
//       second precision is not supported.  Inclusion of this parameter is
//       RECOMMENDED.

//    *  expires: Expiration time as an Integer UNIX timestamp value.  Sub-
//       second precision is not supported.

//    *  nonce: A random unique value generated for this signature as a
//       String value.

//    *  alg: The HTTP message signature algorithm from the HTTP Message
//       Signature Algorithm Registry, as a String value.

//    *  keyid: The identifier for the key material as a String value.

//    Additional parameters can be defined in the HTTP Signature Parameters
//    Registry (Section 6.2.2).
type signatureParams struct {
	id string

	coveredComponents   []string
	// The identifier for the key material as a String value.
	keyID   *string
	// The HTTP message signature algorithm from the HTTP Message Signature Algorithm Registry, as a String value.
	alg     *string
	//Creation time as an Integer UNIX timestamp value.  
	//Sub-second precision is not supported.  Inclusion of this parameter is RECOMMENDED.
	created *time.Time
	// Expiration time as an Integer UNIX timestamp value.  Sub-second precision is not supported.
	expires *time.Time
	// A random unique value generated for this signature as a String value.
	nonce   *string
}


// Cannonicalized the values but not the entire thing
// This allows this func to be used to build the header
func (sp signatureParams) normalizeValues() []byte {
	components := make([]string, len(sp.coveredComponents))

	// Transform all coverend components to lowercase and
	// wrap each component with ""
	// Do not separate with a comma
	for i, component := range sp.coveredComponents {
		components[i] = fmt.Sprintf("\"%s\"", strings.ToLower(component))
	}

	// Each CC must be separated by a single white space
	// EX: ("@target-uri" "@authority" "date" "cache-control")
	sigParams := fmt.Sprintf("(%s)", strings.Join(components, " "))

	if sp.created != nil {
		sigParams += fmt.Sprintf(";created=%d", time.Now().Unix())
	}

	if sp.expires != nil {
		sigParams += fmt.Sprintf(";expires=%d", sp.expires.Unix())
	}
	
	if sp.keyID != nil {
		sigParams += fmt.Sprintf(";keyid=%s", *sp.keyID)
	}

	if sp.alg != nil {
		sigParams += fmt.Sprintf(";alg=%s", *sp.alg)
	}

	if sp.nonce != nil {
		sigParams += fmt.Sprintf(";nonce=%s", *sp.nonce)
	}

	return []byte(sigParams)
}

var errMalformedSignatureInput = errors.New("malformed signature-input header")

func parseStringComponent(component string) (string, error) {
	n := len(component)

	if n < 2 {
		return component, errMalformedSignatureInput
	}

	if component[0] != '"' && component[n - 1] != '"' {
		return component, errMalformedSignatureInput
	}

	return strings.Trim(component, `"`), nil
}

func parseSignatureParams(in string) (signatureParams, error) {
	sp := signatureParams{}

	// Seperate components from  associated parameters
	// Components will be strings delimeted by a single whitespace inside ()
	// Right now there are only ["created", "expires", "nonce", "alg", "keyid"]
	// The associated parameters will be appended to the end of the string delimited by ';'
	// 
	// EX: ["("@method" "@path" "@query" "authorization" "content-type" "content-digest")", "created=1657133676", 'nonce="foo"']
	parts := strings.Split(in, ";")
	if len(parts) < 1 {
		// Associated parameters are optional at the bare minimum the string will consist of 
		// No covered components: ()
		return sp, errMalformedSignatureInput
	}

	componentStr := parts[0]

	// The Covered Components MUST be encapsulated by ()
	if componentStr[0] != '(' || componentStr[len(parts[0])-1] != ')' {
		return sp, errMalformedSignatureInput
	}

	// Strip leading and trailing parenthesis:
	// '"@method" "@path" "@query" "authorization" "content-type" "content-digest"'
	componentStr = componentStr[1:len(componentStr)-1]

	// Components will be delimeted by string 
	// ["@method", "@path", "@query", "authorization", "content-type", "content-digest"]
	components := strings.Split(parts[0][1:len(parts[0])-1], " ")

	// Now that we have an approximate length
	sp.coveredComponents = make([]string, len(components))

	// Components are not required, it is acceptible to have none 
	// Otherwise validate and normalize component
	for i, component := range components {
		n := len(component)

		if n < 2 {
			return sp, errMalformedSignatureInput
		}

		if component[0] != '"' && component[n - 1] != '"' {
			return sp, errMalformedSignatureInput
		}

		sp.coveredComponents[i] = strings.Trim(component, `"`)
	}


	// Index 1 through n will be the associated parameters
	// They are not required so it is acceptable to have none 
	// EX: ["created=1657133676", 'nonce="foo"']]
	for _, param := range parts[1:] {
		// Parse key and value 
		// ["created", "1657133676"]
		paramParts := strings.Split(param, "=")
		if len(paramParts) != 2 {
			return sp, errMalformedSignatureInput
		}
		
		var covParam string
		var err error
		// TODO: error when not wrapped in quotes
		switch paramParts[0] {
		case "alg":
			*sp.alg, err = parseStringComponent(paramParts[1])
			if err != nil {
				return sp, err
			}
		case "keyid":
			covParam  = strings.Trim(paramParts[1], `"`)
			sp.keyID = &covParam
		case "nonce":
			covParam = strings.Trim(paramParts[1], `"`)
			sp.nonce  = &covParam
		case "created":
			i, err := strconv.ParseInt(paramParts[1], 10, 64)
			if err != nil {
				return sp, errMalformedSignatureInput
			}
			t := time.Unix(i, 0)
			
			sp.created = &t
		case "expires":
			i, err := strconv.ParseInt(paramParts[1], 10, 64)
			if err != nil {
				return sp, errMalformedSignatureInput
			}
			t := time.Unix(i, 0)
			sp.expires = &t
		default:
			// TODO: unknown params could be kept? hard to say.
			return sp, errMalformedSignatureInput
		}
	}

	return sp, nil
}


func canonicalizeDerivedComponent(component string, msg message) ([]byte, error) {
	var err error
	var value []byte

	switch component {
	case "@method":
		value = canonicalizeMethod(msg.Method)
	case "@path":
		value = canonicalizePath(*msg.URL)
	case "@query":
		value, err = canonicalizeQuery(*msg.URL)
	case "@authority":
		value = canonicalizeAuthority(msg.Authority)
	default:
		return value, fmt.Errorf("unsupported derived component %v", component)
	}

	if err != nil {
		return value, fmt.Errorf("issue deriving component %s, %w", component, err)
	}

	return value, nil
}

func cannonicalizeDictionary(name string, headers http.Header) ([]byte, string, error) {
	builder := bytes.Buffer{}
	values := headers.Values(name)
	headerName := strings.ToLower(name)

	if len(values) != 1 {
		return nil, builder.String(), fmt.Errorf("")
	}

	// Dictionaries will be in the form:
	//  Example-Dict: a=1, b=2;x=1;y=2, c=(a   b    c), d
	rawDict := values[0]

	// Split the dictionary by key/value pair
	// Each kv pair is delimited by comma
	// Resulting: ["a=1", "b=2;x=1;y=2", "c=(a   b    c)", "d"]
	members := strings.Split(rawDict, ",")


	// Cannonicalize each memeber of the dictionary into the buff
	for _, member := range members {
		// Parse key/value pair 
		// EX: " a=1    "

		// Remove excess white space: "a=1"
		// Parse key and value into array ["a", "1"]
		pair := strings.Split(strings.TrimSpace(member), "=")
		if len(pair) < 2 {
			return builder.Bytes(), headerName, fmt.Errorf(
				"invalid dictionary member %s",
				member,
			)
		}

		key := strings.TrimSpace(pair[0])

		// TODO: Remove all excess whitespace
		// spec references "strict member_value algorithm."
		// However, I am not able to find any ref to it
		value := strings.TrimSpace(pair[1])

		// Write to the buffer
		fmt.Fprintf(&builder, "\"%s\";key=\"%s\": %s\n", headerName, key, value)
	}

	return builder.Bytes(), headerName, nil
}