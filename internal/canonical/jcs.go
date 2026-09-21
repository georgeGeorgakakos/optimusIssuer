// Package canonical implements the subset of RFC 8785 (JSON Canonicalization
// Scheme) needed to hash a Verifiable Credential deterministically.
//
// Why JCS rather than URDNA2015: the W3C data model points at RDF dataset
// canonicalisation, which requires full JSON-LD processing, context resolution
// and a graph isomorphism algorithm. JCS canonicalises the JSON structure
// itself — object keys sorted by UTF-16 code unit, no insignificant
// whitespace, defined number formatting — and is a few hundred lines rather
// than a few thousand.
//
// The deviation is deliberate and is recorded in the design document. It means
// credentials issued here are not verifiable by a strict RDF-canonicalising
// verifier, and vice versa.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Hash returns the SHA-256 of the canonical serialisation of v.
func Hash(v interface{}) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// Marshal returns the RFC 8785 canonical form of v.
func Marshal(v interface{}) ([]byte, error) {
	// Round-trip through encoding/json so that struct tags, omitempty and
	// custom marshallers are honoured before canonicalisation.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: pre-marshal: %w", err)
	}
	var generic interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: decode: %w", err)
	}
	var out bytes.Buffer
	if err := write(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func write(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		return writeNumber(buf, t)
	case float64:
		return writeNumber(buf, json.Number(strconv.FormatFloat(t, 'g', -1, 64)))
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// RFC 8785 sorts by UTF-16 code unit, not by Go's byte order. For
		// the ASCII keys used throughout the credential model these agree,
		// but sort explicitly so non-ASCII keys behave correctly.
		sort.Slice(keys, func(i, j int) bool {
			return lessUTF16(keys[i], keys[j])
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeNumber applies the ECMAScript Number-to-String rules that RFC 8785
// requires. Integers within the safe range are emitted without a decimal
// point; everything else goes through the shortest round-trip form.
func writeNumber(buf *bytes.Buffer, n json.Number) error {
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical: %q is not a number: %w", n.String(), err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("canonical: %v cannot be represented", f)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		buf.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

// writeString emits a JSON string with the minimal escaping RFC 8785 allows.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
