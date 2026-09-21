package credential_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/canonical"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/credential"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
)

func newSigner(t *testing.T) *credential.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := credential.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func subjectDID(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := did.FromEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The round trip that matters: what we sign must verify with the same code an
// agent runs. A canonicalisation defect shows up here.
func TestIssueThenVerify(t *testing.T) {
	s := newSigner(t)
	vc, err := s.Issue(credential.IssueOptions{
		SubjectDID:   subjectDID(t),
		Name:         "Attica Solar Ingest",
		Capabilities: []credential.Capability{{Action: "crudget", Store: "kbmetadata"}},
		ValidFor:     90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Verify(vc, credential.DefaultSkew); err != nil {
		t.Fatalf("freshly issued credential does not verify: %v", err)
	}
}

// Verification must survive a trip through JSON, because that is how a
// credential reaches an agent.
func TestVerifyAfterSerialisation(t *testing.T) {
	s := newSigner(t)
	vc, _ := s.Issue(credential.IssueOptions{
		SubjectDID:   subjectDID(t),
		Capabilities: []credential.Capability{{Action: "crudput", Store: "kbmetadata"}},
		ValidFor:     time.Hour,
	})
	raw, err := json.Marshal(vc)
	if err != nil {
		t.Fatal(err)
	}
	var round credential.Credential
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if err := credential.Verify(&round, credential.DefaultSkew); err != nil {
		t.Fatalf("verification failed after a JSON round trip: %v", err)
	}
}

func TestTamperedFieldFailsVerification(t *testing.T) {
	s := newSigner(t)
	vc, _ := s.Issue(credential.IssueOptions{
		SubjectDID:   subjectDID(t),
		Capabilities: []credential.Capability{{Action: "crudget", Store: "kbmetadata"}},
		ValidFor:     time.Hour,
	})

	// Widening a capability after signing must be detected.
	vc.Subject.Capabilities[0].Store = "*"
	if err := credential.Verify(vc, credential.DefaultSkew); err == nil {
		t.Fatal("a widened capability verified; the signature does not cover the subject")
	}
}

func TestUnsignedCredentialIsRejected(t *testing.T) {
	vc := &credential.Credential{
		Context: []string{credential.ContextW3C},
		Type:    []string{credential.TypeVerifiable, credential.TypeCapability},
		Issuer:  subjectDID(t),
		Subject: credential.Subject{
			ID:           subjectDID(t),
			Capabilities: []credential.Capability{{Action: "*", Store: "*"}},
		},
	}
	if err := credential.Verify(vc, credential.DefaultSkew); err == nil {
		t.Fatal("an unsigned credential verified; it must be rejected")
	}
}

func TestExpiredCredentialIsRejected(t *testing.T) {
	s := newSigner(t)
	vc, _ := s.Issue(credential.IssueOptions{
		SubjectDID:   subjectDID(t),
		Capabilities: []credential.Capability{{Action: "crudget", Store: "kbmetadata"}},
		ValidFor:     time.Nanosecond,
	})
	time.Sleep(2 * time.Millisecond)
	if err := credential.Verify(vc, 0); err == nil {
		t.Fatal("an expired credential verified")
	}
}

// A credential naming one issuer but signed by another key must not verify.
func TestVerificationMethodMustMatchIssuer(t *testing.T) {
	s := newSigner(t)
	vc, _ := s.Issue(credential.IssueOptions{
		SubjectDID:   subjectDID(t),
		Capabilities: []credential.Capability{{Action: "crudget", Store: "kbmetadata"}},
		ValidFor:     time.Hour,
	})
	vc.Issuer = subjectDID(t)
	if err := credential.Verify(vc, credential.DefaultSkew); err == nil {
		t.Fatal("issuer and verificationMethod mismatch was accepted")
	}
}

func TestPermits(t *testing.T) {
	vc := &credential.Credential{Subject: credential.Subject{
		Capabilities: []credential.Capability{
			{Action: "crudget", Store: "*"},
			{Action: "crudput", Store: "kbmetadata"},
		},
	}}
	cases := []struct {
		action, store string
		want          bool
	}{
		{"crudget", "kbtrust", true},
		{"crudput", "kbmetadata", true},
		{"crudput", "kbtrust", false},
		{"cruddelete", "kbmetadata", false},
		{"crudput", "kbmet", false}, // not a prefix match
	}
	for _, c := range cases {
		if got := vc.Permits(c.action, c.store); got != c.want {
			t.Errorf("Permits(%q,%q) = %v, want %v", c.action, c.store, got, c.want)
		}
	}
}

func TestDIDRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id, err := did.FromEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "did:key:z") {
		t.Fatalf("unexpected prefix in %q", id)
	}
	back, err := did.ToEd25519(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(pub) {
		t.Fatal("round trip did not recover the public key")
	}
}

func TestDIDRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "did:web:example.com", "did:key:QnotMultibase",
		"did:key:z", "did:key:z6Mk",
	} {
		if _, err := did.ToEd25519(bad); err == nil {
			t.Errorf("%q was accepted as a did:key", bad)
		}
	}
}

// Canonicalisation must not depend on key insertion order.
func TestCanonicalIsOrderIndependent(t *testing.T) {
	a := map[string]interface{}{"b": 2, "a": 1, "c": map[string]interface{}{"z": 1, "y": 2}}
	b := map[string]interface{}{"c": map[string]interface{}{"y": 2, "z": 1}, "a": 1, "b": 2}

	ca, err := canonical.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := canonical.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("canonical forms differ:\n  %s\n  %s", ca, cb)
	}
}

func TestCanonicalIsStable(t *testing.T) {
	v := map[string]interface{}{"n": 42, "f": 1.5, "s": "hello", "t": true, "z": nil}
	first, _ := canonical.Marshal(v)
	for i := 0; i < 50; i++ {
		again, _ := canonical.Marshal(v)
		if string(first) != string(again) {
			t.Fatalf("canonical form is not stable across runs")
		}
	}
}
