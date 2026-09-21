package credential

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/canonical"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
)

// Signer holds the issuer key. It is the only component in this service that
// touches private key material.
type Signer struct {
	priv ed25519.PrivateKey
	did  string
}

// NewSigner wraps a private key and derives the issuer DID from it.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	id, err := did.FromEd25519(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, did: id}, nil
}

// DID returns the issuer identifier.
func (s *Signer) DID() string { return s.did }

// IssueOptions are the parameters of one issuance.
type IssueOptions struct {
	SubjectDID   string
	Name         string
	Organisation string
	Capabilities []Capability
	ValidFor     time.Duration
	Types        []string
	Parent       string
}

// Issue builds and signs a capability credential.
func (s *Signer) Issue(opt IssueOptions) (*Credential, error) {
	if !did.Valid(opt.SubjectDID) {
		return nil, fmt.Errorf("issue: subject %q is not a valid Ed25519 did:key", opt.SubjectDID)
	}
	if len(opt.Capabilities) == 0 {
		return nil, fmt.Errorf("issue: at least one capability is required")
	}
	for _, c := range opt.Capabilities {
		if c.Action == "" || c.Store == "" {
			return nil, fmt.Errorf("issue: capability %+v has an empty field; "+
				"use \"*\" explicitly if a wildcard is intended", c)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	types := opt.Types
	if len(types) == 0 {
		types = []string{TypeVerifiable, TypeCapability}
	}

	vc := &Credential{
		Context:      []string{ContextW3C, ContextOptimusDB},
		ID:           "urn:uuid:" + uuid.NewString(),
		Type:         types,
		Issuer:       s.did,
		IssuanceDate: now.Format(time.RFC3339),
		Subject: Subject{
			ID:               opt.SubjectDID,
			Name:             opt.Name,
			Organisation:     opt.Organisation,
			Capabilities:     opt.Capabilities,
			ParentCredential: opt.Parent,
		},
	}
	if opt.ValidFor > 0 {
		vc.ExpirationDate = now.Add(opt.ValidFor).Format(time.RFC3339)
	}

	vc.Proof = &Proof{
		Type:               SuiteEd25519,
		Created:            now.Format(time.RFC3339),
		ProofPurpose:       PurposeAssertion,
		VerificationMethod: did.VerificationMethod(s.did),
	}

	sig, err := s.signCredential(vc)
	if err != nil {
		return nil, err
	}
	vc.Proof.ProofValue = sig
	return vc, nil
}

// signCredential hashes the credential with the proof value cleared and signs
// the digest. The remaining proof fields are inside the signed payload, so the
// purpose, the creation time and the verification method cannot be altered.
func (s *Signer) signCredential(vc *Credential) (string, error) {
	clone := *vc
	if clone.Proof != nil {
		p := *clone.Proof
		p.ProofValue = ""
		clone.Proof = &p
	}
	digest, err := canonical.Hash(&clone)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return "z" + base58.Encode(ed25519.Sign(s.priv, digest)), nil
}

// SignRecord signs an arbitrary record destined for a store, used for trusted
// issuer entries and revocations so that their provenance is checkable.
func (s *Signer) SignRecord(v interface{}) (string, error) {
	digest, err := canonical.Hash(v)
	if err != nil {
		return "", err
	}
	return "z" + base58.Encode(ed25519.Sign(s.priv, digest)), nil
}
