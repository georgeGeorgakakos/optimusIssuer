// Package credential implements the OptimusDB capability credential: the W3C
// Verifiable Credential data model plus the capability grant used by the
// agents, together with signing and verification.
package credential

import "time"

const (
	ContextW3C       = "https://www.w3.org/2018/credentials/v1"
	ContextOptimusDB = "https://swarmchestrate.eu/contexts/optimusdb/v1"

	TypeVerifiable = "VerifiableCredential"
	TypeCapability = "OptimusDBCapability"
	TypePresent    = "VerifiablePresentation"

	SuiteEd25519 = "Ed25519Signature2020"

	PurposeAssertion      = "assertionMethod"
	PurposeAuthentication = "authentication"
)

// Capability is one grant: an action on a store. Either field may be "*".
//
// This is the point at which the model departs from role-based access control.
// A role is a name that means something only by reference to a table held
// somewhere else, which implies a server. A capability carries the grant
// itself, so a verifier needs nothing beyond the credential and a public key.
type Capability struct {
	Action string `json:"action"`
	Store  string `json:"store"`
}

// Subject is the credentialSubject of an OptimusDB capability credential.
type Subject struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	Organisation     string       `json:"organisation,omitempty"`
	Capabilities     []Capability `json:"capabilities"`
	ParentCredential string       `json:"parentCredential,omitempty"`
}

// Proof is a linked data proof. The same structure serves a credential, where
// the issuer signs, and a presentation, where the holder signs over a
// challenge.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	Challenge          string `json:"challenge,omitempty"`
	Domain             string `json:"domain,omitempty"`
	ProofValue         string `json:"proofValue"`
}

// Credential is a W3C Verifiable Credential carrying OptimusDB capabilities.
type Credential struct {
	Context        []string `json:"@context"`
	ID             string   `json:"id"`
	Type           []string `json:"type"`
	Issuer         string   `json:"issuer"`
	IssuanceDate   string   `json:"issuanceDate"`
	ExpirationDate string   `json:"expirationDate,omitempty"`
	Subject        Subject  `json:"credentialSubject"`
	Proof          *Proof   `json:"proof,omitempty"`
}

// Expiry parses expirationDate. A credential with no expiry returns the zero
// time, which callers must treat as "never expires" and warn about.
func (c *Credential) Expiry() (time.Time, bool) {
	if c.ExpirationDate == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, c.ExpirationDate)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Permits reports whether the capabilities cover an action on a store.
// Matching is exact except for the wildcard; it is not a prefix match, so
// "kb*" does not match "kbtrust".
func (c *Credential) Permits(action, store string) bool {
	for _, cap := range c.Subject.Capabilities {
		if cap.Action != action && cap.Action != "*" {
			continue
		}
		if store == "" || cap.Store == store || cap.Store == "*" {
			return true
		}
	}
	return false
}

// Request is what an application submits to ask for a credential. It is
// unsigned and carries no secret: the only key-derived field is a public DID.
type Request struct {
	ID                     string       `json:"id"`
	RequestType            string       `json:"request_type"`
	SubjectDID             string       `json:"subject_did"`
	Name                   string       `json:"name"`
	Organisation           string       `json:"organisation,omitempty"`
	Contact                string       `json:"contact,omitempty"`
	Deployment             string       `json:"deployment,omitempty"`
	Justification          string       `json:"justification,omitempty"`
	RequestedCapabilities  []Capability `json:"requested_capabilities"`
	RequestedValidityDays  int          `json:"requested_validity_days"`
	Status                 string       `json:"status"`  // pending | approved | rejected | issued
	RequestedAt            string       `json:"requested_at"`
	DecidedAt              string       `json:"decided_at,omitempty"`
	DecidedBy              string       `json:"decided_by,omitempty"`
	DecisionReason         string       `json:"decision_reason,omitempty"`
	IssuedCredentialID     string       `json:"issued_credential_id,omitempty"`
}

// TrustedIssuer is a record in the kbtrust store naming an issuer the swarm
// accepts, and bounding what that issuer may grant.
type TrustedIssuer struct {
	ID                 string       `json:"_id"`
	RecordType         string       `json:"record_type"`
	Name               string       `json:"name"`
	MayIssue           []string     `json:"may_issue"`
	MaxCapabilities    []Capability `json:"max_capabilities,omitempty"`
	MaxDelegationDepth int          `json:"max_delegation_depth"`
	Status             string       `json:"status"` // active | inactive
	AddedAt            string       `json:"added_at"`
	AddedBy            string       `json:"added_by"`
}

// Revocation withdraws a credential before its expiry.
type Revocation struct {
	ID           string `json:"_id"`
	RecordType   string `json:"record_type"`
	CredentialID string `json:"credential_id"`
	SubjectDID   string `json:"subject_did"`
	RevokedBy    string `json:"revoked_by"`
	Reason       string `json:"reason"`
	RevokedAt    string `json:"revoked_at"`
	PruneAfter   string `json:"prune_after,omitempty"`
}
