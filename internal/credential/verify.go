package credential

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/mr-tron/base58"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/canonical"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
)

// DefaultSkew is the tolerance applied to issuance and expiry comparisons.
const DefaultSkew = 60 * time.Second

// Verify performs the checks an OptimusDB agent performs, so that this service
// never hands out a credential it would itself reject. Running the verifier
// immediately after signing is the cheapest possible guard against a
// canonicalisation defect: a mismatch fails here rather than in the field.
func Verify(vc *Credential, skew time.Duration) error {
	if vc == nil {
		return fmt.Errorf("verify: no credential")
	}
	if vc.Proof == nil {
		// A credential without a proof is not verifiable; it is ordinary JSON
		// asserting whatever its author chose.
		return fmt.Errorf("verify: credential has no proof")
	}
	if vc.Proof.Type != SuiteEd25519 {
		return fmt.Errorf("verify: unsupported proof suite %q, expected %s",
			vc.Proof.Type, SuiteEd25519)
	}
	if vc.Proof.ProofValue == "" {
		return fmt.Errorf("verify: proof has no proofValue")
	}

	// The key named by the proof must be controlled by the issuer, otherwise a
	// credential could name one issuer and be signed by another.
	if got := did.SubjectOf(vc.Proof.VerificationMethod); got != vc.Issuer {
		return fmt.Errorf("verify: verificationMethod %q does not belong to issuer %q",
			vc.Proof.VerificationMethod, vc.Issuer)
	}

	pub, err := did.ToEd25519(vc.Issuer)
	if err != nil {
		return fmt.Errorf("verify: resolve issuer: %w", err)
	}

	clone := *vc
	p := *clone.Proof
	p.ProofValue = ""
	clone.Proof = &p

	digest, err := canonical.Hash(&clone)
	if err != nil {
		return fmt.Errorf("verify: canonicalise: %w", err)
	}

	sigStr := vc.Proof.ProofValue
	if len(sigStr) < 2 || sigStr[0] != 'z' {
		return fmt.Errorf("verify: proofValue is not base58btc multibase")
	}
	sig, err := base58.Decode(sigStr[1:])
	if err != nil {
		return fmt.Errorf("verify: decode proofValue: %w", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		return fmt.Errorf("verify: signature does not verify")
	}

	now := time.Now().UTC()
	if vc.IssuanceDate != "" {
		issued, err := time.Parse(time.RFC3339, vc.IssuanceDate)
		if err != nil {
			return fmt.Errorf("verify: malformed issuanceDate: %w", err)
		}
		if now.Add(skew).Before(issued) {
			return fmt.Errorf("verify: credential is not yet valid (issued %s)", vc.IssuanceDate)
		}
	}
	if exp, ok := vc.Expiry(); ok {
		if now.Add(-skew).After(exp) {
			return fmt.Errorf("verify: credential expired at %s", vc.ExpirationDate)
		}
	}
	return nil
}
