// Package keys loads issuer key material and refuses to proceed when the file
// is readable by anyone other than its owner.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mr-tron/base58"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
)

// File is the on-disk representation of a key pair. Only privateKeyMultibase
// is secret; the DID is derived from it and stored for convenience.
type File struct {
	DID                 string `json:"did"`
	KeyType             string `json:"keyType"`
	Created             string `json:"created"`
	Label               string `json:"label,omitempty"`
	PrivateKeyMultibase string `json:"privateKeyMultibase"`
}

// Generate creates a new Ed25519 key pair and its did:key identifier.
func Generate(label string) (*File, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: generate: %w", err)
	}
	id, err := did.FromEd25519(pub)
	if err != nil {
		return nil, nil, err
	}
	return &File{
		DID:                 id,
		KeyType:             "Ed25519",
		Created:             time.Now().UTC().Format(time.RFC3339),
		Label:               label,
		PrivateKeyMultibase: "z" + base58.Encode(priv.Seed()),
	}, priv, nil
}

// Save writes a key file with mode 0600, failing if the path already exists so
// that an existing key is never silently overwritten.
func (f *File) Save(path string) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keys: create %s: %w", path, err)
	}
	defer fh.Close()
	if _, err := fh.Write(b); err != nil {
		return err
	}
	return nil
}

// Load reads a key file and returns the private key.
//
// The permission check is not decoration. An issuer key readable by other
// local accounts is equivalent to a published key, and the failure is silent
// unless something refuses to start.
func Load(path string) (ed25519.PrivateKey, *File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: %s: %w", path, err)
	}
	// An issuer key readable by other accounts is equivalent to a published
	// key, so this is a hard failure by default.
	//
	// The exception is a bind mount from a filesystem that cannot express Unix
	// permissions. Docker Desktop on Windows reports every bind-mounted file as
	// 0777 whatever its permissions on the host, which would otherwise make
	// local development impossible. The escape hatch is explicit and noisy.
	//
	// Kubernetes is unaffected: a Secret mounted with defaultMode 0400 reports
	// the real mode, so the check stays live where it matters.
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		if os.Getenv("OPTIMUS_ALLOW_INSECURE_KEY_PERMS") != "1" {
			return nil, nil, fmt.Errorf(
				"keys: %s has mode %04o; it must not be readable by group or others.\n"+
					"  On Linux:   chmod 600 %s\n"+
					"  On a Windows bind mount the mode is always reported as 0777.\n"+
					"  For development only, set OPTIMUS_ALLOW_INSECURE_KEY_PERMS=1.",
				path, mode, path)
		}
		fmt.Fprintf(os.Stderr,
			"WARNING: key file %s has mode %04o and the permission check is "+
				"disabled. Never do this outside development.\n", path, mode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("keys: parse %s: %w", path, err)
	}
	if f.KeyType != "Ed25519" {
		return nil, nil, fmt.Errorf("keys: unsupported key type %q", f.KeyType)
	}
	if len(f.PrivateKeyMultibase) < 2 || f.PrivateKeyMultibase[0] != 'z' {
		return nil, nil, fmt.Errorf("keys: privateKeyMultibase is not base58btc multibase")
	}
	seed, err := base58.Decode(f.PrivateKeyMultibase[1:])
	if err != nil {
		return nil, nil, fmt.Errorf("keys: decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("keys: expected a %d byte seed, got %d",
			ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Guard against a file whose recorded DID does not match its key, which
	// would otherwise produce credentials nobody can verify.
	derived, err := did.FromEd25519(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	if f.DID != "" && f.DID != derived {
		return nil, nil, fmt.Errorf(
			"keys: file records DID %s but the private key derives %s", f.DID, derived)
	}
	f.DID = derived
	return priv, &f, nil
}
