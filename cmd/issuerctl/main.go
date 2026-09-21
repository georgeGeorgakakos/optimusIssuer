// Command issuerctl performs the operations that must happen offline: the key
// ceremony, genesis list production, and emergency signing when the service is
// unavailable or compromised.
//
// Nothing here talks to a network. It reads and writes files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/georgeGeorgakakos/optimusIssuer/internal/credential"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/did"
	"github.com/georgeGeorgakakos/optimusIssuer/internal/keys"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	case "issue":
		err = issue(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "genesis":
		err = genesis(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `issuerctl — offline operations for optimusIssuer

  keygen   --out FILE [--label TEXT]        create a key pair, print its DID
  inspect  --key FILE                       show a key's DID without exposing it
  issue    --key FILE --subject DID ...     sign a credential offline
  verify   --credential FILE                verify a credential, no network
  genesis  --key FILE [--key FILE ...]      emit the genesis trusted issuer list
  revoke   --key FILE --credential ID       emit a revocation record

All commands are local. None contacts a network.
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "path to write the key file")
	label := fs.String("label", "", "human readable label, recorded in the file")
	_ = fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	kf, _, err := keys.Generate(*label)
	if err != nil {
		return err
	}
	if err := kf.Save(*out); err != nil {
		return err
	}
	fmt.Printf("DID:  %s\n", kf.DID)
	fmt.Printf("key:  %s (mode 0600)\n\n", *out)
	fmt.Println("Publish the DID. Never copy the key file off this machine.")
	return nil
}

func inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	key := fs.String("key", "", "key file")
	_ = fs.Parse(args)

	_, kf, err := keys.Load(*key)
	if err != nil {
		return err
	}
	fmt.Printf("DID:      %s\n", kf.DID)
	fmt.Printf("type:     %s\n", kf.KeyType)
	fmt.Printf("created:  %s\n", kf.Created)
	fmt.Printf("label:    %s\n", kf.Label)
	return nil
}

type capList []credential.Capability

func (c *capList) String() string { return fmt.Sprintf("%d capabilities", len(*c)) }

func (c *capList) Set(v string) error {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("expected action:store, got %q", v)
	}
	*c = append(*c, credential.Capability{Action: parts[0], Store: parts[1]})
	return nil
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	key := fs.String("key", "", "issuer key file")
	subject := fs.String("subject", "", "subject did:key")
	name := fs.String("name", "", "subject name, recorded in the credential")
	org := fs.String("org", "", "subject organisation")
	days := fs.Int("days", 90, "validity in days")
	out := fs.String("out", "", "path to write the credential")
	var caps capList
	fs.Var(&caps, "capability", "action:store, repeatable")
	_ = fs.Parse(args)

	if *key == "" || *subject == "" || *out == "" {
		return fmt.Errorf("--key, --subject and --out are required")
	}
	if len(caps) == 0 {
		return fmt.Errorf("at least one --capability is required")
	}

	priv, _, err := keys.Load(*key)
	if err != nil {
		return err
	}
	signer, err := credential.NewSigner(priv)
	if err != nil {
		return err
	}
	vc, err := signer.Issue(credential.IssueOptions{
		SubjectDID:   *subject,
		Name:         *name,
		Organisation: *org,
		Capabilities: caps,
		ValidFor:     time.Duration(*days) * 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	// Verify immediately, with the same code an agent runs.
	if err := credential.Verify(vc, credential.DefaultSkew); err != nil {
		return fmt.Errorf("self-verification failed, refusing to write: %w", err)
	}

	b, _ := json.MarshalIndent(vc, "", "  ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("issued  %s\n", vc.ID)
	fmt.Printf("subject %s\n", vc.Subject.ID)
	fmt.Printf("expires %s\n", vc.ExpirationDate)
	fmt.Printf("written %s\n", *out)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("credential", "", "credential file")
	_ = fs.Parse(args)

	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var vc credential.Credential
	if err := json.Unmarshal(raw, &vc); err != nil {
		return err
	}
	if err := credential.Verify(&vc, credential.DefaultSkew); err != nil {
		return err
	}
	fmt.Println("signature   valid")
	fmt.Printf("issuer      %s\n", vc.Issuer)
	fmt.Printf("subject     %s\n", vc.Subject.ID)
	fmt.Printf("expires     %s\n", vc.ExpirationDate)
	for _, c := range vc.Subject.Capabilities {
		fmt.Printf("capability  %s on %s\n", c.Action, c.Store)
	}
	fmt.Println("\nNote: this checks the signature only. An agent additionally requires")
	fmt.Println("the issuer to appear in its trust list with status active.")
	return nil
}

func genesis(args []string) error {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	out := fs.String("out", "", "path to write issuers.json; stdout if empty")
	var keyPaths multiFlag
	var names multiFlag
	fs.Var(&keyPaths, "key", "key file, repeatable")
	fs.Var(&names, "name", "name for the corresponding key, repeatable")
	_ = fs.Parse(args)

	if len(keyPaths) == 0 {
		return fmt.Errorf("at least one --key is required")
	}
	list := make([]credential.TrustedIssuer, 0, len(keyPaths))
	for i, p := range keyPaths {
		_, kf, err := keys.Load(p)
		if err != nil {
			return err
		}
		name := kf.Label
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		list = append(list, credential.TrustedIssuer{
			ID:                 kf.DID,
			RecordType:         "trusted_issuer",
			Name:               name,
			MayIssue:           []string{credential.TypeCapability},
			MaxDelegationDepth: 2,
			Status:             "active",
			AddedAt:            time.Now().UTC().Format(time.RFC3339),
			AddedBy:            "genesis",
		})
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	if *out == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(*out, b, 0o644)
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	key := fs.String("key", "", "issuer key file")
	cred := fs.String("credential", "", "credential id to revoke")
	subject := fs.String("subject", "", "subject did, for the record")
	reason := fs.String("reason", "", "why")
	out := fs.String("out", "", "path to write the record; stdout if empty")
	_ = fs.Parse(args)

	_, kf, err := keys.Load(*key)
	if err != nil {
		return err
	}
	rev := credential.Revocation{
		ID:           "revocation:" + *cred,
		RecordType:   "revocation",
		CredentialID: *cred,
		SubjectDID:   *subject,
		RevokedBy:    kf.DID,
		Reason:       *reason,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(rev, "", "  ")
	if *out == "" {
		fmt.Println(string(b))
		fmt.Fprintln(os.Stderr, "\nWrite this record into the kbtrust store on any agent.")
		return nil
	}
	return os.WriteFile(*out, b, 0o644)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

var _ = did.Valid // keep the import meaningful for future validation helpers
