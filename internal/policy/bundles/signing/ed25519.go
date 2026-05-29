package signing

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/policy/bundles/manifest"
)

// Signer handles Ed25519 manifest signing.
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

func NewSigner(priv ed25519.PrivateKey, keyID string) *Signer {
	return &Signer{
		privateKey: priv,
		keyID:      keyID,
	}
}

func (s *Signer) SignManifest(m *manifest.BundleManifest) error {
	const op = "policy.bundles.signing.SignManifest"

	m.Signature.KeyID = s.keyID
	m.Signature.Algorithm = "Ed25519"
	m.Signature.SignedAt = time.Now().UTC()

	// Create payload to sign (canonical representation)
	payload := fmt.Sprintf("%s|%s|%s", m.BundleID, m.Version, m.SHA256)

	sig := ed25519.Sign(s.privateKey, []byte(payload))
	m.Signature.Signature = sig

	return nil
}

// Verifier handles Ed25519 signature validation.
type Verifier struct {
	publicKeys map[string]ed25519.PublicKey
}

func NewVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{publicKeys: keys}
}

func (v *Verifier) Verify(m manifest.BundleManifest) error {
	const op = "policy.bundles.signing.Verifier.Verify"

	pub, ok := v.publicKeys[m.Signature.KeyID]
	if !ok {
		return apperr.Newf(op, "unrecognized key ID: %s", m.Signature.KeyID)
	}

	payload := fmt.Sprintf("%s|%s|%s", m.BundleID, m.Version, m.SHA256)

	if !ed25519.Verify(pub, []byte(payload), m.Signature.Signature) {
		return apperr.New(op, "invalid manifest signature")
	}

	return nil
}
