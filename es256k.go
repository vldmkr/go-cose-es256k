package es256k

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/veraison/go-cose"
)

const (
	// ECDSA using secp256k1 curve w/ SHA-256 by RFC 8812.
	// Requires an available crypto.SHA256.
	AlgorithmES256K cose.Algorithm = -47
)

type es256kSigner struct {
	key *secp256k1.PrivateKey
}

func NewSigner(key *secp256k1.PrivateKey) cose.Signer {
	return &es256kSigner{key: key}
}

func (es *es256kSigner) Algorithm() cose.Algorithm {
	return AlgorithmES256K
}

func (es *es256kSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	hash := sha256.Sum256(content)
	sig := ecdsa.SignCompact(es.key, hash[:], true)

	// remove the first byte which is compactSigRecoveryCode
	return sig[1:65], nil
}

type es256kVerifier struct {
	key *secp256k1.PublicKey
}

func NewVerifier(key *secp256k1.PublicKey) cose.Verifier {
	return &es256kVerifier{key: key}
}

func (ev *es256kVerifier) Algorithm() cose.Algorithm {
	return AlgorithmES256K
}

func (ev *es256kVerifier) Verify(content []byte, signature []byte) error {
	hash := sha256.Sum256(content)

	sig, err := signatureFromBytes(signature)
	if err != nil {
		return err
	}

	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	// see: https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
	// Serialize() would negate S value if it is over half order.
	// Hence, if the signature is different after Serialize() if should be rejected.
	modifiedSig, err := ecdsa.ParseDERSignature(sig.Serialize())
	if err != nil {
		return err
	}
	if !sig.IsEqual(modifiedSig) {
		return fmt.Errorf("malleable signature")
	}

	if verified := modifiedSig.Verify(hash[:], ev.key); !verified {
		return cose.ErrVerification
	}
	return nil
}

func signatureFromBytes(signature []byte) (*ecdsa.Signature, error) {
	if len(signature) != 64 {
		return nil, fmt.Errorf("invalid signature length")
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[0:32]); overflow {
		str := "invalid signature: R >= group order"
		return nil, fmt.Errorf(str)
	}
	if r.IsZero() {
		str := "invalid signature: R is 0"
		return nil, fmt.Errorf(str)
	}
	if overflow := s.SetByteSlice(signature[32:]); overflow {
		str := "invalid signature: S >= group order"
		return nil, fmt.Errorf(str)
	}
	if s.IsZero() {
		str := "invalid signature: S is 0"
		return nil, fmt.Errorf(str)
	}

	return ecdsa.NewSignature(&r, &s), nil
}
