// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package keyfactor turns a security key into a factor a policy can ask.
//
// It is the piece between github.com/go-authn/fido, which speaks CTAP and
// knows about no operating system, and github.com/go-authn/mfa, which decides
// how much proof is enough and knows about no device. Neither should import
// the other; this does both, and nothing else does.
//
//	// From the registration: the credential ID and its public key.
//	pub, err := attestation.Parsed.PublicKey()
//	open := func(context.Context) (fido.Transport, error) { return linuxfido.Transport() }
//	f := keyfactor.New(open, keyfactor.Options{
//	    RPID:         "example.test",
//	    CredentialID: id,
//	    PublicKey:    pub,
//	})
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2}, somethingElse, f)
//
// # What is checked
//
// Whatever answers on the transport is a device, not necessarily THE key: a
// programmable USB board can speak CTAP as well as a security key can. So the
// answer is verified against what the registration recorded -- the relying
// party hash, the credential ID when the device names one, and the signature
// over the authenticator data and a fresh random challenge, with the
// credential's public key. A device that does not hold the credential's
// private key cannot produce that signature, whatever flags it claims.
//
// # What is not, and cannot be
//
// A PIN is sent to whatever device answers, before anything is signed: CTAP
// has the platform hand the key LEFT(SHA-256(PIN), 16), encrypted under a
// secret agreed with the device itself. A forged device holding no credential
// is refused here, but it has still received that hash, and a short PIN falls
// to an offline search in moments. That is inherent to CTAP, not something
// this package can fix: use a long PIN, and do not type one into a key whose
// provenance is unknown.
//
// # Why it is not in a platform package
//
// It was, twice — once for macOS and once, nearly, for Linux. The two copies
// differed in one line: which [fido.Transport] to open. Everything else — the
// assertion, the flag checks, the refusal to spend somebody's last PIN attempt
// — is the same everywhere CTAP is, which is everywhere.
//
// So the platform package supplies an [Opener] and keeps what is genuinely
// platform-specific: how a key is found, and what it means when there is none.
package keyfactor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	fido "github.com/go-authn/fido"
	"github.com/go-authn/mfa"
)

// Opener produces a transport to the attached key.
//
// It is where the platform lives: go-macos/fido and go-gnulinux/fido each have
// one. An Opener that finds nothing should wrap its error with
// [mfa.ErrUnavailable] — through [Unavailable] — because an empty USB port has
// refused nobody, and a policy counts "could not be asked" separately from
// "said no".
type Opener func(context.Context) (fido.Transport, error)

// Unavailable marks an error as "there was nothing here to ask".
func Unavailable(err error) error {
	return fmt.Errorf("%w: %w", mfa.ErrUnavailable, err)
}

// Options describes what to ask the key.
type Options struct {
	// RPID is the relying party the credential belongs to. Required.
	RPID string
	// CredentialID is what a registration returned. Empty asks the key for a
	// discoverable credential, which it has only if one was registered with
	// the "rk" option. When set, an answer naming any other credential is
	// refused.
	CredentialID []byte
	// PublicKey is the credential's public key, from the registration
	// (fido.AuthData.PublicKey on the attestation). Required: the signature
	// it verifies is the only thing that tells the key that was registered
	// from any device that answers CTAP. Only P-256 is accepted.
	PublicKey *ecdsa.PublicKey
	// PIN, when set, asks the key to establish WHO is holding it rather than
	// only that somebody is.
	//
	// It travels no further than the key: what goes over the wire is the first
	// sixteen bytes of its SHA-256, encrypted under a secret agreed for that
	// one exchange. It is still a secret in a Go string, so a caller that can
	// avoid holding one should.
	PIN string
	// Name is what to call this key when talking to a person. Empty picks a
	// sensible default.
	Name string
}

// New makes a factor.
func New(open Opener, o Options) mfa.Factor { return factor{open: open, opts: o} }

type factor struct {
	open Opener
	opts Options
}

func (f factor) Name() string {
	if f.opts.Name != "" {
		return f.opts.Name
	}
	if f.opts.PIN != "" {
		return "your security key and its PIN"
	}
	return "your security key"
}

// Kind is possession, and it stays possession when a PIN is used.
//
// A PIN entered INTO THE KEY is not a factor a policy can count separately: it
// never reaches this machine, it protects the key rather than identifying the
// person to us, and counting it would let one object masquerade as two
// factors. What it changes is the strength of the possession proof, which
// shows up as the verified bit in the assertion, not as a second kind.
func (f factor) Kind() mfa.Kind { return mfa.Possession }

// Verify asks the key.
func (f factor) Verify(ctx context.Context) error {
	if f.open == nil {
		return errors.New("keyfactor: no opener; the platform package supplies one")
	}
	if f.opts.RPID == "" {
		return errors.New("keyfactor: a security key needs a relying party id to assert for")
	}
	if f.opts.PublicKey == nil {
		return errors.New("keyfactor: no public key for the credential; " +
			"without one any device that answers would pass, so pass the one from the registration")
	}
	if f.opts.PublicKey.Curve != elliptic.P256() {
		return errors.New("keyfactor: the credential's public key is not on P-256, the only curve verified here")
	}
	t, err := f.open(ctx)
	if err != nil {
		return err
	}
	k, err := fido.Open(ctx, t)
	if err != nil {
		_ = t.Close()
		return err
	}
	defer k.Close()

	// The client-data hash is a fresh random challenge, and the signature
	// covers it: a FIXED hash would let a recorded assertion be replayed at
	// this function for ever.
	// crypto/rand.Read "never returns an error, and always fills b entirely":
	// it crashes the program rather than handing back a short read. So there is
	// no branch to write here, and writing one would be dead weight no test
	// could ever reach.
	var hash [sha256.Size]byte
	rand.Read(hash[:]) //nolint:errcheck // documented never to fail

	req := fido.GetAssertionRequest{
		RPID:           f.opts.RPID,
		ClientDataHash: hash[:],
		Options:        map[string]bool{"up": true},
	}
	if len(f.opts.CredentialID) > 0 {
		req.Allow = []fido.Credential{{ID: f.opts.CredentialID}}
	}
	if f.opts.PIN != "" {
		tok, err := f.token(ctx, k)
		if err != nil {
			return err
		}
		req.Token = tok
		req.Options["uv"] = true
	}

	a, err := k.GetAssertion(ctx, req)
	if err != nil {
		return err
	}
	// ⛔ Whatever answered is a device, not necessarily the key. Before this
	// was checked, a device holding no credential -- a zero rpIdHash, a
	// one-byte "signature", somebody else's credential ID, UP|UV claimed --
	// satisfied the factor. The flags below mean something only once the
	// signature over them has been verified.
	if rp := sha256.Sum256([]byte(f.opts.RPID)); a.Parsed.RPIDHash != rp {
		return fmt.Errorf("keyfactor: %s answered for another relying party", f.Name())
	}
	if len(f.opts.CredentialID) > 0 && len(a.Credential.ID) > 0 && !bytes.Equal(a.Credential.ID, f.opts.CredentialID) {
		return fmt.Errorf("keyfactor: %s answered with a credential other than the one asked for", f.Name())
	}
	digest := sha256.Sum256(append(append([]byte{}, a.AuthData...), hash[:]...))
	if !ecdsa.VerifyASN1(f.opts.PublicKey, digest[:], a.Signature) {
		return fmt.Errorf("keyfactor: %s answered with a signature the credential's key did not make", f.Name())
	}
	// The key answering is not enough: it must say a person was there.
	if !a.Parsed.Flags.Has(fido.FlagUP) {
		return fmt.Errorf("keyfactor: %s answered without anyone touching it", f.Name())
	}
	if f.opts.PIN != "" && !a.Parsed.Flags.Has(fido.FlagUV) {
		return fmt.Errorf("keyfactor: %s was asked to establish who holds it and did not", f.Name())
	}
	return nil
}

// token buys a PIN/UV token, having first asked how many attempts are left.
//
// Asking first is not politeness. A wrong PIN costs a retry, a key that runs
// out locks until it is unplugged and then permanently -- taking every
// credential on it -- and a factor that spent somebody's last attempt on a
// typo would have destroyed something.
func (f factor) token(ctx context.Context, k *fido.Key) (fido.Token, error) {
	r, err := k.PINRetries(ctx)
	if err != nil {
		return fido.Token{}, err
	}
	if r.PowerCycle {
		return fido.Token{}, fmt.Errorf("keyfactor: %s will take no more PINs until it is unplugged", f.Name())
	}
	if r.PIN <= 1 {
		return fido.Token{}, fmt.Errorf(
			"keyfactor: %s has %d attempt(s) left and this one is not being spent on a guess; "+
				"unlock it another way first", f.Name(), r.PIN)
	}
	// Protocol two where the key offers it: it separates the encryption key
	// from the authentication key and prepends a fresh initialisation vector.
	proto := fido.PINProtocolOne
	if info, err := k.GetInfo(ctx); err == nil {
		for _, p := range info.PINProtocols {
			if fido.PINProtocol(p) == fido.PINProtocolTwo {
				proto = fido.PINProtocolTwo
			}
		}
	}
	return k.PINToken(ctx, f.opts.PIN, proto, fido.PermGetAssertion, f.opts.RPID)
}

// compile-time proof that the factor satisfies the interface.
var _ mfa.Factor = factor{}
