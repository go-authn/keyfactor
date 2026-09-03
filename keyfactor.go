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
//	f := keyfactor.New(linuxfido.Transport, keyfactor.Options{
//	    RPID:         "example.test",
//	    CredentialID: id,
//	})
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2}, somethingElse, f)
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
	"context"
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
	// the "rk" option.
	CredentialID []byte
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

	// The client-data hash is random. Nothing here verifies the signature, so
	// there is no protocol to bind it to -- and a FIXED hash would let a
	// recorded assertion be replayed at this function for ever. A caller who
	// needs a verifiable assertion should use go-authn/fido directly.
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
