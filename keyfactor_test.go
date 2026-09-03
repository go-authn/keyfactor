// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package keyfactor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	fido "github.com/go-authn/fido"
	"github.com/go-authn/mfa"
)

// A key that answers, built out of go-authn/fido's own exported framing.
//
// Faking the authenticator rather than the transport is what makes this
// package testable at all: everything it does happens between a CTAPHID
// handshake and a parsed assertion, and neither end is reachable from a test
// that stops at the wire.
type fakeKey struct {
	// flags is what the authenticator claims about the person: FlagUP that
	// somebody touched it, FlagUV that it established who they were.
	flags fido.Flags
	// pinRetries is what getPINRetries reports. Zero means "do not ask me".
	pinRetries uint
	powerCycle bool
	// status, when non-zero, is the CTAP error the key answers GetAssertion
	// with.
	status byte
	// noSignature makes the key answer an assertion with no signature, which
	// proves nothing.
	noSignature bool
	// pin plays the authenticator half of PIN/UV auth protocol two.
	pin *pinAuthenticator
	// pinStatus, when non-zero, is the error clientPIN answers with.
	pinStatus byte
	// infoStatus, when non-zero, is the error getInfo answers with.
	infoStatus byte
	// protocols is what getInfo advertises. Nil means [2 1].
	protocols []uint

	closed int
	inbox  [][]byte
	asked  []byte // the ctap commands seen, in order
	chn    *fido.Reassembler
	bcast  *fido.Reassembler
}

const fakeChannel = 0x11223344

func newFakeKey() *fakeKey {
	return &fakeKey{
		flags: fido.FlagUP,
		pin:   newPINAuthenticator("0000"),
		chn:   fido.NewReassembler(fakeChannel),
		bcast: fido.NewReassembler(fido.BroadcastChannel),
	}
}

func (f *fakeKey) Name() string { return "Test Key" }
func (f *fakeKey) Close() error { f.closed++; return nil }

func (f *fakeKey) Send(report []byte) error {
	var msg fido.Message
	var done bool
	if binary.BigEndian.Uint32(report[0:4]) == fido.BroadcastChannel {
		msg, done, _ = f.bcast.Feed(report)
	} else {
		msg, done, _ = f.chn.Feed(report)
	}
	if !done {
		return nil
	}
	switch msg.Cmd {
	case fido.CmdInit:
		payload := make([]byte, 17)
		copy(payload, msg.Data) // the nonce comes back unchanged
		binary.BigEndian.PutUint32(payload[8:12], fakeChannel)
		payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
		payload[16] = byte(fido.CapCBOR | fido.CapWink)
		p, _ := fido.Split(fido.BroadcastChannel, fido.CmdInit, payload)
		f.inbox = append(f.inbox, p...)
	case fido.CmdCBOR:
		f.inbox = append(f.inbox, f.ctap2(msg.Data)...)
	}
	return nil
}

func (f *fakeKey) Receive(ctx context.Context) ([]byte, error) {
	if len(f.inbox) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := f.inbox[0]
	f.inbox = f.inbox[1:]
	return r, nil
}

func (f *fakeKey) reply(status byte, body map[uint64]any) [][]byte {
	out := []byte{status}
	if body != nil {
		enc, _ := cbor.CTAP2EncOptions().EncMode()
		b, _ := enc.Marshal(body)
		out = append(out, b...)
	}
	p, _ := fido.Split(fakeChannel, fido.CmdCBOR, out)
	return p
}

func (f *fakeKey) ctap2(data []byte) [][]byte {
	if len(data) == 0 {
		return f.reply(0x01, nil)
	}
	cmd := data[0]
	f.asked = append(f.asked, cmd)
	switch cmd {
	case 0x04: // getInfo
		if f.infoStatus != 0 {
			return f.reply(f.infoStatus, nil)
		}
		protocols := f.protocols
		if protocols == nil {
			protocols = []uint{2, 1}
		}
		return f.reply(0, map[uint64]any{
			1: []string{"FIDO_2_0", "FIDO_2_1"},
			3: make([]byte, 16),
			6: protocols,
		})
	case 0x06: // clientPIN
		if f.pinStatus != 0 {
			return f.reply(f.pinStatus, nil)
		}
		return f.clientPIN(data[1:])
	case 0x02: // getAssertion
		if f.status != 0 {
			return f.reply(f.status, nil)
		}
		authData := make([]byte, 37)
		h := sha256.Sum256([]byte("example.test"))
		copy(authData, h[:])
		authData[32] = byte(f.flags)
		binary.BigEndian.PutUint32(authData[33:], 7)
		body := map[uint64]any{2: authData}
		if !f.noSignature {
			body[3] = []byte{0x30, 0x44, 0x01, 0x02}
		}
		return f.reply(0, body)
	}
	return f.reply(0x01, nil)
}

// opener hands the factor this fake, and counts how often it was asked.
func opener(k *fakeKey) (Opener, *int) {
	n := 0
	return func(context.Context) (fido.Transport, error) { n++; return k, nil }, &n
}

func TestAKeyThatAnswersSatisfiesTheFactor(t *testing.T) {
	k := newFakeKey()
	open, calls := opener(k)
	f := New(open, Options{RPID: "example.test", CredentialID: []byte("cred")})

	if f.Kind() != mfa.Possession {
		t.Errorf("a security key is %v, want possession", f.Kind())
	}
	if err := f.Verify(context.Background()); err != nil {
		t.Fatalf("a key that answered was refused: %v", err)
	}
	if *calls != 1 {
		t.Errorf("the opener was called %d times", *calls)
	}
	if k.closed == 0 {
		t.Error("the key was not closed")
	}
}

// TestAKeyThatAnswersWithoutAnyoneTouchingItIsRefused. An authenticator that
// signs on its own proves it exists, not that a person is there -- which is
// the entire content of a possession factor.
func TestAKeyThatAnswersWithoutAnyoneTouchingItIsRefused(t *testing.T) {
	k := newFakeKey()
	k.flags = 0
	open, _ := opener(k)
	err := New(open, Options{RPID: "example.test"}).Verify(context.Background())
	if err == nil {
		t.Fatal("an untouched key satisfied the factor")
	}
	if !strings.Contains(err.Error(), "without anyone touching") {
		t.Errorf("error = %q", err)
	}
}

// TestVerificationIsCheckedInTheANSWER, not merely requested. A key may be
// asked for "uv" and simply not do it, and the request is not the proof.
func TestVerificationIsCheckedInTheAnswer(t *testing.T) {
	k := newFakeKey()
	k.flags = fido.FlagUP // present, but not verified
	k.pinRetries = 8
	open, _ := opener(k)
	err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background())
	if err == nil {
		t.Fatal("a key that did not verify satisfied a verified factor")
	}
	if !strings.Contains(err.Error(), "did not") {
		t.Errorf("error = %q", err)
	}

	k2 := newFakeKey()
	k2.flags = fido.FlagUP | fido.FlagUV
	k2.pinRetries = 8
	open2, _ := opener(k2)
	if err := New(open2, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background()); err != nil {
		t.Fatalf("a key that verified was refused: %v", err)
	}
	// It really did buy a token: clientPIN was asked before getAssertion.
	if len(k2.asked) < 2 || k2.asked[len(k2.asked)-1] != 0x02 {
		t.Errorf("the commands were %#v", k2.asked)
	}
}

// TestTheLastPINAttemptIsNotSpentOnAGuess. A key that runs out locks until it
// is unplugged, and then permanently, taking every credential on it.
func TestTheLastPINAttemptIsNotSpentOnAGuess(t *testing.T) {
	for _, retries := range []uint{0, 1} {
		k := newFakeKey()
		k.pinRetries = retries
		open, _ := opener(k)
		err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background())
		if err == nil {
			t.Fatalf("with %d attempts left, the key was asked anyway", retries)
		}
		if !strings.Contains(err.Error(), "not being spent on a guess") {
			t.Errorf("error = %q", err)
		}
		// And getAssertion was never reached.
		for _, c := range k.asked {
			if c == 0x02 {
				t.Error("getAssertion was sent despite the refusal")
			}
		}
	}
}

func TestAKeyThatWillTakeNoMorePINsSaysSo(t *testing.T) {
	k := newFakeKey()
	k.powerCycle = true
	open, _ := opener(k)
	err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unplugged") {
		t.Errorf("error = %v", err)
	}
}

// TestAnAssertionWithNoSignatureProvesNothing.
func TestAnAssertionWithNoSignatureIsRefused(t *testing.T) {
	k := newFakeKey()
	k.noSignature = true
	open, _ := opener(k)
	if err := New(open, Options{RPID: "example.test"}).Verify(context.Background()); err == nil {
		t.Fatal("an assertion with no signature satisfied the factor")
	}
}

func TestAKeyThatRefusesIsARefusal(t *testing.T) {
	k := newFakeKey()
	k.status = 0x27 // CTAP2_ERR_ACTION_TIMEOUT, in the specification's numbering
	open, _ := opener(k)
	err := New(open, Options{RPID: "example.test"}).Verify(context.Background())
	if err == nil {
		t.Fatal("a key that refused satisfied the factor")
	}
	if errors.Is(err, mfa.ErrUnavailable) {
		t.Error("a refusal was reported as nothing being there")
	}
}

// TestAnEmptyPortIsNotARefusal: the Opener decides, and the factor passes its
// verdict through untouched.
func TestAnEmptyPortIsNotARefusal(t *testing.T) {
	noKey := errors.New("no security key is attached")
	f := New(func(context.Context) (fido.Transport, error) {
		return nil, Unavailable(noKey)
	}, Options{RPID: "example.test"})

	err := f.Verify(context.Background())
	if !errors.Is(err, mfa.ErrUnavailable) {
		t.Errorf("error = %v, want it to read as unavailable", err)
	}
	if !errors.Is(err, noKey) {
		t.Error("the reason was lost")
	}
	// And a policy counts it separately.
	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1}, f)
	if err == nil {
		t.Fatal("a machine with no key satisfied a policy")
	}
	for _, a := range r.Answers {
		if !a.Unavailable() {
			t.Errorf("%s was reported as a refusal", a.Name)
		}
	}
}

// TestAnOpenerThatFailsForARealReasonIsARefusal, not an absence: the two go
// through the same return, and only the Opener knows which it was.
func TestAnOpenerThatFailsIsPassedThrough(t *testing.T) {
	boom := errors.New("the device is on fire")
	f := New(func(context.Context) (fido.Transport, error) { return nil, boom }, Options{RPID: "e.test"})
	err := f.Verify(context.Background())
	if !errors.Is(err, boom) {
		t.Errorf("error = %v", err)
	}
	if errors.Is(err, mfa.ErrUnavailable) {
		t.Error("an ordinary failure was excused as an absence")
	}
}

func TestAnIncompleteFactorIsRefusedBeforeAnythingIsOpened(t *testing.T) {
	k := newFakeKey()
	open, calls := opener(k)

	if err := New(open, Options{}).Verify(context.Background()); err == nil {
		t.Error("a factor with no relying party was accepted")
	} else if !strings.Contains(err.Error(), "relying party id") {
		t.Errorf("error = %q", err)
	}
	if err := New(nil, Options{RPID: "e.test"}).Verify(context.Background()); err == nil {
		t.Error("a factor with no opener was accepted")
	} else if !strings.Contains(err.Error(), "opener") {
		t.Errorf("error = %q", err)
	}
	if *calls != 0 {
		t.Errorf("the key was opened %d times for an incomplete factor", *calls)
	}
}

func TestTheFactorSaysWhatItIs(t *testing.T) {
	if got := New(nil, Options{}).Name(); got != "your security key" {
		t.Errorf("Name() = %q", got)
	}
	if got := New(nil, Options{PIN: "0000"}).Name(); !strings.Contains(got, "PIN") {
		t.Errorf("Name() = %q, which does not say a PIN will be asked for", got)
	}
	if got := New(nil, Options{Name: "the yubikey on the desk"}).Name(); got != "the yubikey on the desk" {
		t.Errorf("Name() = %q", got)
	}
}

// TestAKeyThatWillNotHandshakeIsReportedAndClosed. Whatever went wrong, the
// transport must not be left open: a leaked device stops the next attempt from
// finding it.
func TestAKeyThatWillNotHandshakeIsClosed(t *testing.T) {
	k := newFakeKey()
	k.chn, k.bcast = fido.NewReassembler(0), fido.NewReassembler(0) // answers nothing
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	open, _ := opener(k)
	if err := New(open, Options{RPID: "e.test"}).Verify(ctx); err == nil {
		t.Fatal("a key that never answered satisfied the factor")
	}
	if k.closed == 0 {
		t.Error("the transport was left open after a failed handshake")
	}
}

// clientPIN answers the three subcommands this package uses: how many attempts
// are left, the key agreement, and the token itself.
func (f *fakeKey) clientPIN(body []byte) [][]byte {
	var req map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(body, &req); err != nil {
		return f.reply(0x12, nil) // CTAP2_ERR_INVALID_CBOR
	}
	var sub uint
	_ = cbor.Unmarshal(req[0x02], &sub)
	switch sub {
	case 1: // getPINRetries
		if f.powerCycle {
			return f.reply(0, map[uint64]any{3: uint(0), 4: true})
		}
		return f.reply(0, map[uint64]any{3: f.pinRetries})
	case 2: // getKeyAgreement
		return f.reply(0, map[uint64]any{1: f.pin.coseKey()})
	case 9: // getPinUvAuthTokenUsingPinWithPermissions
		var peer map[int64]cbor.RawMessage
		if err := cbor.Unmarshal(req[0x03], &peer); err != nil {
			return f.reply(0x12, nil)
		}
		var hashEnc []byte
		if err := cbor.Unmarshal(req[0x06], &hashEnc); err != nil {
			return f.reply(0x12, nil)
		}
		enc, err := f.pin.exchange(peer, hashEnc)
		if err != nil {
			return f.reply(0x31, nil) // CTAP2_ERR_PIN_INVALID
		}
		return f.reply(0, map[uint64]any{2: enc})
	}
	return f.reply(0x2B, nil) // CTAP2_ERR_UNSUPPORTED_OPTION
}

// TestAKeyThatWillNotSayHowManyAttemptsAreLeftIsNotGuessedAt. If the count
// cannot be had, the safe thing is to stop -- not to try one and see.
func TestAKeyThatWillNotSayHowManyAttemptsAreLeftIsRefused(t *testing.T) {
	k := newFakeKey()
	k.pinStatus = 0x2B // unsupported option
	open, _ := opener(k)
	err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background())
	if err == nil {
		t.Fatal("a key that would not say satisfied a verified factor")
	}
	for _, c := range k.asked {
		if c == 0x02 {
			t.Error("getAssertion was sent anyway")
		}
	}
}

// TestProtocolOneIsUsedWhenTwoIsNotOffered. The two are not a version number:
// one hashes the ECDH output once and uses those bytes as BOTH keys, with a
// zero IV and a truncated HMAC. A package that treated them as interchangeable
// would pass every round trip and be wrong on the wire.
func TestProtocolOneIsUsedWhenTwoIsNotOffered(t *testing.T) {
	k := newFakeKey()
	k.protocols = []uint{1}
	k.pinRetries = 8
	open, _ := opener(k)
	// The fake only plays protocol two, so asking it for one must FAIL -- which
	// is what proves the choice was made from what the key advertised rather
	// than hard-coded.
	err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background())
	if err == nil {
		t.Fatal("protocol two was used against a key offering only one")
	}
}

// TestAKeyThatWillNotDescribeItselfStillWorks. getInfo is asked only to learn
// which PIN protocol to use; a key that refuses gets protocol one, which every
// key that has ClientPIN at all supports.
func TestAKeyThatWillNotDescribeItselfFallsBackToProtocolOne(t *testing.T) {
	k := newFakeKey()
	k.infoStatus = 0x01
	k.pinRetries = 8
	open, _ := opener(k)
	// Again the fake plays only two, so this must fail rather than silently
	// pick two.
	if err := New(open, Options{RPID: "example.test", PIN: "0000"}).Verify(context.Background()); err == nil {
		t.Fatal("a key that would not describe itself was assumed to speak protocol two")
	}
}
