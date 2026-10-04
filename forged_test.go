// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package keyfactor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	fido "github.com/go-authn/fido"
)

// evilKey is an attacker-controlled CTAPHID device (a $5 programmable USB
// board, or any malicious Transport). It holds NO credential, never checks the
// PIN, and answers every assertion with garbage.
type evilKey struct {
	*fakeKey
	r          *fido.Reassembler
	stolenHash []byte
	crackedPIN string
}

func (e *evilKey) Send(report []byte) error {
	before := len(e.fakeKey.inbox)
	var msg fido.Message
	var done bool
	if binary.BigEndian.Uint32(report[0:4]) != fido.BroadcastChannel {
		msg, done, _ = e.r.Feed(report)
	}
	if err := e.fakeKey.Send(report); err != nil {
		return err
	}
	if !done || msg.Cmd != fido.CmdCBOR || len(msg.Data) == 0 {
		return nil
	}
	switch msg.Data[0] {
	case 0x02: // getAssertion: wrong rpIdHash, UP|UV claimed, 1-byte "signature", foreign credential id
		e.fakeKey.inbox = e.fakeKey.inbox[:before]
		authData := make([]byte, 37) // rpIdHash all zero, sign count 0
		authData[32] = byte(fido.FlagUP | fido.FlagUV)
		e.fakeKey.inbox = append(e.fakeKey.inbox, e.fakeKey.reply(0, map[uint64]any{
			1: map[string]any{"type": "public-key", "id": []byte("NOT-the-registered-credential")},
			2: authData,
			3: []byte{0x00},
		})...)
	case 0x06:
		var req map[uint64]cbor.RawMessage
		_ = cbor.Unmarshal(msg.Data[1:], &req)
		var sub uint
		_ = cbor.Unmarshal(req[0x02], &sub)
		if sub != 9 {
			return nil
		}
		e.fakeKey.inbox = e.fakeKey.inbox[:before]
		var peer map[int64]cbor.RawMessage
		_ = cbor.Unmarshal(req[0x03], &peer)
		var hashEnc []byte
		_ = cbor.Unmarshal(req[0x06], &hashEnc)
		_, aesKey, _ := e.pin.derive(peer)
		e.stolenHash, _ = decryptTwo(aesKey, hashEnc)
		for i := 0; i < 1000000; i++ { // offline crack, no retry counter involved
			for _, w := range []int{4, 6} {
				c := fmt.Sprintf("%0*d", w, i)
				h := sha256.Sum256([]byte(c))
				if string(h[:16]) == string(e.stolenHash) && e.crackedPIN == "" {
					e.crackedPIN = c
				}
			}
			if e.crackedPIN != "" {
				break
			}
		}
		enc, _ := encryptTwo(aesKey, e.pin.token) // any token: PIN never checked
		e.fakeKey.inbox = append(e.fakeKey.inbox, e.fakeKey.reply(0, map[uint64]any{2: enc})...)
	}
	return nil
}

// ⛔ A device that holds no credential does not satisfy the factor, whatever it
// claims. Before the answer was verified, this one -- a zero rpIdHash, a
// one-byte "signature", somebody else's credential ID, UP|UV set, the PIN never
// checked -- passed as the possession factor.
//
// What it still gets is the PIN's hash: CTAP sends it to whatever answers,
// before anything is signed, and a four-digit PIN falls to an offline search
// at once. That is the protocol, not this package, and the README says so;
// the test pins it so that the documentation is not quietly wrong.
func TestADeviceHoldingNoCredentialDoesNotSatisfyTheFactor(t *testing.T) {
	k := newFakeKey()
	k.pinRetries = 8
	k.pin = newPINAuthenticator("irrelevant-the-forged-device-never-checks")
	e := &evilKey{fakeKey: k, r: fido.NewReassembler(fakeChannel)}
	open := func(context.Context) (fido.Transport, error) { return e, nil }
	f := New(open, Options{PublicKey: pub, RPID: "bank.example", CredentialID: []byte("registered-cred-id"), PIN: "4821"})
	err := f.Verify(context.Background())
	if err == nil {
		t.Fatal("a device holding no credential satisfied the possession factor")
	}
	if !strings.Contains(err.Error(), "another relying party") {
		t.Errorf("error = %q", err)
	}
	if e.crackedPIN != "4821" {
		t.Errorf("the forged device recovered %q; the README says a short PIN is learnt offline", e.crackedPIN)
	}
}
