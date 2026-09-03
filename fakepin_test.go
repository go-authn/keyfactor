// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package keyfactor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

// The authenticator's half of PIN/UV auth protocol two, played by the fake.
//
// ⭐ This is written INDEPENDENTLY of go-authn/fido's client half, from the
// specification, and that is the point: if the two derivations disagree by a
// byte the exchange fails and the test says so. A fake that reused the code
// under test would agree with it for free, including when both are wrong.
//
// Protocol two: HKDF-SHA256 over the ECDH output with a 32-zero salt, two
// separate keys ("CTAP2 HMAC key" then "CTAP2 AES key"), a fresh
// initialisation vector prepended to every ciphertext, and an untruncated
// 32-byte HMAC. Protocol one is a different animal and is not played here.
type pinAuthenticator struct {
	priv *ecdh.PrivateKey
	// pin is what the key believes the PIN to be.
	pin string
	// token is what it hands out when the PIN is right.
	token []byte
}

func newPINAuthenticator(pin string) *pinAuthenticator {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	tok := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tok); err != nil {
		panic(err)
	}
	return &pinAuthenticator{priv: priv, pin: pin, token: tok}
}

// coseKey encodes the authenticator's public key the way CTAP2 does.
func (a *pinAuthenticator) coseKey() map[int64]any {
	b := a.priv.PublicKey().Bytes() // 0x04 || X || Y
	return map[int64]any{
		1:  2,        // kty: EC2
		3:  -25,      // alg: ECDH-ES + HKDF-256
		-1: 1,        // crv: P-256
		-2: b[1:33],  // x
		-3: b[33:65], // y
	}
}

// derive is the shared secret and the two keys made from it.
func (a *pinAuthenticator) derive(peer map[int64]cbor.RawMessage) (hmacKey, aesKey []byte, err error) {
	var x, y []byte
	if err := cbor.Unmarshal(peer[-2], &x); err != nil {
		return nil, nil, err
	}
	if err := cbor.Unmarshal(peer[-3], &y); err != nil {
		return nil, nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, nil, errors.New("the platform key is not a P-256 point")
	}
	raw := append([]byte{0x04}, append(x, y...)...)
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, nil, err
	}
	z, err := a.priv.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, 32)
	hmacKey = make([]byte, 32)
	aesKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 HMAC key")), hmacKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 AES key")), aesKey); err != nil {
		return nil, nil, err
	}
	return hmacKey, aesKey, nil
}

func decryptTwo(key, ct []byte) ([]byte, error) {
	if len(ct) < aes.BlockSize || (len(ct)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a whole number of blocks after its IV")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct)-aes.BlockSize)
	cipher.NewCBCDecrypter(blk, ct[:aes.BlockSize]).CryptBlocks(out, ct[aes.BlockSize:])
	return out, nil
}

func encryptTwo(key, pt []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, pt)
	return append(iv, out...), nil
}

// exchange plays getPinUvAuthTokenUsingPinWithPermissions.
func (a *pinAuthenticator) exchange(peer map[int64]cbor.RawMessage, pinHashEnc []byte) ([]byte, error) {
	_, aesKey, err := a.derive(peer)
	if err != nil {
		return nil, err
	}
	got, err := decryptTwo(aesKey, pinHashEnc)
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256([]byte(a.pin))
	if !hmac.Equal(got, want[:16]) {
		return nil, errors.New("wrong PIN")
	}
	return encryptTwo(aesKey, a.token)
}
