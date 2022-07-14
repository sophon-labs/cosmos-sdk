package bls

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

const (
	PrivKeyName   = "tendermint/PrivKeyBLS12"
	PubKeyName    = "tendermint/PubKeyBLS12"
	PrivKeySize   = 32
	PubKeySize    = 48
	SignatureSize = 96
	KeyType       = "bls12-381"
)

func init() {
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		panic(fmt.Sprintf("ERROR: %s", err))
	}
	err = bls.SetETHmode(bls.EthModeLatest)
	if err != nil {
		panic(fmt.Sprintf("ERROR: %s", err))
	}
}

var _ cryptotypes.PrivKey = &PrivKey{}
var _ codec.AminoMarshaler = &PrivKey{}

// GenPrivKey generates a new BLS12-381 private key.
func GenPrivKey() *PrivKey {
	sigKey := bls.SecretKey{}
	sigKey.SetByCSPRNG()
	sigKeyBytes := make([]byte, PrivKeySize)
	binary := sigKey.Serialize()
	if len(binary) != PrivKeySize {
		panic(fmt.Sprintf("unexpected BLS private key size: %d != %d", len(binary), PrivKeySize))
	}
	copy(sigKeyBytes[:], binary)
	return &PrivKey{Key: sigKeyBytes}
}

// Bytes marshals the privkey using amino encoding.
func (privKey PrivKey) Bytes() []byte {
	return privKey.Key
}

// Sign produces a signature on the provided message.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	if msg == nil {
		panic("Nil specified as the message")
	}
	blsKey := bls.SecretKey{}
	err := blsKey.Deserialize(privKey.Key)
	if err != nil {
		return nil, err
	}
	hash := sha512.Sum512_256(msg)
	sign := blsKey.SignHash(hash[:])
	return sign.Serialize(), nil
}

// PubKey gets the corresponding public key from the private key.
func (privKey *PrivKey) PubKey() cryptotypes.PubKey {
	blsKey := bls.SecretKey{}
	err := blsKey.Deserialize(privKey.Key)
	if err != nil {
		panic(fmt.Sprintf("Not a BLS12-381 private key: %X", privKey.Key))
	}
	pubKey := blsKey.GetPublicKey()
	pubkeyBytes := make([]byte, PubKeySize)
	binary := pubKey.Serialize()
	if len(binary) != PubKeySize {
		panic(fmt.Sprintf("unexpected BLS public key size: %d != %d", len(binary), PubKeySize))
	}
	copy(pubkeyBytes[:], binary)
	return &PubKey{Key: pubkeyBytes}
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	if privKey.Type() != other.Type() {
		return false
	}

	return subtle.ConstantTimeCompare(privKey.Bytes(), other.Bytes()) == 1
}

// Type returns information to identify the type of this key.
func (privKey PrivKey) Type() string {
	return KeyType
}

// MarshalAmino overrides Amino binary marshalling.
func (privKey PrivKey) MarshalAmino() ([]byte, error) {
	return privKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshalling.
func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PrivKeySize {
		return fmt.Errorf("invalid privkey size")
	}
	privKey.Key = bz

	return nil
}

// MarshalAminoJSON overrides Amino JSON marshalling.
func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) {
	// When we marshal to Amino JSON, we don't marshal the "key" field itself,
	// just its contents (i.e. the key bytes).
	return privKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshalling.
func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error {
	return privKey.UnmarshalAmino(bz)
}

var _ cryptotypes.PubKey = &PubKey{}
var _ codec.AminoMarshaler = &PubKey{}

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("pubkey is incorrect size")
	}

	return tmhash.SumTruncated(pubKey.Key)
}

// Bytes marshals the PubKey using amino encoding.
func (pubKey PubKey) Bytes() []byte {
	return pubKey.Key
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != SignatureSize {
		return false
	}
	blsPubKey := bls.PublicKey{}
	err := blsPubKey.Deserialize(pubKey.Key)
	if err != nil {
		return false
	}
	blsSign := bls.Sign{}
	err = blsSign.Deserialize(sig)
	if err != nil {
		return false
	}
	hash := sha512.Sum512_256(msg)
	return blsSign.VerifyHash(&blsPubKey, hash[:])
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12{%X}", pubKey.Key)
}

func (pubKey PubKey) Equals(other cryptotypes.PubKey) bool {
	if pubKey.Type() != other.Type() {
		return false
	}

	return subtle.ConstantTimeCompare(pubKey.Bytes(), other.Bytes()) == 1
}

// Type returns information to identify the type of this key.
func (pubKey PubKey) Type() string {
	return KeyType
}

// MarshalAmino overrides Amino binary marshalling.
func (pubKey PubKey) MarshalAmino() ([]byte, error) {
	return pubKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshalling.
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errors.Wrap(errors.ErrInvalidPubKey, "invalid pubkey size")
	}
	pubKey.Key = bz

	return nil
}

// MarshalAminoJSON overrides Amino JSON marshalling.
func (pubKey PubKey) MarshalAminoJSON() ([]byte, error) {
	// When we marshal to Amino JSON, we don't marshal the "key" field itself,
	// just its contents (i.e. the key bytes).
	return pubKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshalling.
func (pubKey *PubKey) UnmarshalAminoJSON(bz []byte) error {
	return pubKey.UnmarshalAmino(bz)
}
