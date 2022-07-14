package bls_test

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/bls"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	"github.com/stretchr/testify/require"
)

func TestMarshalJSON(t *testing.T) {
	require := require.New(t)
	privKey := bls.GenPrivKey()
	pk := privKey.PubKey()

	registry := types.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	bz, err := cdc.MarshalInterfaceJSON(pk)
	require.NoError(err)

	var pk2 cryptotypes.PubKey
	err = cdc.UnmarshalInterfaceJSON(bz, &pk2)
	require.NoError(err)
	require.True(pk2.Equals(pk))
}
