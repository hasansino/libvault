package tests

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	_ "embed"

	"github.com/hasansino/libvault"
)

var (
	//go:embed secrets/group1.json
	groupData1 []byte
	//go:embed secrets/group2.json
	groupData2 []byte
)

func TestVault(t *testing.T) {
	const (
		vaultAddr = "http://localhost:8200"
		token     = "qwerty"

		pathGroup1 = "some-domain/data/some-service/group1"
		pathGroup2 = "some-domain/data/some-service/group2"
	)

	var expected1 map[string]interface{}
	require.NoError(t, json.Unmarshal(groupData1, &expected1))

	var expected2 map[string]interface{}
	require.NoError(t, json.Unmarshal(groupData2, &expected2))

	vaultClient, err := libvault.New(vaultAddr)
	require.NoError(t, err)

	err = vaultClient.TokenAuth(token)
	require.NoError(t, err)

	secret, err := vaultClient.Retrieve(pathGroup1)
	require.NoError(t, err)
	require.Equal(t, expected1, secret)

	secret, err = vaultClient.Retrieve(pathGroup2)
	require.NoError(t, err)
	require.Equal(t, expected2, secret)
}
