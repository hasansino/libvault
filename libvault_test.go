package libvault

import (
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/hasansino/libvault/mocks"
)

func newTestStdClient(t *testing.T) *Vault {
	t.Helper()

	ctrl := gomock.NewController(t)
	return &Vault{
		stdVault: mocks.NewMockstdVaultLogicAccessor(ctrl),
	}
}

func TestRetrieve_Success(t *testing.T) {
	client := newTestStdClient(t)
	stdVault, ok := client.stdVault.(*mocks.MockstdVaultLogicAccessor)
	require.True(t, ok)
	stdVault.EXPECT().Read(gomock.Any()).Return(
		&vault.Secret{Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "bar",
			},
		}}, nil,
	)
	result, err := client.Retrieve("secret/path")
	require.NoError(t, err)
	assert.True(t, assert.ObjectsAreEqual(map[string]interface{}{"foo": "bar"}, result))
}

func TestRetrieve_EmptyData(t *testing.T) {
	client := newTestStdClient(t)
	stdVault, ok := client.stdVault.(*mocks.MockstdVaultLogicAccessor)
	require.True(t, ok)
	stdVault.EXPECT().Read(gomock.Any()).Return(
		&vault.Secret{Data: map[string]interface{}{}}, nil,
	)
	_, err := client.Retrieve("secret/path")
	assert.Equal(t, ErrNoData, err)
}

func TestRetrieve_DataNotMap(t *testing.T) {
	client := newTestStdClient(t)
	stdVault, ok := client.stdVault.(*mocks.MockstdVaultLogicAccessor)
	require.True(t, ok)
	stdVault.EXPECT().Read(gomock.Any()).Return(
		&vault.Secret{Data: map[string]interface{}{
			"data": "test",
		}}, nil,
	)
	_, err := client.Retrieve("secret/path")
	require.Error(t, err)
	assert.Equal(t, ErrNoData, err)
}

func TestRetrieve_NotAuthorized(t *testing.T) {
	client := &Vault{}
	_, err := client.Retrieve("secret/path")
	require.Error(t, err)
	assert.Equal(t, ErrNoAuth, err)
}
