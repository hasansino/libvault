package libvault

import (
	"context"
	"fmt"
	"log/slog"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	authK8 "github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/pkg/errors"
)

//go:generate mockgen -source $GOFILE -package mocks -destination mocks/mocks.go

type stdVaultLogicAccessor interface {
	Read(path string) (*vault.Secret, error)
}

const (
	K8DefaultMountPath          = "kubernetes"
	K8DefaultServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

var (
	ErrNoAuth     = errors.New("not authenticated")
	ErrNoData     = errors.New("no data returned for secret")
	ErrNoResponse = errors.New("no response received from vault")
)

// Vault is a simple wrapper around vault api client.
type Vault struct {
	client   *vault.Client
	stdVault stdVaultLogicAccessor
	logger   *slog.Logger
}

// New creates new instance of vault client.
// Checks for connectivity before returning.
func New(host string, opts ...Option) (*Vault, error) {
	v := new(Vault)
	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.New(slog.DiscardHandler)
	}

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = host
	vaultCfg.Logger = v.logger

	if vaultCfg.Error != nil {
		return nil, fmt.Errorf("failed to create client: %w", vaultCfg.Error)
	}

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	_, err = client.Sys().Health()
	if err != nil {
		return nil, fmt.Errorf("vault server is not available: %w", err)
	}

	v.client = client

	return v, nil
}

// Client returns original vault api client.
func (v *Vault) Client() *vault.Client {
	return v.client
}

// SetNamespace for current client.
func (v *Vault) SetNamespace(n string) {
	v.client.SetNamespace(n)
}

func (v *Vault) TokenAuth(token string) error {
	v.client.SetToken(token)
	v.stdVault = v.client.Logical()
	v.logger.Debug("authenticated")
	return nil
}

// AppRoleAuth authenticates in vault using approle engine
// @see https://www.vaultproject.io/api-docs/auth/approle
func (v *Vault) AppRoleAuth(roleID string, secretID string) error {
	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID, &auth.SecretID{FromString: secretID},
	)
	if err != nil {
		return fmt.Errorf("failed to initialize approle auth: %w", err)
	}

	authInfo, err := v.client.Auth().Login(context.TODO(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	if authInfo == nil {
		return errors.New("failed to authenticate: empty auth info")
	}

	v.logger.Debug("authenticated")

	v.stdVault = v.client.Logical()

	return nil
}

// K8Auth authenticates in vault using kubernetes engine
// @see https://www.vaultproject.io/api-docs/auth/kubernetes
func (v *Vault) K8Auth(role string, saPath string, mountPath string) error {
	if len(saPath) == 0 {
		saPath = K8DefaultServiceAccountPath
	}
	if len(mountPath) == 0 {
		mountPath = K8DefaultMountPath
	}

	k8Auth, err := authK8.NewKubernetesAuth(
		role,
		authK8.WithServiceAccountTokenPath(saPath),
		authK8.WithMountPath(mountPath),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize k8 auth: %w", err)
	}

	authInfo, err := v.client.Auth().Login(context.TODO(), k8Auth)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	if authInfo == nil {
		return errors.New("failed to authenticate: empty auth info")
	}

	v.logger.Debug("authenticated")

	v.stdVault = v.client.Logical()

	return nil
}

// Retrieve secret by its path
// Authentication is required before retrieving secrets.
func (v *Vault) Retrieve(path string) (map[string]interface{}, error) {
	if v.stdVault == nil {
		return nil, ErrNoAuth
	}

	s, err := v.stdVault.Read(path)
	if err != nil {
		return nil, errors.Wrap(err, "retrieve")
	}
	if s == nil {
		return nil, ErrNoResponse
	}

	for _, w := range s.Warnings {
		v.logger.Warn(w)
	}

	if s.Data != nil {
		if tmp, found := s.Data["data"]; found {
			if tmp2, ok := tmp.(map[string]interface{}); ok {
				return tmp2, nil
			}
		}
	}

	return nil, ErrNoData
}
