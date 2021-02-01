package client

import (
	"io/ioutil"
	"path"
	"testing"

	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func TestGetRootCAsPools(t *testing.T) {
	ca, err := ioutil.ReadFile(path.Join("testdata", "vault-ca.pem"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		cfg  config.TLSConfig
	}{
		{
			name: "PEM encoded",
			cfg: config.TLSConfig{
				VaultCAPEM: string(ca),
			},
		},
		{
			name: "file",
			cfg: config.TLSConfig{
				VaultCACertPath: path.Join("testdata", "vault-ca.pem"),
			},
		},
		{
			name: "directory",
			cfg: config.TLSConfig{
				VaultCADirectory: "testdata",
			},
		},
		{
			name: "system",
			cfg:  config.TLSConfig{},
		},
	} {
		pool, err := getRootCAsPools(tc.cfg)
		require.NoError(t, err, tc.name)
		require.True(t, len(pool.Subjects()) > 0)
	}
}

func TestGetRootCAsAsPoolsError(t *testing.T) {
	ca, err := ioutil.ReadFile(path.Join("testdata", "bad_directory", "not-a-ca.pem"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		cfg  config.TLSConfig
	}{
		{
			name: "PEM encoded error",
			cfg: config.TLSConfig{
				VaultCAPEM: string(ca),
			},
		},
		{
			name: "file error",
			cfg: config.TLSConfig{
				VaultCACertPath: path.Join("testdata", "bad_directory", "not-a-ca.pem"),
			},
		},
		{
			name: "directory error",
			cfg: config.TLSConfig{
				VaultCADirectory: path.Join("testdata", "bad_directory"),
			},
		},
	} {
		_, err := getRootCAsPools(tc.cfg)
		require.Error(t, err, tc.name)
	}
}
