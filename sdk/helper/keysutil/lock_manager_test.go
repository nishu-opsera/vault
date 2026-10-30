// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestImportPolicy(t *testing.T) {
	lm, err := NewLockManager(false, 0)
	require.NoError(t, err)

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testKeys, err := generateTestKeys()
	require.NoError(t, err)

	testCases := map[string]struct {
		req       PolicyRequest
		key       []byte
		expectErr bool
	}{
		"import AES key": {
			req: PolicyRequest{
				Name:         "test-aes-key",
				KeyType:      KeyType_AES256_GCM96,
				Storage:      storage,
				IsPrivateKey: true,
			},
			key: testKeys[KeyType_AES256_GCM96],
		},
		"import RSA key": {
			req: PolicyRequest{
				Name:         "test-rsa-key",
				KeyType:      KeyType_RSA2048,
				Storage:      storage,
				IsPrivateKey: true,
			},
			key: testKeys[KeyType_RSA2048],
		},
		"import ECDSA key": {
			req: PolicyRequest{
				Name:         "test-ecdsa-key",
				KeyType:      KeyType_ECDSA_P256,
				Storage:      storage,
				IsPrivateKey: true,
			},
			key: testKeys[KeyType_ECDSA_P256],
		},
		"import ED25519 key": {
			req: PolicyRequest{
				Name:         "test-ed25519-key",
				KeyType:      KeyType_ED25519,
				Storage:      storage,
				IsPrivateKey: true,
			},
			key: testKeys[KeyType_ED25519],
		},
		"import ed25519 with derivation": {
			req: PolicyRequest{
				Name:         "ed25519-derived",
				KeyType:      KeyType_ED25519,
				Storage:      storage,
				IsPrivateKey: true,
				Derived:      true,
			},
			key: testKeys[KeyType_ED25519],
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			err = lm.ImportPolicy(ctx, tt.req, tt.key, rand.Reader)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				pol, upserted, err := lm.GetPolicy(ctx, PolicyRequest{Name: tt.req.Name, Storage: storage}, rand.Reader)
				require.NoError(t, err)
				require.False(t, upserted)

				defer pol.Unlock()

				require.Equal(t, tt.req.KeyType, pol.Type)
				if tt.req.Derived {
					require.True(t, pol.Derived)
					require.Equal(t, Kdf_hkdf_sha256, pol.KDF)
				}
			}
		})
	}
}

func TestRestorePolicy_NilPolicy(t *testing.T) {
	lm, err := NewLockManager(false, 0)
	require.NoError(t, err)

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	// Create backup data without "policy" field (causes nil Policy)
	invalidBackup := base64.StdEncoding.EncodeToString([]byte(`{"archived_keys": null}`))

	_, err = lm.RestorePolicy(ctx, storage, "test-key", invalidBackup, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "backup data does not contain a valid policy")
}

// TestGetPolicy_MLKEMDerivedConvergentRejection verifies GetPolicy rejects
// derived/convergent for ML-KEM types and allows plain upsert with a public key.
func TestGetPolicy_MLKEMDerivedConvergentRejection(t *testing.T) {
	t.Parallel()

	keyTypes := []KeyType{KeyType_ML_KEM_768, KeyType_ML_KEM_1024}

	for _, keyType := range keyTypes {
		t.Run(keyType.String()+"/derived", func(t *testing.T) {
			t.Parallel()
			lm, err := NewLockManager(false, 0)
			require.NoError(t, err)
			storage := &logical.InmemStorage{}

			_, _, err = lm.GetPolicy(context.Background(), PolicyRequest{
				Upsert:  true,
				Storage: storage,
				KeyType: keyType,
				Name:    "mlkem-derived",
				Derived: true,
			}, rand.Reader)
			require.Error(t, err)
			require.Contains(t, err.Error(), "key derivation and convergent encryption not supported")
		})

		t.Run(keyType.String()+"/convergent", func(t *testing.T) {
			t.Parallel()
			lm, err := NewLockManager(false, 0)
			require.NoError(t, err)
			storage := &logical.InmemStorage{}

			_, _, err = lm.GetPolicy(context.Background(), PolicyRequest{
				Upsert:     true,
				Storage:    storage,
				KeyType:    keyType,
				Name:       "mlkem-convergent",
				Convergent: true,
			}, rand.Reader)
			require.Error(t, err)
			require.Contains(t, err.Error(), "key derivation and convergent encryption not supported")
		})

		t.Run(keyType.String()+"/plain", func(t *testing.T) {
			t.Parallel()
			lm, err := NewLockManager(false, 0)
			require.NoError(t, err)
			storage := &logical.InmemStorage{}

			p, upserted, err := lm.GetPolicy(context.Background(), PolicyRequest{
				Upsert:  true,
				Storage: storage,
				KeyType: keyType,
				Name:    "mlkem-plain",
			}, rand.Reader)
			require.NoError(t, err)
			require.True(t, upserted)
			require.NotNil(t, p)
			defer p.Unlock()

			require.Equal(t, 1, p.LatestVersion)
			entry, ok := p.Keys["1"]
			require.True(t, ok)
			require.NotEmpty(t, entry.FormattedPublicKey)
		})
	}
}
