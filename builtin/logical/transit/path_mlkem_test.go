// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestTransit_MLKEMSanity is a quick create/read/encrypt/decrypt check with the
// VAULT_TRANSIT_ENABLE_MLKEM feature flag enabled. Full flag matrix coverage is
// a separate story.
func TestTransit_MLKEMSanity(t *testing.T) {
	t.Setenv(envTransitEnableMLKEM, "true")

	b, storage := createBackendWithStorage(t)

	createReq := &logical.Request{
		Path:      "keys/mlkem",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"type": "ml-kem-768",
		},
	}
	resp, err := b.HandleRequest(context.Background(), createReq)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %#v", resp)

	readReq := &logical.Request{
		Path:      "keys/mlkem",
		Operation: logical.ReadOperation,
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "read: %#v", resp)

	keys, ok := resp.Data["keys"].(map[string]map[string]interface{})
	if !ok {
		// Handle map[string]interface{} wrapping from structs.Map merge paths.
		keysIface, ok := resp.Data["keys"].(map[string]interface{})
		require.True(t, ok, "keys type %T", resp.Data["keys"])
		v1, ok := keysIface["1"].(map[string]interface{})
		require.True(t, ok)
		require.NotEmpty(t, v1["public_key"])
	} else {
		require.NotEmpty(t, keys["1"]["public_key"])
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("mlkem-sanity"))
	encReq := &logical.Request{
		Path:      "encrypt/mlkem",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"plaintext": plaintext,
		},
	}
	resp, err = b.HandleRequest(context.Background(), encReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "encrypt: %#v", resp)
	ciphertext, ok := resp.Data["ciphertext"].(string)
	require.True(t, ok)
	require.NotEmpty(t, ciphertext)

	decReq := &logical.Request{
		Path:      "decrypt/mlkem",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
		},
	}
	resp, err = b.HandleRequest(context.Background(), decReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "decrypt: %#v", resp)
	require.Equal(t, plaintext, resp.Data["plaintext"])
}
