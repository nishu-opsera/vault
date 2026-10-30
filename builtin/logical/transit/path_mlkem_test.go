// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func mlkemEnableFlag(t *testing.T) {
	t.Helper()
	t.Setenv(envTransitEnableMLKEM, "true")
}

func mlkemCreate(t *testing.T, b *backend, storage logical.Storage, name, keyType string, data map[string]interface{}) {
	t.Helper()
	if data == nil {
		data = map[string]interface{}{}
	}
	data["type"] = keyType
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "keys/" + name,
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data:      data,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create %s: %#v", name, resp)
}

func mlkemEncrypt(t *testing.T, b *backend, storage logical.Storage, name, plaintextB64 string) string {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "encrypt/" + name,
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data:      map[string]interface{}{"plaintext": plaintextB64},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "encrypt: %#v", resp)
	ct, ok := resp.Data["ciphertext"].(string)
	require.True(t, ok)
	require.NotEmpty(t, ct)
	return ct
}

func mlkemDecrypt(t *testing.T, b *backend, storage logical.Storage, name, ciphertext string) string {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "decrypt/" + name,
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data:      map[string]interface{}{"ciphertext": ciphertext},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "decrypt: %#v", resp)
	pt, ok := resp.Data["plaintext"].(string)
	require.True(t, ok)
	return pt
}

func mlkemKemSize(keyType string) int {
	if keyType == "ml-kem-1024" {
		return mlkem.CiphertextSize1024
	}
	return mlkem.CiphertextSize768
}

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

// TestTransit_MLKEMFeatureFlag covers VAULT_TRANSIT_ENABLE_MLKEM create gating and
// that existing ML-KEM keys keep working (encrypt/decrypt/rotate/auto-rotate) when
// the flag is later unset.
func TestTransit_MLKEMFeatureFlag(t *testing.T) {
	createKey := func(t *testing.T, b *backend, storage logical.Storage, name, keyType string) (*logical.Response, error) {
		t.Helper()
		return b.HandleRequest(context.Background(), &logical.Request{
			Path:      "keys/" + name,
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data: map[string]interface{}{
				"type": keyType,
			},
		})
	}

	readKey := func(t *testing.T, b *backend, storage logical.Storage, name string) (*logical.Response, error) {
		t.Helper()
		return b.HandleRequest(context.Background(), &logical.Request{
			Path:      "keys/" + name,
			Operation: logical.ReadOperation,
			Storage:   storage,
		})
	}

	errorText := func(resp *logical.Response, err error) string {
		if resp != nil && resp.IsError() {
			return resp.Error().Error()
		}
		if err != nil {
			return err.Error()
		}
		return ""
	}

	t.Run("flag_values", func(t *testing.T) {
		cases := []struct {
			name       string
			flagValue  string
			expectFail bool
		}{
			{name: "true", flagValue: "true", expectFail: false},
			{name: "empty", flagValue: "", expectFail: true},
			{name: "false", flagValue: "false", expectFail: true},
			{name: "foo", flagValue: "foo", expectFail: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv(envTransitEnableMLKEM, tc.flagValue)
				b, storage := createBackendWithStorage(t)

				for _, keyType := range []string{"ml-kem-768", "ml-kem-1024"} {
					name := fmt.Sprintf("mlkem-%s-%s", tc.name, keyType)
					resp, err := createKey(t, b, storage, name, keyType)
					if !tc.expectFail {
						require.NoError(t, err)
						require.False(t, resp != nil && resp.IsError(), "create %s: %#v", keyType, resp)
						continue
					}

					msg := errorText(resp, err)
					require.Contains(t, msg, "ML-KEM key types are not enabled")

					readResp, readErr := readKey(t, b, storage, name)
					require.NoError(t, readErr)
					require.Nil(t, readResp)
				}
			})
		}
	})

	t.Run("flag_off_existing_key_ops", func(t *testing.T) {
		b, storage := createBackendWithStorage(t)

		t.Setenv(envTransitEnableMLKEM, "true")
		resp, err := createKey(t, b, storage, "existing", "ml-kem-768")
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "create: %#v", resp)

		pt1 := base64.StdEncoding.EncodeToString([]byte("first-plaintext"))
		encResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "encrypt/existing",
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data:      map[string]interface{}{"plaintext": pt1},
		})
		require.NoError(t, err)
		require.False(t, encResp != nil && encResp.IsError(), "encrypt: %#v", encResp)
		ct1 := encResp.Data["ciphertext"].(string)

		t.Setenv(envTransitEnableMLKEM, "")

		decResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "decrypt/existing",
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data:      map[string]interface{}{"ciphertext": ct1},
		})
		require.NoError(t, err)
		require.False(t, decResp != nil && decResp.IsError(), "decrypt ct1: %#v", decResp)
		require.Equal(t, pt1, decResp.Data["plaintext"])

		pt2 := base64.StdEncoding.EncodeToString([]byte("second-plaintext"))
		encResp2, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "encrypt/existing",
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data:      map[string]interface{}{"plaintext": pt2},
		})
		require.NoError(t, err)
		require.False(t, encResp2 != nil && encResp2.IsError(), "encrypt pt2: %#v", encResp2)
		ct2 := encResp2.Data["ciphertext"].(string)

		decResp2, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "decrypt/existing",
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data:      map[string]interface{}{"ciphertext": ct2},
		})
		require.NoError(t, err)
		require.False(t, decResp2 != nil && decResp2.IsError(), "decrypt ct2: %#v", decResp2)
		require.Equal(t, pt2, decResp2.Data["plaintext"])

		rotResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "keys/existing/rotate",
			Operation: logical.UpdateOperation,
			Storage:   storage,
		})
		require.NoError(t, err)
		require.False(t, rotResp != nil && rotResp.IsError(), "rotate: %#v", rotResp)

		readResp, err := readKey(t, b, storage, "existing")
		require.NoError(t, err)
		require.NotNil(t, readResp)
		require.Equal(t, 2, readResp.Data["latest_version"])

		p, _, err := b.GetPolicy(context.Background(), keysutil.PolicyRequest{
			Storage: storage,
			Name:    "existing",
		}, b.GetRandomReader())
		require.NoError(t, err)
		require.NotNil(t, p)
		p.AutoRotatePeriod = time.Nanosecond
		require.NoError(t, p.Persist(context.Background(), storage))
		p.Unlock()

		b.checkAutoRotateAfter = time.Now()
		require.NoError(t, b.autoRotateKeys(context.Background(), &logical.Request{Storage: storage}))

		readResp, err = readKey(t, b, storage, "existing")
		require.NoError(t, err)
		require.NotNil(t, readResp)
		require.Equal(t, 3, readResp.Data["latest_version"])

		failResp, failErr := createKey(t, b, storage, "new-mlkem", "ml-kem-768")
		require.Contains(t, errorText(failResp, failErr), "ML-KEM key types are not enabled")
		absent, err := readKey(t, b, storage, "new-mlkem")
		require.NoError(t, err)
		require.Nil(t, absent)

		aesResp, err := createKey(t, b, storage, "aes-ok", "aes256-gcm96")
		require.NoError(t, err)
		require.False(t, aesResp != nil && aesResp.IsError(), "aes create: %#v", aesResp)
	})
}

// TestTransit_MLKEMEncryptDecryptRoundTrip covers transit encrypt/decrypt for
// empty/short/1KB/UTF-8 plaintexts, vault:v1: prefix, nondeterminism, and batch.
func TestTransit_MLKEMEncryptDecryptRoundTrip(t *testing.T) {
	mlkemEnableFlag(t)

	plaintexts := map[string][]byte{
		"empty": {},
		"short": []byte("hi"),
		"1KB":   bytesRepeat('a', 1024),
		"utf8":  []byte("héllo 世界 🔐"),
	}

	for _, keyType := range []string{"ml-kem-768", "ml-kem-1024"} {
		t.Run(keyType, func(t *testing.T) {
			b, storage := createBackendWithStorage(t)
			mlkemCreate(t, b, storage, "rt", keyType, nil)

			for name, pt := range plaintexts {
				t.Run("roundtrip/"+name, func(t *testing.T) {
					ptB64 := base64.StdEncoding.EncodeToString(pt)
					ct := mlkemEncrypt(t, b, storage, "rt", ptB64)
					require.True(t, strings.HasPrefix(ct, "vault:v1:"))
					require.Equal(t, ptB64, mlkemDecrypt(t, b, storage, "rt", ct))
				})
			}

			t.Run("nondeterministic", func(t *testing.T) {
				ptB64 := base64.StdEncoding.EncodeToString([]byte("same"))
				ct1 := mlkemEncrypt(t, b, storage, "rt", ptB64)
				ct2 := mlkemEncrypt(t, b, storage, "rt", ptB64)
				require.True(t, strings.HasPrefix(ct1, "vault:v1:"))
				require.True(t, strings.HasPrefix(ct2, "vault:v1:"))
				require.NotEqual(t, ct1, ct2)
			})

			t.Run("batch", func(t *testing.T) {
				pt1 := base64.StdEncoding.EncodeToString([]byte("batch-one"))
				pt2 := base64.StdEncoding.EncodeToString([]byte("batch-two"))
				resp, err := b.HandleRequest(context.Background(), &logical.Request{
					Path:      "encrypt/rt",
					Operation: logical.UpdateOperation,
					Storage:   storage,
					Data: map[string]interface{}{
						"batch_input": []interface{}{
							map[string]interface{}{"plaintext": pt1, "reference": "a"},
							map[string]interface{}{"plaintext": pt2, "reference": "b"},
						},
					},
				})
				require.NoError(t, err)
				require.False(t, resp != nil && resp.IsError(), "batch encrypt: %#v", resp)
				results, ok := resp.Data["batch_results"].([]EncryptBatchResponseItem)
				require.True(t, ok)
				require.Len(t, results, 2)
				require.Equal(t, pt1, mlkemDecrypt(t, b, storage, "rt", results[0].Ciphertext))
				require.Equal(t, pt2, mlkemDecrypt(t, b, storage, "rt", results[1].Ciphertext))
			})
		})
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestTransit_MLKEMDecryptFailures verifies wrong-key, tampered regions,
// truncated, and garbage ciphertext return ErrInvalidRequest with no plaintext.
func TestTransit_MLKEMDecryptFailures(t *testing.T) {
	mlkemEnableFlag(t)

	assertInvalidDecrypt := func(t *testing.T, b *backend, storage logical.Storage, name, ciphertext string) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Path:      "decrypt/" + name,
			Operation: logical.UpdateOperation,
			Storage:   storage,
			Data:      map[string]interface{}{"ciphertext": ciphertext},
		})
		require.ErrorIs(t, err, logical.ErrInvalidRequest)
		require.NotNil(t, resp)
		require.True(t, resp.IsError())
		_, hasPT := resp.Data["plaintext"]
		require.False(t, hasPT)
	}

	flipCTByte := func(ct string, offset int) string {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
		require.NoError(t, err)
		require.Greater(t, len(raw), offset)
		raw[offset] ^= 0x01
		return "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
	}

	for _, keyType := range []string{"ml-kem-768", "ml-kem-1024"} {
		t.Run(keyType, func(t *testing.T) {
			b, storage := createBackendWithStorage(t)
			mlkemCreate(t, b, storage, "good", keyType, nil)
			mlkemCreate(t, b, storage, "other", keyType, nil)

			ptB64 := base64.StdEncoding.EncodeToString([]byte("secret"))
			ct := mlkemEncrypt(t, b, storage, "good", ptB64)
			kemSize := mlkemKemSize(keyType)

			t.Run("wrong_key", func(t *testing.T) {
				assertInvalidDecrypt(t, b, storage, "other", ct)
			})
			t.Run("tampered_kem", func(t *testing.T) {
				assertInvalidDecrypt(t, b, storage, "good", flipCTByte(ct, 0))
			})
			t.Run("tampered_nonce", func(t *testing.T) {
				assertInvalidDecrypt(t, b, storage, "good", flipCTByte(ct, kemSize))
			})
			t.Run("tampered_data", func(t *testing.T) {
				assertInvalidDecrypt(t, b, storage, "good", flipCTByte(ct, kemSize+12))
			})
			t.Run("truncated", func(t *testing.T) {
				raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
				require.NoError(t, err)
				short := "vault:v1:" + base64.StdEncoding.EncodeToString(raw[:kemSize+12+8])
				assertInvalidDecrypt(t, b, storage, "good", short)
			})
			t.Run("garbage", func(t *testing.T) {
				assertInvalidDecrypt(t, b, storage, "good", "vault:v1:!!!not-base64!!!")
			})
		})
	}
}

// TestTransit_MLKEMDatakeyRoundTrip covers datakey/plaintext and datakey/wrapped
// for bits 128/256/512 with both ML-KEM types.
func TestTransit_MLKEMDatakeyRoundTrip(t *testing.T) {
	mlkemEnableFlag(t)

	for _, keyType := range []string{"ml-kem-768", "ml-kem-1024"} {
		t.Run(keyType, func(t *testing.T) {
			b, storage := createBackendWithStorage(t)
			mlkemCreate(t, b, storage, "dk", keyType, nil)

			for _, bits := range []int{128, 256, 512} {
				t.Run(fmt.Sprintf("plaintext/%d", bits), func(t *testing.T) {
					resp, err := b.HandleRequest(context.Background(), &logical.Request{
						Path:      "datakey/plaintext/dk",
						Operation: logical.UpdateOperation,
						Storage:   storage,
						Data:      map[string]interface{}{"bits": bits},
					})
					require.NoError(t, err)
					require.False(t, resp != nil && resp.IsError(), "datakey plaintext: %#v", resp)
					ptB64, ok := resp.Data["plaintext"].(string)
					require.True(t, ok)
					ct, ok := resp.Data["ciphertext"].(string)
					require.True(t, ok)
					raw, err := base64.StdEncoding.DecodeString(ptB64)
					require.NoError(t, err)
					require.Len(t, raw, bits/8)
					require.Equal(t, ptB64, mlkemDecrypt(t, b, storage, "dk", ct))
				})

				t.Run(fmt.Sprintf("wrapped/%d", bits), func(t *testing.T) {
					resp, err := b.HandleRequest(context.Background(), &logical.Request{
						Path:      "datakey/wrapped/dk",
						Operation: logical.UpdateOperation,
						Storage:   storage,
						Data:      map[string]interface{}{"bits": bits},
					})
					require.NoError(t, err)
					require.False(t, resp != nil && resp.IsError(), "datakey wrapped: %#v", resp)
					_, hasPT := resp.Data["plaintext"]
					require.False(t, hasPT)
					ct, ok := resp.Data["ciphertext"].(string)
					require.True(t, ok)
					ptB64 := mlkemDecrypt(t, b, storage, "dk", ct)
					raw, err := base64.StdEncoding.DecodeString(ptB64)
					require.NoError(t, err)
					require.Len(t, raw, bits/8)
				})
			}
		})
	}
}
