package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePrivateKeyDERNilData(t *testing.T) {
	assertions := assert.New(t)

	key, err := ParsePrivateKeyDER(nil)
	assertions.Error(err)
	assertions.Nil(key)
}

func TestParsePrivateKeyDERMalformedData(t *testing.T) {
	assertions := assert.New(t)

	key, err := ParsePrivateKeyDER([]byte{0})
	assertions.Error(err)
	assertions.Nil(key)
}

func TestParsePrivateKeyDER_PKCS8(t *testing.T) {
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#8 RSA key file:  %s", err)
	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	key, err := ParsePrivateKeyDER(blocks[0].Bytes)
	requirements.NoErrorf(err, "failed to parse private key: %s", err)

	switch v := key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
	default:
		t.Fatalf("Unexpected key type: %T", v)
	}
}

func TestParsePrivateKeyDER_EC(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	ecKeyFile, err := os.ReadFile("../../test/pem/testECPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test EC key file:  %s", err)
	blocks, err := DecodePEMBlocks(ecKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	key, err := ParsePrivateKeyDER(blocks[0].Bytes)
	requirements.NoErrorf(err, "failed to parse private key: %s", err)
	assertions.IsType(&ecdsa.PrivateKey{}, key)
}

func TestParsePrivateKeyDER_PKCS1(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS1RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#1 RSA key file:  %s", err)
	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	key, err := ParsePrivateKeyDER(blocks[0].Bytes)
	requirements.NoErrorf(err, "failed to parse private key: %s", err)
	assertions.IsType(&rsa.PrivateKey{}, key)
}
