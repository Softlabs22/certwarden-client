package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodePEMBlocksNilData(t *testing.T) {
	assertions := assert.New(t)

	blocks, err := DecodePEMBlocks(nil)
	assertions.NoError(err)
	assertions.Empty(blocks)
}

func TestDecodePEMBlocksMalformedData(t *testing.T) {
	assertions := assert.New(t)

	blocks, err := DecodePEMBlocks([]byte(`-----BEGIN CERTIFICATE-----`))
	assertions.EqualError(err, "failed to decode PEM block")
	assertions.Nil(blocks)
}

func TestDecodePEMBlocksPKCS8(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#8 RSA key file: %s", err)

	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoError(err)
	requirements.Len(blocks, 1)
	assertions.Equal(blocks[0].Type, "PRIVATE KEY", "unexpected PEM block type for PKCS#8 private key")
}

func TestDecodePEMBlocksPKCS1(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS1RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#1 RSA key file: %s", err)

	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoError(err)
	requirements.Len(blocks, 1)
	assertions.Equal(blocks[0].Type, "RSA PRIVATE KEY", "unexpected PEM block type for PKCS#1 private key")
}

func TestDecodePEMBlocksEC(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	ecPrivateKeyFile, err := os.ReadFile("../../test/pem/testECPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test EC private key file: %s", err)

	blocks, err := DecodePEMBlocks(ecPrivateKeyFile)
	requirements.NoError(err)
	requirements.Len(blocks, 1)
	assertions.Equal(blocks[0].Type, "EC PRIVATE KEY", "unexpected PEM block type for EC private key")
}

func TestDecodePEMBlocksCerificate(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certificateFile, err := os.ReadFile("../../test/pem/testCertificate.pem")
	requirements.NoErrorf(err, "failed to read test certificate file: %s", err)

	blocks, err := DecodePEMBlocks(certificateFile)
	requirements.NoError(err)
	requirements.Len(blocks, 1)
	assertions.Equal(blocks[0].Type, "CERTIFICATE", "unexpected PEM block type for certificate")
}

func TestDecodePEMBlocksKeyPair(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	keyPairFile, err := os.ReadFile("../../test/pem/testKeyPair.pem")
	requirements.NoErrorf(err, "failed to read test keypair file: %s", err)

	blocks, err := DecodePEMBlocks(keyPairFile)
	requirements.NoError(err)
	requirements.Len(blocks, 2)
	assertions.Equal(blocks[0].Type, "PRIVATE KEY", "unexpected PEM block type for private key")
	assertions.Equal(blocks[1].Type, "CERTIFICATE", "unexpected PEM block type for certificate")
}

func TestEncodePrivateKeyPEMNilData(t *testing.T) {
	assertions := assert.New(t)

	keyPEM, err := EncodePrivateKeyPEM(nil)
	assertions.Error(err)
	assertions.Nil(keyPEM)
}

func TestEncodePrivateKeyPEMMalformedData(t *testing.T) {
	assertions := assert.New(t)

	key := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: big.NewInt(123),
			E: 65537,
		},
		D:      nil,
		Primes: nil,
		Precomputed: rsa.PrecomputedValues{
			Dp:   big.NewInt(123),
			Dq:   big.NewInt(123),
			Qinv: big.NewInt(123),
		},
	}
	keyPEM, err := EncodePrivateKeyPEM(&key)
	assertions.Error(err)
	assertions.Nil(keyPEM)
}

func TestEncodePrivateKeyPEM(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#8 RSA key file: %s", err)
	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)
	requirements.Len(blocks, 1)

	key, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	requirements.NoErrorf(err, "failed to parse private key as PKCS#8: %s", err)

	keyPEM, err := EncodePrivateKeyPEM(key)
	assertions.NoError(err)
	assertions.Equal(blocks[0], keyPEM)
}

func TestParsePEMChainNilData(t *testing.T) {
	assertions := assert.New(t)

	certs, keys, err := ParsePEMChain(nil)
	assertions.EqualError(err, "got nil PEM chain")
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChainEmptyData(t *testing.T) {
	assertions := assert.New(t)

	certs, keys, err := ParsePEMChain([]*pem.Block{})
	assertions.NoError(err)
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChainMalformedCertificate(t *testing.T) {
	assertions := assert.New(t)

	badPEMBlock := pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   []byte("malformed"),
		Headers: map[string]string{},
	}
	certs, keys, err := ParsePEMChain([]*pem.Block{&badPEMBlock})
	assertions.Error(err)
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChainMalformedKey(t *testing.T) {
	assertions := assert.New(t)

	badPEMBlock := pem.Block{
		Type:    "PRIVATE KEY",
		Bytes:   []byte("malformed"),
		Headers: map[string]string{},
	}
	certs, keys, err := ParsePEMChain([]*pem.Block{&badPEMBlock})
	assertions.Error(err)
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChainUnknownBlock(t *testing.T) {
	assertions := assert.New(t)

	badPEMBlock := pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Bytes:   []byte{},
		Headers: map[string]string{},
	}
	certs, keys, err := ParsePEMChain([]*pem.Block{&badPEMBlock})
	assertions.EqualError(err, "unknown PEM block type: CERTIFICATE REQUEST")
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChainKeyOnly(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rsaKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read test PKCS#8 RSA key file: %s", err)
	blocks, err := DecodePEMBlocks(rsaKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	certs, keys, err := ParsePEMChain(blocks)
	assertions.NoError(err)
	assertions.Nil(certs)
	assertions.NotNil(keys)
}

func TestParsePEMChainCertOnly(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certFile, err := os.ReadFile("../../test/pem/testCertificate.pem")
	requirements.NoErrorf(err, "failed to read test certificate file: %s", err)
	blocks, err := DecodePEMBlocks(certFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	certs, keys, err := ParsePEMChain(blocks)
	assertions.NoError(err)
	assertions.NotNil(certs)
	assertions.Nil(keys)
}

func TestParsePEMChain(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certKeyFile, err := os.ReadFile("../../test/pem/testKeyPair.pem")
	requirements.NoErrorf(err, "failed to read test key pair file: %s", err)
	blocks, err := DecodePEMBlocks(certKeyFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	certs, keys, err := ParsePEMChain(blocks)
	assertions.NoError(err)
	assertions.NotNil(certs)
	assertions.NotNil(keys)
}
