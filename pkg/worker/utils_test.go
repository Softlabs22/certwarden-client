package worker

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromFileBadPath(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	nonExistentPath := "/nonexistent"
	data, err := loadFromFile(nonExistentPath)
	requirements.NoError(err)
	requirements.NotNil(data)
	assertions.Empty(data)
}

func TestLoadFromFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	testPath := "../../test/pem/testCertificate.pem"
	data, err := loadFromFile(testPath)
	requirements.NoError(err)
	requirements.NotNil(data)
	assertions.NotEmpty(data)
}

func TestSaveToFileBadPath(t *testing.T) {
	assertions := assert.New(t)

	data := []byte("Lorem ipsum dolor sit amet")
	err := saveToFile("/tmp/nonexistent/path/here", data)
	assertions.Error(err)
}

func TestSaveToFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	data := []byte("Lorem ipsum dolor sit amet")
	err := saveToFile("/tmp/test.bin", data)
	requirements.NoError(err)
	assertions.FileExists("/tmp/test.bin")

	readBack, err := os.ReadFile("/tmp/test.bin")
	requirements.NoError(err)
	assertions.Equal(data, readBack)
	_ = os.Remove("/tmp/test.bin")
}

func TestLoadCertKeyFromFileBadPath(t *testing.T) {
	assertions := assert.New(t)
	certs, keys, err := loadCertKeyChainFromFile("/nonexistent")

	assertions.NoError(err)
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestLoadCertKeyFromFileMalformedData(t *testing.T) {
	assertions := assert.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/configs/allOptionsConfig.yaml")
	assertions.Error(err)
	assertions.Nil(certs)
	assertions.Nil(keys)

	certs, keys, err = loadCertKeyChainFromFile("../../test/pem/testMalformedKeyPair.pem")
	assertions.Error(err)
	assertions.Nil(certs)
	assertions.Nil(keys)
}

func TestLoadCertKeyChainFromFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/pem/testCertificate.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	assertions.Nil(keys)

	certs, keys, err = loadCertKeyChainFromFile("../../test/pem/testPKCS1RSAPrivateKey.pem")
	requirements.NoError(err)
	assertions.Nil(certs)
	assertions.NotNil(keys)

	certs, keys, err = loadCertKeyChainFromFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoError(err)
	assertions.Nil(certs)
	assertions.NotNil(keys)

	certs, keys, err = loadCertKeyChainFromFile("../../test/pem/testECPrivateKey.pem")
	requirements.NoError(err)
	assertions.Nil(certs)
	assertions.NotNil(keys)

	certs, keys, err = loadCertKeyChainFromFile("../../test/pem/testKeyPair.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	assertions.NotNil(keys)
}

func TestSaveCertKeyChainToFileBadPath(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/pem/testKeyPair.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	assertions.NotNil(keys)

	err = saveCertKeyChainToFile("/non/existent", certs, keys)
	assertions.Error(err)
}

func TestSaveCertKeyChainToFileMalformedData(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/pem/testKeyPair.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	requirements.NotNil(keys)
	requirements.GreaterOrEqual(len(keys), 1)

	keys[0] = nil

	err = saveCertKeyChainToFile("/tmp/test.pem", certs, keys)
	assertions.Error(err)
	assertions.NoFileExists("/tmp/test.pem")
}

func TestSaveCertKeyChainToFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/pem/testKeyPair.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	assertions.NotNil(keys)

	err = saveCertKeyChainToFile("/tmp/test.pem", certs, keys)
	requirements.NoError(err)
	requirements.FileExists("/tmp/test.pem")

	origContents, _ := os.ReadFile("../../test/pem/testKeyPair.pem")
	newContents, _ := os.ReadFile("/tmp/test.pem")
	_ = os.Remove("/tmp/test.pem")

	assertions.Equal(origContents, newContents)
}
