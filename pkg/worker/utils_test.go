package worker

import (
	"os"
	"path/filepath"
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

	tempDir := t.TempDir()
	data := []byte("Lorem ipsum dolor sit amet")
	err := saveToFile(filepath.Join(tempDir, "nonexistent", "path"), data, new(os.FileMode(0640)))
	assertions.Error(err)
}

func TestSaveToFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test.pem")

	data := []byte("Lorem ipsum dolor sit amet")
	err := saveToFile(tempFile, data, new(os.FileMode(0640)))
	requirements.NoError(err)
	requirements.FileExists(tempFile)
	stat, err := os.Stat(tempFile)
	requirements.NoError(err)
	assertions.Equal(os.FileMode(0640), stat.Mode())

	readBack, err := os.ReadFile(tempFile)
	requirements.NoError(err)
	assertions.Equal(data, readBack)
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

	err = saveCertKeyChainToFile("/non/existent", certs, keys, new(os.FileMode(0640)))
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

	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test.pem")

	err = saveCertKeyChainToFile(tempFile, certs, keys, new(os.FileMode(0640)))
	assertions.Error(err)
	assertions.NoFileExists(tempFile)
}

func TestSaveCertKeyChainToFile(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certs, keys, err := loadCertKeyChainFromFile("../../test/pem/testKeyPair.pem")
	requirements.NoError(err)
	assertions.NotNil(certs)
	assertions.NotNil(keys)

	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test.pem")

	err = saveCertKeyChainToFile(tempFile, certs, keys, new(os.FileMode(0640)))
	requirements.NoError(err)
	requirements.FileExists(tempFile)
	stat, err := os.Stat(tempFile)
	requirements.NoError(err)
	assertions.Equal(os.FileMode(0640), stat.Mode())

	origContents, _ := os.ReadFile("../../test/pem/testKeyPair.pem")
	newContents, _ := os.ReadFile(tempFile)

	assertions.Equal(origContents, newContents)
}
