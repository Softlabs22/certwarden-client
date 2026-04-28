package worker

import (
	"certwarden-client/pkg/api"
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/crypto"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestCertToken = "test-cert-token"
	TestKeyToken  = "test-key-token"
)

func setupTestServer(t *testing.T, route, credentials, fileToServe string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case route:
			auth := r.Header.Get("X-API-Key")
			if auth != credentials {
				w.WriteHeader(http.StatusUnauthorized)
				_, err := w.Write([]byte("unauthorized"))
				require.NoError(t, err)
			} else {
				content, err := os.ReadFile(fileToServe)
				require.NoError(t, err)
				w.WriteHeader(http.StatusOK)
				_, err = w.Write(content)
				require.NoError(t, err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("Not Found"))
			require.NoError(t, err)
		}
	}))
	return server
}

func checkFileCreated(t *testing.T, job *CertJob, targetFile, flagFile string, TargetFileMode fs.FileMode) {
	assertions := assert.New(t)
	requirements := require.New(t)

	ctx := context.Background()
	err := job.Run(ctx)
	assertions.NoError(err)
	requirements.FileExists(targetFile)
	stat, _ := os.Stat(targetFile)
	assertions.Equal(TargetFileMode, stat.Mode())
	assertions.FileExists(flagFile)
}

func checkFileChanged(t *testing.T, job *CertJob, targetFile, flagFile string, TargetFileMode fs.FileMode, shouldChange bool) {
	assertions := assert.New(t)
	requirements := require.New(t)

	ctx := context.Background()
	oldFile, err := os.ReadFile(targetFile)
	requirements.NoError(err)

	err = job.Run(ctx)
	assertions.NoError(err)
	newFile, err := os.ReadFile(targetFile)
	requirements.NoError(err)
	stat, _ := os.Stat(targetFile)
	if shouldChange {
		assertions.NotEqual(oldFile, newFile)
		assertions.FileExists(flagFile)
	} else {
		assertions.Equal(oldFile, newFile)
		assertions.NoFileExists(flagFile)
	}
	assertions.Equal(TargetFileMode, stat.Mode())
}

func TestCompareKeysEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	result, err := compareKeys(nil, nil)
	assertions.NoError(err)
	assertions.True(result)

	privateKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read private key file: %s", err)
	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	requirements.NotNilf(privateKeyBlock, "failed to decode private key PEM block")

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	requirements.NoErrorf(err, "failed to parse private key: %s", err)

	result, err = compareKeys(privateKey, privateKey)
	assertions.NoError(err)
	assertions.True(result)

	keyCopy, _ := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	result, err = compareKeys(privateKey, keyCopy)
	assertions.NoError(err)
	assertions.True(result)

	result, err = compareKeys(keyCopy, privateKey)
	assertions.NoError(err)
	assertions.True(result)
}

func TestCompareKeysNotEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	privateKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "failed to read private key file: %s", err)
	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	requirements.NotNilf(privateKeyBlock, "failed to decode private key PEM block")

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	requirements.NoErrorf(err, "failed to parse private key: %s", err)

	result, err := compareKeys(nil, privateKey)
	assertions.NoError(err)
	assertions.False(result)

	result, err = compareKeys(privateKey, nil)
	assertions.NoError(err)
	assertions.False(result)

	anotherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	result, err = compareKeys(privateKey, anotherKey)
	assertions.NoError(err)
	assertions.False(result)

	result, err = compareKeys(anotherKey, privateKey)
	assertions.NoError(err)
	assertions.False(result)
}

func TestCompareKeysMalformedData(t *testing.T) {
	assertions := assert.New(t)

	goodKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	result, err := compareKeys(goodKey, []byte("malformedData"))
	assertions.Error(err)
	assertions.False(result)

	result, err = compareKeys([]byte("malformedData"), goodKey)
	assertions.Error(err)
	assertions.False(result)
}

func TestCompareCertificatesEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	assertions.True(compareCertificates(nil, nil))
	assertions.True(compareCertificates([]*x509.Certificate{}, []*x509.Certificate{}))

	certChainFile, err := os.ReadFile("../../test/pem/testChain.pem")
	assertions.NoErrorf(err, "failed to read certificate chain file: %s", err)

	var pemBlocks []*pem.Block
	for len(certChainFile) > 0 {
		var block *pem.Block
		block, certChainFile = pem.Decode(certChainFile)
		requirements.NotNilf(block, "failed to decode certificate PEM block")
		pemBlocks = append(pemBlocks, block)
	}

	certs, _, err := crypto.ParsePEMChain(pemBlocks)
	requirements.NoErrorf(err, "failed to parse certificate PEM blocks: %s", err)

	requirements.GreaterOrEqualf(len(certs), 2, "expected at least two certificates in the chain")
	assertions.True(compareCertificates(certs, certs))

	// shuffle certificates around
	reversedCerts := make([]*x509.Certificate, 0, len(certs))
	for i := len(certs); i > 0; i-- {
		reversedCerts = append(reversedCerts, certs[i-1])
	}

	assertions.True(compareCertificates(certs, reversedCerts))
	assertions.True(compareCertificates(reversedCerts, certs))
}

func TestCompareCertificatesNotEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	assertions.False(compareCertificates(nil, []*x509.Certificate{}))
	assertions.False(compareCertificates([]*x509.Certificate{}, nil))

	certChainFile, err := os.ReadFile("../../test/pem/testChain.pem")
	requirements.NoErrorf(err, "failed to read certificate chain file: %s", err)

	var pemBlocks []*pem.Block
	for len(certChainFile) > 0 {
		var block *pem.Block
		block, certChainFile = pem.Decode(certChainFile)
		requirements.NotNilf(block, "failed to decode certificate PEM block")
		pemBlocks = append(pemBlocks, block)
	}

	certs, _, err := crypto.ParsePEMChain(pemBlocks)
	requirements.NoErrorf(err, "failed to parse certificate PEM blocks: %s", err)

	requirements.GreaterOrEqualf(len(certs), 2, "expected at least two certificates in the chain")

	assertions.False(compareCertificates([]*x509.Certificate{certs[0]}, certs))
	assertions.False(compareCertificates(certs, []*x509.Certificate{certs[0]}))

	anotherChain := []*x509.Certificate{certs[0], certs[0]}

	assertions.False(compareCertificates(certs, anotherChain))
	assertions.False(compareCertificates(anotherChain, certs))
}

func TestWorkerPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.PrivateKeysAPIPath+"test",
		TestKeyToken,
		"../../test/pem/testPKCS8RSAPrivateKey.pem",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateKey,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	checkFileCreated(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawKey, _ := x509.MarshalPKCS8PrivateKey(newKey)
	_ = os.WriteFile(
		pemFile,
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: rawKey,
			},
		),
		fs.FileMode(0755),
	)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}

func TestWorkerCertificate(t *testing.T) {
	requirements := require.New(t)

	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.CertificatesAPIPath+"test",
		TestCertToken,
		"../../test/pem/testCertificate.pem",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertificate,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	checkFileCreated(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}

func TestWorkerPrivateCertChain(t *testing.T) {
	requirements := require.New(t)

	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.PrivateCertChainsAPIPath+"test",
		TestCertToken+"."+TestKeyToken,
		"../../test/pem/testFullChain.pem",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateCertChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	checkFileCreated(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}

func TestWorkerPFX(t *testing.T) {
	requirements := require.New(t)

	tempDir := t.TempDir()
	pfxFile := filepath.Join(tempDir, "testpfx.p12")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.PFXAPIPath+"test",
		TestCertToken+"."+TestKeyToken,
		"../../test/pem/testPFX.p12",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "testpfx.p12",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPFX,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	checkFileCreated(
		t,
		&job,
		pfxFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pfxFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	fin, err := os.Open("../../test/pem/testAnotherPFX.p12")
	requirements.NoError(err)
	fout, err := os.Create(pfxFile)
	requirements.NoError(err)
	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	checkFileChanged(
		t,
		&job,
		pfxFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}

func TestWorkerPrivateCert(t *testing.T) {
	requirements := require.New(t)

	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.PrivateCertsAPIPath+"test",
		TestCertToken+"."+TestKeyToken,
		"../../test/pem/testKeyPair.pem",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateCert,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	checkFileCreated(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}

func TestWorkerRootChain(t *testing.T) {
	requirements := require.New(t)

	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")
	flagFile := filepath.Join(tempDir, "refresh.ok")

	server := setupTestServer(t,
		api.DownloadAPIPath+api.CertRootChainsAPIPath+"test",
		TestCertToken,
		"../../test/pem/testCACert.pem",
	)
	defer server.Close()

	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: fmt.Sprintf("touch %s", flagFile),
		SavePath:     tempDir,
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertRootChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	checkFileCreated(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
	)
	_ = os.Remove(flagFile)

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		false,
	)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	checkFileChanged(
		t,
		&job,
		pemFile,
		flagFile,
		os.FileMode(0640),
		true,
	)
}
