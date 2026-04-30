package worker

import (
	"certwarden-client/pkg/api"
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/crypto"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func checkFileCreated(t *testing.T, targetFile string, targetFileMode fs.FileMode) {
	assertions := assert.New(t)
	requirements := require.New(t)

	requirements.FileExists(targetFile)
	stat, _ := os.Stat(targetFile)
	assertions.Equal(targetFileMode, stat.Mode())
}

func checkFileChanged(t *testing.T, oldHash [32]byte, newFile string, targetFileMode fs.FileMode, shouldChange bool) {
	assertions := assert.New(t)
	requirements := require.New(t)

	data, err := os.ReadFile(newFile)
	requirements.NoError(err)
	newHash := sha256.Sum256(data)
	if shouldChange {
		assertions.NotEqual(oldHash, newHash)
	} else {
		assertions.Equal(oldHash, newHash)
	}
	stat, _ := os.Stat(newFile)
	assertions.Equal(targetFileMode, stat.Mode())
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

	assertions.False(compareCertificates(certs, []*x509.Certificate{certs[0], certs[0], certs[1]}))
	assertions.False(compareCertificates([]*x509.Certificate{certs[0], certs[0], certs[1]}, certs))

	anotherChain := []*x509.Certificate{certs[0], certs[0]}

	assertions.False(compareCertificates(certs, anotherChain))
	assertions.False(compareCertificates(anotherChain, certs))
}

func TestWorkerBadRefreshCommand(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	tempDir := t.TempDir()
	pemFile := filepath.Join(tempDir, "test.pem")

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
		OnRefreshCmd: "false",
		SavePath:     tempDir,
		Filename:     "test.pem",
		SplitMode:    false,
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateKey,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	ctx := context.Background()

	err := job.Run(ctx)
	requirements.NoError(err)
	assertions.FileExists(pemFile)
	_ = os.Remove(pemFile)

	job.OnRefreshCmd = "kill -9 $$"
	err = job.Run(ctx)
	requirements.NoError(err)
	assertions.FileExists(pemFile)
}

func TestWorkerPrivateKey(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateKey,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	ctx := context.Background()

	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pemFile,
		os.FileMode(0640),
	)
	data, err := os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		false,
	)
	assertions.NoFileExists(flagFile)

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
	data, err = os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		true,
	)
	assertions.FileExists(flagFile)
}

func TestWorkerCertificate(t *testing.T) {
	assertions := assert.New(t)
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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertificate,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	ctx := context.Background()

	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pemFile,
		os.FileMode(0640),
	)
	data, err := os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	data, err = os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		true,
	)
	assertions.FileExists(flagFile)
}

func TestWorkerPrivateCertChain(t *testing.T) {
	assertions := assert.New(t)
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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0644)),
		Kind:         config.KindPrivateCertChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	ctx := context.Background()

	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pemFile,
		os.FileMode(0644),
	)
	data, err := os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0644),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)
	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	data, err = os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0644),
		true,
	)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	job.SplitMode = true
	job.Filename = "prefix"
	job.Permissions = new(os.FileMode(0644))
	certFile := filepath.Join(tempDir, "prefix_"+splitFullchainFilename)
	keyFile := filepath.Join(tempDir, "prefix_"+splitKeyFilename)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		certFile,
		os.FileMode(0644),
	)
	checkFileCreated(
		t,
		keyFile,
		os.FileMode(0640),
	)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	data, err = os.ReadFile(keyFile)
	require.NoError(t, err)
	keyHash := sha256.Sum256(data)
	data, err = os.ReadFile(certFile)
	require.NoError(t, err)
	certHash := sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		keyHash,
		keyFile,
		os.FileMode(0640),
		false,
	)
	checkFileChanged(
		t,
		certHash,
		certFile,
		os.FileMode(0644),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin1, err := os.Open("../../test/pem/testCACert.pem")
	requirements.NoError(err)
	fin2, err := os.Open("../../test/pem/testPKCS1RSAPrivateKey.pem")
	requirements.NoError(err)
	fout1, err := os.Create(certFile)
	requirements.NoError(err)
	fout2, err := os.Create(keyFile)
	requirements.NoError(err)

	_, err = io.Copy(fout1, fin1)
	requirements.NoError(err)
	_, err = io.Copy(fout2, fin2)
	requirements.NoError(err)
	_ = fin1.Close()
	_ = fin2.Close()
	_ = fout1.Close()
	_ = fout2.Close()

	data, err = os.ReadFile(keyFile)
	require.NoError(t, err)
	keyHash = sha256.Sum256(data)
	data, err = os.ReadFile(certFile)
	require.NoError(t, err)
	certHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		keyHash,
		keyFile,
		os.FileMode(0640),
		true,
	)
	checkFileChanged(
		t,
		certHash,
		certFile,
		os.FileMode(0644),
		true,
	)
	assertions.FileExists(flagFile)
}

func TestWorkerPFX(t *testing.T) {
	assertions := assert.New(t)
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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPFX,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	ctx := context.Background()
	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pfxFile,
		os.FileMode(0640),
	)
	data, err := os.ReadFile(pfxFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pfxFile,
		os.FileMode(0640),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin, err := os.Open("../../test/pem/testAnotherPFX.p12")
	requirements.NoError(err)
	fout, err := os.Create(pfxFile)
	requirements.NoError(err)
	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	data, err = os.ReadFile(pfxFile)
	require.NoError(t, err)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pfxFile,
		os.FileMode(0640),
		true,
	)
	assertions.FileExists(flagFile)
}

func TestWorkerPrivateCert(t *testing.T) {
	assertions := assert.New(t)
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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0644)),
		Kind:         config.KindPrivateCert,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	ctx := context.Background()
	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pemFile,
		os.FileMode(0644),
	)
	data, err := os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0644),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	data, err = os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0644),
		true,
	)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	job.SplitMode = true
	job.Filename = "prefix"
	job.Permissions = new(os.FileMode(0644))
	certFile := filepath.Join(tempDir, "prefix_"+splitCertFilename)
	keyFile := filepath.Join(tempDir, "prefix_"+splitKeyFilename)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		certFile,
		os.FileMode(0644),
	)
	checkFileCreated(
		t,
		keyFile,
		os.FileMode(0640),
	)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	data, err = os.ReadFile(keyFile)
	require.NoError(t, err)
	keyHash := sha256.Sum256(data)
	data, err = os.ReadFile(certFile)
	require.NoError(t, err)
	certHash := sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		keyHash,
		keyFile,
		os.FileMode(0640),
		false,
	)
	checkFileChanged(
		t,
		certHash,
		certFile,
		os.FileMode(0644),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin1, err := os.Open("../../test/pem/testCACert.pem")
	requirements.NoError(err)
	fin2, err := os.Open("../../test/pem/testPKCS1RSAPrivateKey.pem")
	requirements.NoError(err)
	fout1, err := os.Create(certFile)
	requirements.NoError(err)
	fout2, err := os.Create(keyFile)
	requirements.NoError(err)

	_, err = io.Copy(fout1, fin1)
	requirements.NoError(err)
	_, err = io.Copy(fout2, fin2)
	requirements.NoError(err)
	_ = fin1.Close()
	_ = fin2.Close()
	_ = fout1.Close()
	_ = fout2.Close()

	data, err = os.ReadFile(keyFile)
	require.NoError(t, err)
	keyHash = sha256.Sum256(data)
	data, err = os.ReadFile(certFile)
	require.NoError(t, err)
	certHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		keyHash,
		keyFile,
		os.FileMode(0640),
		true,
	)
	checkFileChanged(
		t,
		certHash,
		certFile,
		os.FileMode(0644),
		true,
	)
	assertions.FileExists(flagFile)
}

func TestWorkerRootChain(t *testing.T) {
	assertions := assert.New(t)
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
		SplitMode:    false,
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertRootChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}

	ctx := context.Background()
	err := job.Run(ctx)
	requirements.NoError(err)
	checkFileCreated(
		t,
		pemFile,
		os.FileMode(0640),
	)
	data, err := os.ReadFile(pemFile)
	require.NoError(t, err)
	oldHash := sha256.Sum256(data)
	assertions.FileExists(flagFile)
	_ = os.Remove(flagFile)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		false,
	)
	assertions.NoFileExists(flagFile)

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create(pemFile)
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	data, err = os.ReadFile(pemFile)
	oldHash = sha256.Sum256(data)

	err = job.Run(ctx)
	requirements.NoError(err)
	checkFileChanged(
		t,
		oldHash,
		pemFile,
		os.FileMode(0640),
		true,
	)
	assertions.FileExists(flagFile)
}
