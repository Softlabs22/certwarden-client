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
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestCertToken = "test-cert-token"
	TestKeyToken  = "test-key-token"
)

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
	assertions := assert.New(t)
	requirements := require.New(t)

	privateKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "error reading private key file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.PrivateKeysAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestKeyToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(privateKeyFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateKey,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/test.pem")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/test.pem")
	}()

	oldStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawKey, _ := x509.MarshalPKCS8PrivateKey(newKey)
	_ = os.WriteFile(
		"/tmp/test.pem",
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: rawKey,
			},
		),
		fs.FileMode(0755),
	)

	oldStat, _ = os.Stat("/tmp/test.pem")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/test.pem")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}

func TestWorkerCertificate(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certificateFile, err := os.ReadFile("../../test/pem/testCertificate.pem")
	requirements.NoErrorf(err, "error reading certificate file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.CertificatesAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(certificateFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertificate,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/test.pem")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/test.pem")
	}()

	oldStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create("/tmp/test.pem")
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	oldStat, _ = os.Stat("/tmp/test.pem")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/test.pem")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}

func TestWorkerPrivateCertChain(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	fullChainFile, err := os.ReadFile("../../test/pem/testFullChain.pem")
	requirements.NoErrorf(err, "error reading certificate file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.PrivateCertChainsAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken+"."+TestKeyToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(fullChainFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateCertChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/test.pem")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/test.pem")
	}()

	oldStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create("/tmp/test.pem")
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	oldStat, _ = os.Stat("/tmp/test.pem")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/test.pem")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}

func TestWorkerPFX(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	pfxFile, err := os.ReadFile("../../test/pem/testPFX.p12")
	requirements.NoErrorf(err, "error reading PFX file %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.PFXAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken+"."+TestKeyToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(pfxFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "testpfx.p12",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPFX,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/testpfx.p12")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/testpfx.p12")
	}()

	oldStat, _ := os.Stat("/tmp/testpfx.p12")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/testpfx.p12")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	fin, err := os.Open("../../test/pem/testAnotherPFX.p12")
	requirements.NoError(err)
	fout, err := os.Create("/tmp/testpfx.p12")
	requirements.NoError(err)
	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	oldStat, _ = os.Stat("/tmp/testpfx.p12")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/testpfx.p12")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}

func TestWorkerPrivateCert(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	keyPairFile, err := os.ReadFile("../../test/pem/testKeyPair.pem")
	requirements.NoErrorf(err, "error reading certificate file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.PrivateCertsAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken+"."+TestKeyToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(keyPairFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindPrivateCert,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/test.pem")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/test.pem")
	}()

	oldStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create("/tmp/test.pem")
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	oldStat, _ = os.Stat("/tmp/test.pem")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/test.pem")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}

func TestWorkerRootChain(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	rootCertFile, err := os.ReadFile("../../test/pem/testCACert.pem")
	requirements.NoErrorf(err, "error reading certificate file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.DownloadAPIPath + api.CertRootChainsAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(rootCertFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	job := CertJob{
		Name:         "test",
		APIHostURL:   server.URL,
		CertToken:    TestCertToken,
		KeyToken:     TestKeyToken,
		OnRefreshCmd: "touch /tmp/refresh.ok",
		SavePath:     "/tmp/",
		Filename:     "test.pem",
		Permissions:  new(os.FileMode(0640)),
		Kind:         config.KindCertRootChain,
		RunInterval:  3600,
		JobTimeout:   5,
	}
	err = job.Run(ctx)
	assertions.NoError(err)
	assertions.FileExists("/tmp/test.pem")
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
	defer func() {
		_ = os.Remove("/tmp/test.pem")
	}()

	oldStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(os.FileMode(0640), oldStat.Mode())

	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ := os.Stat("/tmp/test.pem")
	assertions.Equal(oldStat.ModTime(), newStat.ModTime())
	assertions.NoFileExists("/tmp/refresh.ok")

	fin, err := os.Open("../../test/pem/testAnotherChain.pem")
	requirements.NoError(err)

	fout, err := os.Create("/tmp/test.pem")
	requirements.NoError(err)

	_, err = io.Copy(fout, fin)
	requirements.NoError(err)
	_ = fin.Close()
	_ = fout.Close()

	oldStat, _ = os.Stat("/tmp/test.pem")
	time.Sleep(time.Millisecond * 100)
	err = job.Run(ctx)
	assertions.NoError(err)
	newStat, _ = os.Stat("/tmp/test.pem")
	assertions.NotEqual(oldStat.ModTime(), newStat.ModTime())
	assertions.Equal(os.FileMode(0640), newStat.Mode())
	assertions.FileExists("/tmp/refresh.ok")
	_ = os.Remove("/tmp/refresh.ok")
}
