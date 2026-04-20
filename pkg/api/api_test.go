package api

import (
	cwcrypto "certwarden-client/pkg/crypto"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	TestCertToken = "test-cert-token"
	TestKeyToken  = "test-key-token"
)

func isValidPrivateKeyType(key any) bool {
	switch key.(type) {
	case *rsa.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return true
	case *ed25519.PrivateKey:
		return true
	default:
		return false
	}
}

func TestMakeAPIRequest(t *testing.T) {
	assertions := assert.New(t)

	ctx := context.Background()
	malformedURL := "Lorem ipsum dolor sit amet"
	nonexistentURL := "https://thisdoesnotresolve.example.com"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/404":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	goodURL := server.URL

	cw := new(CertWarden{Context: ctx, HostURL: malformedURL, Client: &http.Client{}})
	data, err := makeAPIRequest(cw, "/", "dontcare")
	assertions.IsType(&url.Error{}, err)
	assertions.Nil(data)

	cw.HostURL = nonexistentURL
	data, err = makeAPIRequest(cw, "/", "dontcare")
	assertions.IsType(&url.Error{}, err)
	assertions.Nil(data)

	cw.HostURL = goodURL
	data, err = makeAPIRequest(cw, "/404", "dontcare")
	assertions.EqualError(err, "404 Not Found")
	assertions.Nil(data)

	data, err = makeAPIRequest(cw, "/", "dontcare")
	assertions.NoError(err)
	assertions.NotNil(data)
}

func TestGetPrivateKey(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	privateKeyFile, err := os.ReadFile("../../test/pem/testPKCS8RSAPrivateKey.pem")
	requirements.NoErrorf(err, "error reading private key file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + PrivateKeysAPIPath + "test":
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
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	PEMKeys, err := cw.GetPrivateKey("test", TestKeyToken)
	requirements.NoErrorf(err, "GetPrivateKey() failed: %s", err)

	var keys []any
	for _, block := range PEMKeys {
		key, err := cwcrypto.ParsePrivateKeyDER(block.Bytes)
		requirements.NoErrorf(err, "GetPrivateKey() returns malformed data: %s", err)
		keys = append(keys, key)
	}
	for _, key := range keys {
		assertions.Truef(isValidPrivateKeyType(key), "Private key must be one of expected types, actual: %T", key)
	}
}

func TestGetCertificate(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certificateFile, err := os.ReadFile("../../test/pem/testChain.pem")
	requirements.NoErrorf(err, "error reading cert chain file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + CertificatesAPIPath + "test":
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
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	PEMCerts, err := cw.GetCertificate("test", TestCertToken)
	requirements.NoErrorf(err, "GetCertificate() failed: %s", err)

	var certs []*x509.Certificate
	for _, block := range PEMCerts {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "GetCertificate() returns malformed data: %s", err)
		certs = append(certs, cert)
	}
	for _, cert := range certs {
		assertions.IsTypef(&x509.Certificate{}, cert, "Certificate should be a valid x509 certificate, actual type: %T", cert)
	}
}

func TestGetPrivateCertChain(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	certChainFile, err := os.ReadFile("../../test/pem/testFullChain.pem")
	requirements.NoErrorf(err, "error reading cert chain file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + PrivateCertChainsAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken+"."+TestKeyToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(certChainFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	PEMCertKeyChains, err := cw.GetPrivateCertChain("test", TestCertToken+"."+TestKeyToken)
	requirements.NoErrorf(err, "GetPrivateCertChain() failed: %s", err)

	certChain := make([]*x509.Certificate, 0)
	var keys []any
	for _, block := range PEMCertKeyChains {
		if block.Type != "CERTIFICATE" {
			key, err := cwcrypto.ParsePrivateKeyDER(block.Bytes)
			requirements.NoErrorf(err, "GetPrivateCertChain() returns malformed data: %s", err)
			keys = append(keys, key)
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			requirements.NoErrorf(err, "GetPrivateCertChain() returns malformed data: %s", err)
			certChain = append(certChain, cert)
		}
	}
	assertions.GreaterOrEqualf(len(certChain), 2, "GetPrivateCertChain() should return at least two certificates, actual count: %d", len(certChain))
	assertions.Len(keys, 1, "GetPrivateCertChain() should return only one private key, actual count: %d", len(keys))
	signer, ok := keys[0].(crypto.Signer)
	requirements.Truef(ok, "Private key type does not implement crypto.Signer, actual type: %T", keys[0])

	var userCert *x509.Certificate
	for i, cert := range certChain {
		if len(cert.DNSNames) > 0 {
			userCert = cert
			certChain = append(certChain[:i], certChain[i+1:]...)
			break
		}
	}
	requirements.NotEmpty(userCert, "Did not find valid leaf certificate")

	a, err := x509.MarshalPKIXPublicKey(userCert.PublicKey)
	requirements.NoErrorf(err, "Failed to marshal user certificate public key to DER form")
	b, err := x509.MarshalPKIXPublicKey(signer.Public())
	requirements.NoErrorf(err, "Failed to marshal private key to DER form")
	assertions.Equal(a, b, "GetPrivateCertChain() returned mismatched private key and certificate")
}

func TestGetPFX(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	pfxFile, err := os.ReadFile("../../test/pem/testPFX.p12")
	requirements.NoErrorf(err, "error reading PFX: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + PFXAPIPath + "test":
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
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	rawPFX, err := cw.GetPFX("test", TestCertToken+"."+TestKeyToken)
	requirements.NoErrorf(err, "GetPFX() failed: %s", err)

	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(rawPFX, TestKeyToken)
	requirements.NoErrorf(err, "GetPFX() returns malformed data: %s", err)

	assertions.Truef(isValidPrivateKeyType(privateKey), "Private key must be one of expected types, actual: %T", privateKey)
	assertions.IsType(&x509.Certificate{}, certificate, "GetPFX() did not return a valid leaf certificate")

	signer, ok := privateKey.(crypto.Signer)
	requirements.Truef(ok, "Private key type does not implement crypto.Signer, actual type: %T", privateKey)

	a, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	requirements.NoErrorf(err, "Failed to marshal certificate public key to DER form")
	b, err := x509.MarshalPKIXPublicKey(signer.Public())
	requirements.NoErrorf(err, "Failed to marshal private key to DER form")

	assertions.Equal(a, b, "GetPFX() returned mismatched private key and certificate")
	assertions.GreaterOrEqual(len(caCerts), 1, "GetPFX() should return at least one CA certificate")
}

func TestGetPrivateCert(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	keyPairFile, err := os.ReadFile("../../test/pem/testKeyPair.pem")
	requirements.NoErrorf(err, "error reading key pair file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + PrivateCertsAPIPath + "test":
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
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	PEMCertKeyChains, err := cw.GetPrivateCert("test", TestCertToken+"."+TestKeyToken)
	requirements.NoErrorf(err, "GetPrivateCert() failed: %s", err)

	var privateKey any
	var userCert *x509.Certificate
	for _, block := range PEMCertKeyChains {
		if block.Type != "CERTIFICATE" {
			privateKey, err = cwcrypto.ParsePrivateKeyDER(block.Bytes)
			requirements.NoErrorf(err, "GetPrivateCert() returns malformed data: %s", err)
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			requirements.NoErrorf(err, "GetPrivateCert() returns malformed data: %s", err)
			if len(cert.DNSNames) > 0 {
				userCert = cert
			}
		}
	}
	requirements.NotNil(userCert, "Did not find valid leaf certificate")
	assertions.Truef(isValidPrivateKeyType(privateKey), "Private key must be one of expected types, actual: %T", privateKey)

	signer, ok := privateKey.(crypto.Signer)
	requirements.Truef(ok, "PrivateKey type does not implement crypto.Signer, actual type: %T", privateKey)

	a, err := x509.MarshalPKIXPublicKey(userCert.PublicKey)
	requirements.NoErrorf(err, "Failed to marshal certificate public key to DER form")
	b, err := x509.MarshalPKIXPublicKey(signer.Public())
	requirements.NoErrorf(err, "Failed to marshal private key to DER form")

	assertions.Equal(a, b, "GetPrivateCert() returned mismatched private key and certificate")
}

func TestGetCertRootChain(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	chainFile, err := os.ReadFile("../../test/pem/testCACert.pem")
	requirements.NoErrorf(err, "error reading root cert file: %s", err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DownloadAPIPath + CertRootChainsAPIPath + "test":
			auth := r.Header.Get("X-API-Key")
			if auth != TestCertToken {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write(chainFile)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	cw := new(CertWarden{Context: ctx, HostURL: server.URL, Client: &http.Client{}})
	PEMCerts, err := cw.GetCertRootChain("test", TestCertToken)
	requirements.NoErrorf(err, "GetCertRootChain() failed: %s", err)

	for _, block := range PEMCerts {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "GetCertRootChain() returns malformed data: %s", err)
		assertions.NotNil(cert)
	}
}
