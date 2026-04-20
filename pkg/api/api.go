package api

import (
	"certwarden-client/pkg/crypto"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
)

const (
	DownloadAPIPath          = "/certwarden/api/v1/download"
	PrivateKeysAPIPath       = "/privatekeys/"
	CertificatesAPIPath      = "/certificates/"
	PrivateCertChainsAPIPath = "/privatecertchains/"
	PFXAPIPath               = "/pfx/"
	PrivateCertsAPIPath      = "/privatecerts/"
	CertRootChainsAPIPath    = "/certrootchains/"
)

type CertWarden struct {
	Context context.Context
	HostURL string
	Client  *http.Client
}

func makeAPIRequest(c *CertWarden, path string, authToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(c.Context, "GET", c.HostURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-Api-Key", authToken)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *CertWarden) GetPrivateKey(name string, authToken string) ([]*pem.Block, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+PrivateKeysAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}

	return crypto.DecodePEMBlocks(body)
}

func (c *CertWarden) GetCertificate(name string, authToken string) ([]*pem.Block, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+CertificatesAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}

	return crypto.DecodePEMBlocks(body)
}

func (c *CertWarden) GetPrivateCertChain(name string, authToken string) ([]*pem.Block, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+PrivateCertChainsAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}

	return crypto.DecodePEMBlocks(body)
}

func (c *CertWarden) GetPFX(name string, authToken string) ([]byte, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+PFXAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *CertWarden) GetPrivateCert(name, authToken string) ([]*pem.Block, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+PrivateCertsAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}

	return crypto.DecodePEMBlocks(body)
}

func (c *CertWarden) GetCertRootChain(name, authToken string) ([]*pem.Block, error) {
	body, err := makeAPIRequest(c, DownloadAPIPath+CertRootChainsAPIPath+name, authToken)
	if err != nil {
		return nil, err
	}

	return crypto.DecodePEMBlocks(body)
}
