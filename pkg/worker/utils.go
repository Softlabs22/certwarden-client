package worker

import (
	"certwarden-client/pkg/api"
	"certwarden-client/pkg/crypto"
	"certwarden-client/pkg/logger"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

func fetchPrivateKeys(cw *api.CertWarden, name string, auth string) ([]any, error) {
	data, err := cw.GetPrivateKey(name, auth)
	if err != nil {
		return nil, err
	}
	_, keys, err := crypto.ParsePEMChain(data)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func fetchCertChain(cw *api.CertWarden, name string, auth string) ([]*x509.Certificate, error) {
	data, err := cw.GetCertificate(name, auth)
	if err != nil {
		return nil, err
	}
	certs, _, err := crypto.ParsePEMChain(data)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func fetchRootCertChain(cw *api.CertWarden, name string, auth string) ([]*x509.Certificate, error) {
	data, err := cw.GetCertRootChain(name, auth)
	if err != nil {
		return nil, err
	}
	certs, _, err := crypto.ParsePEMChain(data)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func fetchPrivateCertChain(cw *api.CertWarden, name string, auth string) ([]*x509.Certificate, []any, error) {
	data, err := cw.GetPrivateCertChain(name, auth)
	if err != nil {
		return nil, nil, err
	}
	certs, keys, err := crypto.ParsePEMChain(data)
	if err != nil {
		return nil, nil, err
	}
	return certs, keys, nil
}

func fetchPrivateCert(cw *api.CertWarden, name string, auth string) ([]*x509.Certificate, []any, error) {
	data, err := cw.GetPrivateCert(name, auth)
	if err != nil {
		return nil, nil, err
	}
	certs, keys, err := crypto.ParsePEMChain(data)
	if err != nil {
		return nil, nil, err
	}
	return certs, keys, nil
}

func loadFromFile(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Log.Infof("%s does not exist", path)
		return []byte{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func saveToFile(path string, data []byte) error {
	outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer func(outFile *os.File) {
		_ = outFile.Close()
	}(outFile)
	_, err = outFile.Write(data)
	if err != nil {
		return err
	}
	_ = outFile.Sync()
	return nil
}

func saveCertKeyChainToFile(path string, certs []*x509.Certificate, keys []any) error {
	var pemBlocks []*pem.Block
	if keys != nil {
		for _, key := range keys {
			keyPEM, err := crypto.EncodePrivateKeyPEM(key)
			if err != nil {
				return err
			}
			pemBlocks = append(pemBlocks, keyPEM)
		}
	}
	if certs != nil {
		for _, cert := range certs {
			certPEM := &pem.Block{
				Type:    "CERTIFICATE",
				Bytes:   cert.Raw,
				Headers: map[string]string{},
			}
			pemBlocks = append(pemBlocks, certPEM)
		}
	}

	if len(pemBlocks) > 0 {
		data := make([]byte, 0)
		for _, block := range pemBlocks {
			pemBinary := pem.EncodeToMemory(block)
			if pemBinary == nil {
				return errors.New("failed to encode PEM block")
			}
			data = append(data, pemBinary...)
		}
		err := saveToFile(path, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadCertKeyChainFromFile(path string) ([]*x509.Certificate, []any, error) {
	pemData, err := loadFromFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(pemData) == 0 {
		return nil, nil, nil
	}

	var pemBlocks []*pem.Block
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, nil, fmt.Errorf("failed to decode PEM block")
		}
		pemBlocks = append(pemBlocks, block)
	}

	certs, keys, err := crypto.ParsePEMChain(pemBlocks)
	if err != nil {
		return nil, nil, err
	}
	return certs, keys, nil
}
