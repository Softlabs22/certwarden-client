package worker

import (
	"certwarden-client/pkg/api"
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/crypto"
	"certwarden-client/pkg/logger"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	splitKeyFilename       = "privkey.pem"
	splitCertFilename      = "cert.pem"
	splitFullchainFilename = "fullchain.pem"
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

func saveToFile(path string, data []byte, perms *os.FileMode) error {
	outFile, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, *perms)
	if err != nil {
		return err
	}
	_, err = outFile.Write(data)
	if err != nil {
		_ = outFile.Close()
		return err

	}
	_ = outFile.Sync()
	_ = outFile.Close()
	err = os.Rename(path+".tmp", path)
	if err != nil {
		return err
	}
	return nil
}

func saveCertKeyChainToFile(path string, certs []*x509.Certificate, keys []any, perms *os.FileMode, splitMode bool, jobKind config.CertKind) error {
	savePEMFunc := func(blocks []*pem.Block, path string, perms *os.FileMode) error {
		if len(blocks) > 0 {
			data := make([]byte, 0)
			for _, block := range blocks {
				pemBinary := pem.EncodeToMemory(block)
				if pemBinary == nil {
					return errors.New("failed to encode PEM block")
				}
				data = append(data, pemBinary...)
			}
			err := saveToFile(path, data, perms)
			if err != nil {
				return err
			}
		}
		return nil
	}

	var keyPEMBlocks, certPEMBlocks []*pem.Block
	if keys != nil {
		for _, key := range keys {
			keyPEM, err := crypto.EncodePrivateKeyPEM(key)
			if err != nil {
				return err
			}
			keyPEMBlocks = append(keyPEMBlocks, keyPEM)
		}
	}
	if certs != nil {
		for _, cert := range certs {
			certPEM := &pem.Block{
				Type:    "CERTIFICATE",
				Bytes:   cert.Raw,
				Headers: map[string]string{},
			}
			certPEMBlocks = append(certPEMBlocks, certPEM)
		}
	}

	if splitMode {
		var baseDir, filePrefix string
		stat, err := os.Stat(path)
		if err == nil && stat.IsDir() {
			filePrefix = ""
			baseDir = path
		} else if errors.Is(err, os.ErrNotExist) {
			baseDir, filePrefix = filepath.Split(path)
		} else {
			return err
		}

		var certFilename string
		keyFilename := splitKeyFilename
		switch jobKind {
		case config.KindPrivateCertChain:
			certFilename = splitFullchainFilename
		case config.KindPrivateCert:
			certFilename = splitCertFilename
		default:
			return fmt.Errorf("split mode unsupported for job kind %T", jobKind)
		}

		if filePrefix != "" {
			keyFilename = filePrefix + "_" + keyFilename
			certFilename = filePrefix + "_" + certFilename
		}

		// Enforce safer permissions for private key
		keyPerms := new(*perms & 0740)
		err = savePEMFunc(keyPEMBlocks, filepath.Join(baseDir, keyFilename), keyPerms)
		if err != nil {
			return err
		}
		err = savePEMFunc(certPEMBlocks, filepath.Join(baseDir, certFilename), perms)
		if err != nil {
			return err
		}
		return nil
	}

	pemBlocks := append(keyPEMBlocks, certPEMBlocks...)
	return savePEMFunc(pemBlocks, path, perms)
}

func loadCertKeyChainFromFile(path string, splitMode bool, jobKind config.CertKind) ([]*x509.Certificate, []any, error) {
	var pemData []byte
	var err error
	if splitMode {
		var baseDir, filePrefix string
		stat, err := os.Stat(path)
		if err == nil && stat.IsDir() {
			filePrefix = ""
			baseDir = path
		} else if errors.Is(err, os.ErrNotExist) {
			baseDir, filePrefix = filepath.Split(path)
		} else {
			return nil, nil, err
		}

		var certFilename string
		keyFilename := splitKeyFilename
		switch jobKind {
		case config.KindPrivateCertChain:
			certFilename = splitFullchainFilename
		case config.KindPrivateCert:
			certFilename = splitCertFilename
		default:
			return nil, nil, fmt.Errorf("split mode unsupported for job kind %T", jobKind)
		}

		if filePrefix != "" {
			keyFilename = filePrefix + "_" + keyFilename
			certFilename = filePrefix + "_" + certFilename
		}
		pemData, err = loadFromFile(filepath.Join(baseDir, keyFilename))
		if err != nil {
			return nil, nil, err
		}
		var certsData []byte
		certsData, err = loadFromFile(filepath.Join(baseDir, certFilename))
		if err != nil {
			return nil, nil, err
		}
		// add newline separator just to be sure
		if len(pemData) > 0 {
			pemData = append(pemData, 0x0a)
		}
		pemData = append(pemData, certsData...)
	} else {
		pemData, err = loadFromFile(path)
		if err != nil {
			return nil, nil, err
		}
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
