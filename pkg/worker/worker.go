package worker

import (
	"certwarden-client/pkg/api"
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/crypto"
	"certwarden-client/pkg/logger"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

type CertJob struct {
	Name         string
	APIHostURL   string
	CertToken    string
	KeyToken     string
	OnRefreshCmd string
	SavePath     string
	Kind         config.CertKind
	RunInterval  time.Duration
	JobTimeout   time.Duration
}

type CompareStruct struct {
	Key          any
	Certificates []*x509.Certificate
}

func compareKeys(oldKey, newKey any) (bool, error) {
	if oldKey == nil && newKey == nil {
		return true, nil
	}

	if oldKey == nil || newKey == nil {
		return false, nil
	}

	oldPEM, err := crypto.EncodePrivateKeyPEM(oldKey)
	if err != nil {
		return false, err
	}

	newPEM, err := crypto.EncodePrivateKeyPEM(newKey)
	if err != nil {
		return false, err
	}

	return crypto.ComparePrivateKeys(oldPEM, newPEM), nil
}

func compareCertificates(oldCerts, newCerts []*x509.Certificate) bool {
	if oldCerts == nil && newCerts == nil {
		return true
	}

	if oldCerts == nil || newCerts == nil {
		return false
	}

	oldMap := make(crypto.CertChainMap, len(oldCerts))
	newMap := make(crypto.CertChainMap, len(newCerts))

	for _, cert := range oldCerts {
		oldMap[cert.Subject.String()] = cert
	}

	for _, cert := range newCerts {
		newMap[cert.Subject.String()] = cert
	}

	return crypto.CompareCertChainMaps(&oldMap, &newMap)
}

func compare(oldCS, newCS *CompareStruct) (bool, error) {
	if oldCS == newCS {
		return true, nil
	}

	if oldCS == nil || newCS == nil {
		return false, nil
	}

	keysEqual, err := compareKeys(oldCS.Key, newCS.Key)
	if err != nil || !keysEqual {
		return keysEqual, err
	}

	return compareCertificates(oldCS.Certificates, newCS.Certificates), nil
}

func (j *CertJob) Run(ctx context.Context) error {
	logFields := logrus.Fields{
		"job":    j.Name,
		"worker": ctx.Value("worker"),
	}
	logger.Log.WithFields(logFields).Info("Running fetch job")
	cw := new(api.CertWarden{Context: ctx, HostURL: j.APIHostURL, Client: &http.Client{}})
	filesChanged := false
	var filePath string
	var serverKeys, existingKeys []any
	var serverCertChain, existingCertChain []*x509.Certificate
	compareFunc := func(skipCompare bool) error {
		var serverKey, existingKey any
		if serverKeys != nil && len(serverKeys) > 0 {
			serverKey = serverKeys[0]
		}
		if existingKeys != nil && len(existingKeys) > 0 {
			existingKey = existingKeys[0]
		}
		if skipCompare {
			logger.Log.WithFields(logFields).Info("Writing new files to disk")
			err := saveCertKeyChainToFile(
				filePath,
				serverCertChain,
				serverKeys,
			)
			if err != nil {
				return err
			}
			filesChanged = true
		} else {
			dataMatches, err := compare(
				&CompareStruct{
					existingKey,
					existingCertChain,
				},
				&CompareStruct{
					serverKey,
					serverCertChain,
				},
			)
			if err != nil {
				return err
			}
			if !dataMatches {
				logger.Log.WithFields(logFields).Info("Writing new files to disk")
				err = saveCertKeyChainToFile(
					filePath,
					serverCertChain,
					serverKeys,
				)
				if err != nil {
					return err
				}
				filesChanged = true
			}
		}
		return nil
	}
	switch j.Kind {
	case config.KindPrivateKey:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s_key.pem", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching private key")
		var err error
		serverKeys, err = fetchPrivateKeys(cw, j.Name, j.KeyToken)
		if err != nil {
			return err
		}
		if len(serverKeys) == 0 {
			return errors.New("empty response from server")
		}

		logger.Log.WithFields(logFields).Info("Checking for existing private key file")
		_, existingKeys, err = loadCertKeyChainFromFile(filePath)
		if err != nil {
			return err
		}

		err = compareFunc(len(existingKeys) == 0)
		if err != nil {
			return err
		}
	case config.KindCertificate:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s_certchain.pem", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching certificate chain")
		var err error
		serverCertChain, err = fetchCertChain(cw, j.Name, j.CertToken)
		if err != nil {
			return err
		}
		if len(serverCertChain) == 0 {
			return errors.New("empty response from server")
		}

		logger.Log.WithFields(logFields).Info("Checking for existing certificate file")
		existingCertChain, _, err = loadCertKeyChainFromFile(filePath)
		if err != nil {
			return err
		}

		err = compareFunc(len(existingCertChain) == 0)
		if err != nil {
			return err
		}
	case config.KindPrivateCertChain:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s_keycertchain.pem", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching certificate chain+key pair")
		var err error
		serverCertChain, serverKeys, err = fetchPrivateCertChain(cw, j.Name, j.CertToken+"."+j.KeyToken)
		if err != nil {
			return err
		}
		if len(serverCertChain) == 0 {
			return errors.New("invalid response from server: no certificates found")
		}
		if len(serverKeys) == 0 {
			return errors.New("invalid response from server: no private keys found")
		}

		logger.Log.WithFields(logFields).Info("Checking for existing certificate chain+key pair file")
		existingCertChain, existingKeys, err = loadCertKeyChainFromFile(filePath)
		if err != nil {
			return err
		}

		err = compareFunc(len(existingCertChain) == 0 || len(existingKeys) == 0)
		if err != nil {
			return err
		}
	case config.KindPFX:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s.p12", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching PFX")
		pfxData, err := cw.GetPFX(j.Name, j.CertToken+"."+j.KeyToken)
		if err != nil {
			return err
		}
		serverPrivateKey, serverCertificate, serverCACerts, err := pkcs12.DecodeChain(pfxData, j.KeyToken)
		if err != nil {
			return err
		}

		logger.Log.WithFields(logFields).Info("Checking for existing PFX file")
		existingPFXData, err := loadFromFile(filePath)
		if err != nil {
			return err
		}

		if len(existingPFXData) == 0 {
			logger.Log.WithFields(logFields).Info("Writing new files to disk")
			err = saveToFile(filePath, pfxData)
			if err != nil {
				return err
			}
			filesChanged = true
		} else {
			existingPrivateKey, existingCertificate, existingCACerts, err := pkcs12.DecodeChain(existingPFXData, j.KeyToken)
			if err != nil {
				return err
			}
			dataMatches, err := compare(
				&CompareStruct{
					existingPrivateKey,
					append([]*x509.Certificate{existingCertificate}, existingCACerts...),
				},
				&CompareStruct{
					serverPrivateKey,
					append([]*x509.Certificate{serverCertificate}, serverCACerts...),
				},
			)
			if err != nil {
				return err
			}
			if !dataMatches {
				logger.Log.WithFields(logFields).Info("Writing new files to disk")
				err = saveToFile(filePath, pfxData)
				if err != nil {
					return err
				}
				filesChanged = true
			}
		}
	case config.KindPrivateCert:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s_keycert.pem", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching certificate+key pair")
		var err error
		serverCertChain, serverKeys, err = fetchPrivateCert(cw, j.Name, j.CertToken+"."+j.KeyToken)
		if err != nil {
			return err
		}
		if len(serverCertChain) == 0 {
			return errors.New("invalid response from server: no certificates found")
		}
		if len(serverKeys) == 0 {
			return errors.New("invalid response from server: no private keys found")
		}

		logger.Log.WithFields(logFields).Info("Checking for existing certificate+key pair file")
		existingCertChain, existingKeys, err = loadCertKeyChainFromFile(filePath)
		if err != nil {
			return err
		}

		err = compareFunc(len(existingCertChain) == 0 || len(existingKeys) == 0)
		if err != nil {
			return err
		}
	case config.KindCertRootChain:
		filePath = filepath.Join(j.SavePath, fmt.Sprintf("%s_rootchain.pem", j.Name))
		logger.Log.WithFields(logFields).Info("Fetching certificate root chain")
		var err error
		serverCertChain, err = fetchRootCertChain(cw, j.Name, j.CertToken)
		if err != nil {
			return err
		}
		if len(serverCertChain) == 0 {
			return errors.New("invalid response from server: no certificates found")
		}

		logger.Log.WithFields(logFields).Info("Checking for existing certificate root chain file")
		existingCertChain, _, err = loadCertKeyChainFromFile(filePath)
		if err != nil {
			return err
		}

		err = compareFunc(len(existingCertChain) == 0)
		if err != nil {
			return err
		}
	}

	if filesChanged && j.OnRefreshCmd != "" {
		logger.Log.WithFields(logFields).Infof("Files changed, running on-refresh command: %s", j.OnRefreshCmd)
		cmd := exec.Command("bash", "-c", j.OnRefreshCmd)
		result, err := cmd.CombinedOutput()
		if err != nil {
			var exitErr *exec.ExitError
			ok := errors.As(err, &exitErr)
			if !ok {
				logger.Log.WithFields(logFields).Errorf(
					"Failed to run on-refresh command: %s", err)
			} else {
				logger.Log.WithFields(logFields).Errorf(
					"Command failed: %s, output: \"%s\"",
					exitErr.Error(),
					string(result),
				)
			}
		} else {
			logger.Log.WithFields(logFields).Infof("Command succeeded, output: \"%s\"", string(result))
		}

	} else {
		logger.Log.WithFields(logFields).Info("No changes detected.")
	}
	logger.Log.WithFields(logFields).Info("Done.")
	return nil
}
