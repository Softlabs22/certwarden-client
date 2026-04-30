package crypto

import (
	"certwarden-client/pkg/logger"
	"crypto/x509"
	"errors"
)

func ParsePrivateKeyDER(rawKey []byte) (any, error) {
	if rawKey == nil {
		return nil, errors.New("got nil key")
	}

	key, err := x509.ParsePKCS8PrivateKey(rawKey)
	if err != nil {
		logger.Log.Debug("Not a PKCS8 private key, trying EC")
		key, err = x509.ParseECPrivateKey(rawKey)
		if err != nil {
			logger.Log.Debug("Not a EC private key, trying PKCS1")
			key, err = x509.ParsePKCS1PrivateKey(rawKey)
			if err != nil {
				return nil, errors.New("could not parse private key as PKCS8, EC or PKCS1")
			}
		}
	}
	return key, nil
}
