package crypto

import (
	"certwarden-client/pkg/logger"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
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

func ComparePrivateKeys(old []byte, new []byte) bool {
	if old == nil {
		if new == nil {
			return true
		}
		return false
	}

	oldSha1 := sha1.Sum(old)
	newSha1 := sha1.Sum(new)
	logger.Log.Debugf("Old key SHA1: %s, new key SHA1: %s", hex.EncodeToString(oldSha1[:]), hex.EncodeToString(newSha1[:]))
	return oldSha1 == newSha1
}
