package crypto

import (
	"certwarden-client/pkg/logger"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

type CertChainMap = map[string]*x509.Certificate

func printableThumbprint(rawHash [20]byte) string {
	out := make([]string, 20)
	for i, b := range rawHash {
		out[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(out, ":")
}

func CompareCertChainMaps(oldChain *CertChainMap, newChain *CertChainMap) bool {
	if oldChain == newChain {
		return true
	}
	if oldChain == nil || newChain == nil {
		return false
	}

	if len(*oldChain) != len(*newChain) {
		return false
	}

	for key, value := range *newChain {
		oldValue := (*oldChain)[key]
		if oldValue == nil {
			return false
		}
		oldThumbprint, newThumbprint := sha1.Sum(oldValue.Raw), sha1.Sum(value.Raw)
		logger.Log.Debugf(
			"Certificate for \"%s\": old thumbprint: %s, new thumbprint: %s",
			key, printableThumbprint(oldThumbprint), printableThumbprint(newThumbprint),
		)
		if oldThumbprint != newThumbprint {
			return false
		}
	}
	return true
}
