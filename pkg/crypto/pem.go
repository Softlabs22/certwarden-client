package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func DecodePEMBlocks(rawData []byte) ([]*pem.Block, error) {
	blocks := make([]*pem.Block, 0)
	for len(rawData) > 0 {
		var block *pem.Block
		block, rawData = pem.Decode(rawData)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func EncodePrivateKeyPEM(key any) (*pem.Block, error) {
	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:    "PRIVATE KEY",
		Bytes:   rawKey,
		Headers: map[string]string{},
	}
	return pemBlock, nil
}

func ParsePEMChain(chain []*pem.Block) ([]*x509.Certificate, []any, error) {
	if chain == nil {
		return nil, nil, errors.New("got nil PEM chain")
	}
	if len(chain) == 0 {
		return nil, nil, nil
	}
	var certs []*x509.Certificate
	var keys []any
	for _, block := range chain {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			key, err := ParsePrivateKeyDER(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, key)
		} else {
			return nil, nil, errors.New(fmt.Sprintf("unknown PEM block type: %s", block.Type))
		}
	}
	return certs, keys, nil
}
