package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareCertChainMapsEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	assertions.True(CompareCertChainMaps(nil, nil))

	leftCertMap := CertChainMap{}
	rightCertMap := CertChainMap{}
	// same pointer
	assertions.True(CompareCertChainMaps(&leftCertMap, &leftCertMap))
	// both empty
	assertions.True(CompareCertChainMaps(&leftCertMap, &rightCertMap))

	testChainFile, err := os.ReadFile("../../test/pem/testChain.pem")
	requirements.NoErrorf(err, "failed to read test chain file: %s", err)

	testChainReversedFile, err := os.ReadFile("../../test/pem/testChainReversed.pem")
	requirements.NoErrorf(err, "failed to read reversed test chain file: %s", err)

	leftPEMChain, err := DecodePEMBlocks(testChainFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	rightPEMChain, err := DecodePEMBlocks(testChainReversedFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)

	for _, block := range leftPEMChain {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "failed to parse certificate: %s", err)
		leftCertMap[cert.Subject.String()] = cert
	}

	for _, block := range rightPEMChain {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "failed to parse certificate: %s", err)
		rightCertMap[cert.Subject.String()] = cert
	}

	assertions.True(CompareCertChainMaps(&leftCertMap, &rightCertMap))
	assertions.True(CompareCertChainMaps(&rightCertMap, &leftCertMap))

}

func TestCompareCertChainMapsNotEqual(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	leftCertMap := CertChainMap{
		"subj": &x509.Certificate{},
	}

	// One is nil
	assertions.False(CompareCertChainMaps(&leftCertMap, nil))
	assertions.False(CompareCertChainMaps(nil, &leftCertMap))

	testChainFile, err := os.ReadFile("../../test/pem/testChain.pem")
	requirements.NoErrorf(err, "failed to read test chain file: %s", err)

	rightCertMap := make(CertChainMap)
	rightPEMChain, err := DecodePEMBlocks(testChainFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)
	for _, block := range rightPEMChain {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "failed to parse certificate: %s", err)
		rightCertMap[cert.Subject.String()] = cert
	}

	singleCertFile, err := os.ReadFile("../../test/pem/testCertificate.pem")
	requirements.NoErrorf(err, "failed to load certificate file: %s", err)

	singleCertPEM, _ := pem.Decode(singleCertFile)
	requirements.NotNil(singleCertPEM)

	singleCert, err := x509.ParseCertificate(singleCertPEM.Bytes)
	requirements.NoErrorf(err, "failed to parse certificate: %s", err)
	leftCertMap = make(CertChainMap)
	leftCertMap[singleCert.Subject.String()] = singleCert

	// Different lengths
	assertions.False(CompareCertChainMaps(&leftCertMap, &rightCertMap))
	assertions.False(CompareCertChainMaps(&rightCertMap, &leftCertMap))

	testChainFile, err = os.ReadFile("../../test/pem/testAnotherChain.pem")
	requirements.NoErrorf(err, "failed to read test chain file: %s", err)
	leftPEMChain, err := DecodePEMBlocks(testChainFile)
	requirements.NoErrorf(err, "failed to decode PEM blocks: %s", err)
	leftCertMap = make(CertChainMap)
	for _, block := range leftPEMChain {
		cert, err := x509.ParseCertificate(block.Bytes)
		requirements.NoErrorf(err, "failed to parse certificate: %s", err)
		leftCertMap[cert.Subject.String()] = cert
	}

	// Different certificate sets
	assertions.False(CompareCertChainMaps(&leftCertMap, &rightCertMap))
	assertions.False(CompareCertChainMaps(&rightCertMap, &leftCertMap))

	leftCertMap = make(CertChainMap)
	for key, value := range rightCertMap {
		patchedValue := *value
		patchedValue.Raw = []byte("somethingelse")
		leftCertMap[key] = &patchedValue
	}

	// Different certificate contents
	assertions.False(CompareCertChainMaps(&leftCertMap, &rightCertMap))
	assertions.False(CompareCertChainMaps(&rightCertMap, &leftCertMap))
}
