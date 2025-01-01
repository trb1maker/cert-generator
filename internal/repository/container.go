package repository

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"time"
)

const (
	keySize         = 2048
	maxSerialNumber = 1 << 62
	permitions      = 0600
)

func newContainer(isCA bool, organization string, domens ...string) (keyContainer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return keyContainer{}, fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(maxSerialNumber))
	if err != nil {
		return keyContainer{}, fmt.Errorf("rand.Int: %w", err)
	}

	var certUsage x509.KeyUsage
	if isCA {
		certUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		certUsage = x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature
	}

	cert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{organization}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              certUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              append(domens, "localhost"),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	return keyContainer{organization: organization, privateKey: key, certificate: cert}, nil
}

type keyContainer struct {
	organization string
	privateKey   *rsa.PrivateKey
	certificate  *x509.Certificate
	der          []byte
}

func (c *keyContainer) sign(child *keyContainer) error {
	der, err := x509.CreateCertificate(
		rand.Reader,
		child.certificate,
		c.certificate,
		&child.privateKey.PublicKey,
		c.privateKey,
	)
	if err != nil {
		return fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	child.der = der

	return nil
}

func (c *keyContainer) store(isCA bool, dir string) error {
	if err := c.storePrivateKey(isCA, dir); err != nil {
		return fmt.Errorf("store private key: %w", err)
	}

	if err := c.storeCertificate(isCA, dir); err != nil {
		return fmt.Errorf("store certificate: %w", err)
	}

	return nil
}

func (c *keyContainer) storePrivateKey(isCA bool, dir string) error {
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
	})

	var name string
	if isCA {
		name = "ca"
	} else {
		name = c.organization
	}

	if err := os.WriteFile(path.Join(dir, name+".key"), body, permitions); err != nil {
		return fmt.Errorf("os.WriteFile: %w", err)
	}

	return nil
}

func (c *keyContainer) storeCertificate(isCA bool, dir string) error {
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.der,
	})

	var name string
	if isCA {
		name = "ca"
	} else {
		name = c.organization
	}

	if err := os.WriteFile(path.Join(dir, name+".pem"), body, permitions); err != nil {
		return fmt.Errorf("os.WriteFile: %w", err)
	}

	return nil
}
