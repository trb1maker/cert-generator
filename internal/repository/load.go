package repository

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
)

var (
	errDecodingPEMBlock      = errors.New("failed to decode PEM block")
	errNotRSAPrivateKey      = errors.New("not RSA private key")
	errEmptyOrganizationName = errors.New("empty organization name")
)

func (c *keyContainer) loadPrivateKey(dir string) error {
	body, err := os.ReadFile(path.Join(dir, "ca.key"))
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" {
		return errDecodingPEMBlock
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParsePKCS8PrivateKey: %w", err)
	}

	c.privateKey = key

	return nil
}

func (c *keyContainer) loadCertificate(dir string) error {
	body, err := os.ReadFile(path.Join(dir, "ca.pem"))
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return errDecodingPEMBlock
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParseCertificate: %w", err)
	}

	if len(cert.Subject.Organization) == 0 {
		return errEmptyOrganizationName
	}

	c.organization = cert.Subject.Organization[0]
	c.certificate = cert

	return nil
}
