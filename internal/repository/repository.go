package repository

import (
	"errors"
	"fmt"
)

type Repository struct {
	ca keyContainer
}

var errNotImplemented = errors.New("not implemented")

// InitCA create new CA cert and private key.
func (r *Repository) InitCA(dir, organization string, domens ...string) error {
	pair, err := newContainer(true, organization, domens...)
	if err != nil {
		return fmt.Errorf("can't create CA: %w", err)
	}

	if err := pair.sign(&pair); err != nil {
		return fmt.Errorf("can't self-sign CA: %w", err)
	}

	if err := pair.store(true, dir); err != nil {
		return fmt.Errorf("can't store CA: %w", err)
	}

	r.ca = pair

	return nil
}

// LoadCA download ca.key and ca.pem if exists.
func (r *Repository) LoadCA(dir string) error {
	r.ca = keyContainer{}

	if err := r.ca.loadPrivateKey(dir); err != nil {
		return fmt.Errorf("can't load CA private key: %w", err)
	}

	if err := r.ca.loadCertificate(dir); err != nil {
		return fmt.Errorf("can't load CA certificate: %w", err)
	}

	return nil
}

// Realease new cert and private key and sign it with CA
func (r *Repository) Realease(dir, organization string, domens ...string) error {
	pair, err := newContainer(true, organization, domens...)
	if err != nil {
		return fmt.Errorf("can't create certificate: %w", err)
	}

	if err := r.ca.sign(&pair); err != nil {
		return fmt.Errorf("can't sign certificate: %w", err)
	}

	if err := pair.store(false, dir); err != nil {
		return fmt.Errorf("can't store certificate: %w", err)
	}

	return nil
}

// Realease new self-sign cert and private key
func (r *Repository) RealeaseSelfSign(dir, organization string, domens ...string) error {
	pair, err := newContainer(true, organization, domens...)
	if err != nil {
		return fmt.Errorf("can't create certificate: %w", err)
	}

	if err := pair.sign(&pair); err != nil {
		return fmt.Errorf("can't sign certificate: %w", err)
	}

	if err := pair.store(false, dir); err != nil {
		return fmt.Errorf("can't store certificate: %w", err)
	}

	return nil
}
