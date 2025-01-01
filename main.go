package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"
	"strings"

	"github.com/trb1maker/cert-generator/internal/repository"
)

var (
	cert, dir, organization string
	domens                  []string
)

func init() {
	var domens_string string

	flag.StringVar(&cert, "cert", "ca", "expect: ['ca', 'self', 'child']")
	flag.StringVar(&dir, "dir", ".", "path to store certificate")
	flag.StringVar(&organization, "organization", "", "organization name")
	flag.StringVar(&domens_string, "domens", "", "list of domens")

	flag.Parse()

	domens = strings.Split(domens_string, ",")
}

func app() error {
	store := new(repository.Repository)

	switch cert {
	case "ca":
		slog.Info("Init CA...")
		if err := store.InitCA(dir, organization, domens...); err != nil {
			return err
		}
	case "child":
		slog.Info("Load CA...")
		if err := store.LoadCA(dir); err != nil {
			slog.Error("Load CA", "err", err)

			slog.Info("Init CA...")
			if err := store.InitCA(dir, organization, domens...); err != nil {
				return err
			}
		}

		slog.Info("Signing child certificate...")
		if err := store.Realease(dir, organization, domens...); err != nil {
			return err
		}
	case "self":
		slog.Info("Signing self-sgn certificate...")
		if err := store.RealeaseSelfSign(dir, organization, domens...); err != nil {
			return err
		}
	default:
		return errors.New("expected ['ca', 'self', 'child']")
	}

	return nil
}

func main() {
	if err := app(); err != nil {
		slog.Error("Generator", "err", err)
		os.Exit(1)
	}
}
