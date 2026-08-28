package config

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort             = 3030
	defaultAttackerLabPort  = 4040
	defaultAppOrigin        = "http://localhost:3030"
	defaultDatabaseFilename = "bearly-secure.sqlite"
	MaxRequestBodyBytes     = 32 * 1024
	MaxUploadBytes          = 1024 * 1024
	MaxPublicProductResults = 50
)

type Config struct {
	PawPalAPIKey            string
	AppOrigin               string
	Port                    int
	DatabasePath            string
	AcornFulfillmentDelay   time.Duration
	MaxRequestBodyBytes     int64
	MaxUploadBytes          int64
	MaxPublicProductResults int
}

type AttackerLabConfig struct {
	Port int
}

func Load(workingDirectory string) (Config, error) {
	return Parse(processEnvironment(), workingDirectory)
}

func LoadAttackerLab(workingDirectory string) (AttackerLabConfig, error) {
	return ParseAttackerLab(processEnvironment())
}

func Parse(environment map[string]string, workingDirectory string) (Config, error) {
	port, err := parseNonNegativeInteger(valueOrDefault(environment, "PORT", strconv.Itoa(defaultPort)), "PORT")
	if err != nil {
		return Config{}, err
	}
	if port > 65_535 {
		return Config{}, errors.New("PORT must be no greater than 65535")
	}
	appOrigin, err := parseOrigin(valueOrDefault(environment, "APP_ORIGIN", defaultAppOrigin))
	if err != nil {
		return Config{}, err
	}

	acornFulfillmentDelay, err := parseDelay(valueOrDefault(environment, "ACORN_FULFILLMENT_DELAY_MS", "0"))
	if err != nil {
		return Config{}, err
	}

	databasePath := environment["DATABASE_URL"]
	if databasePath == "" {
		databasePath = filepath.Join(workingDirectory, "data", defaultDatabaseFilename)
	}

	return Config{
		PawPalAPIKey:            "bs_test_pawpal_starter_key",
		AppOrigin:               appOrigin,
		Port:                    port,
		DatabasePath:            databasePath,
		AcornFulfillmentDelay:   acornFulfillmentDelay,
		MaxRequestBodyBytes:     MaxRequestBodyBytes,
		MaxUploadBytes:          MaxUploadBytes,
		MaxPublicProductResults: MaxPublicProductResults,
	}, nil
}

func ParseAttackerLab(environment map[string]string) (AttackerLabConfig, error) {
	port, err := parseNonNegativeInteger(valueOrDefault(environment, "ATTACKER_LAB_PORT", strconv.Itoa(defaultAttackerLabPort)), "ATTACKER_LAB_PORT")
	if err != nil {
		return AttackerLabConfig{}, err
	}
	if port > 65_535 {
		return AttackerLabConfig{}, errors.New("ATTACKER_LAB_PORT must be no greater than 65535")
	}
	return AttackerLabConfig{Port: port}, nil
}

func processEnvironment() map[string]string {
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found {
			environment[name] = value
		}
	}
	return environment
}

func valueOrDefault(environment map[string]string, name, fallback string) string {
	if value := environment[name]; value != "" {
		return value
	}
	return fallback
}

func parseNonNegativeInteger(value, name string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return parsed, nil
}

func parseOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("APP_ORIGIN must be an absolute URL")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func parseDelay(value string) (time.Duration, error) {
	milliseconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(milliseconds) || math.IsInf(milliseconds, 0) || milliseconds < 0 {
		return 0, errors.New("ACORN_FULFILLMENT_DELAY_MS must be a non-negative number")
	}
	if milliseconds > float64(math.MaxInt64)/float64(time.Millisecond) {
		return 0, errors.New("ACORN_FULFILLMENT_DELAY_MS is too large")
	}
	return time.Duration(milliseconds * float64(time.Millisecond)), nil
}
