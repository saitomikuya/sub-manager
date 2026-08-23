package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultMaxUploadBytes int64 = 100 * 1024 * 1024

type Config struct {
	Addr              string
	DatabasePath      string
	FilesDir          string
	MaxUploadBytes    int64
	BaseURL           string
	CookieSecure      string
	TrustedProxies    string
	TrustAllByDefault bool
	SessionHours      int
	DefaultRetain     int
}

func LoadConfig() (Config, error) {
	dataDir := envOr("DATA_DIR", "/data")
	cfg := Config{
		Addr:           envOr("ADDR", ":8080"),
		DatabasePath:   filepath.Join(dataDir, "app.db"),
		FilesDir:       envOr("FILES_DIR", filepath.Join(dataDir, "files")),
		MaxUploadBytes: defaultMaxUploadBytes,
		BaseURL:        strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		CookieSecure:   strings.ToLower(envOr("COOKIE_SECURE", "auto")),
		SessionHours:   12,
		DefaultRetain:  90,
	}
	if path := strings.TrimSpace(os.Getenv("DATABASE_PATH")); path != "" {
		cfg.DatabasePath = path
	}
	if raw := strings.TrimSpace(os.Getenv("MAX_UPLOAD_SIZE_MB")); raw != "" {
		megabytes, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || megabytes < 1 || megabytes > 10240 {
			return Config{}, fmt.Errorf("MAX_UPLOAD_SIZE_MB must be an integer between 1 and 10240")
		}
		cfg.MaxUploadBytes = megabytes * 1024 * 1024
	}
	if cfg.CookieSecure != "auto" && cfg.CookieSecure != "true" && cfg.CookieSecure != "false" {
		return Config{}, fmt.Errorf("COOKIE_SECURE must be auto, true, or false")
	}
	rawTrustedProxies := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if rawTrustedProxies == "" {
		cfg.TrustAllByDefault = true
	} else {
		trustedProxies, err := normalizeTrustedProxies(rawTrustedProxies)
		if err != nil {
			return Config{}, fmt.Errorf("TRUSTED_PROXIES: %w", err)
		}
		cfg.TrustedProxies = trustedProxies
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
