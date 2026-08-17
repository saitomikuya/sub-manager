package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Addr          string
	DatabasePath  string
	BaseURL       string
	CookieSecure  string
	SessionHours  int
	DefaultRetain int
}

func LoadConfig() (Config, error) {
	dataDir := envOr("DATA_DIR", "/data")
	cfg := Config{
		Addr:          envOr("ADDR", ":8080"),
		DatabasePath:  filepath.Join(dataDir, "app.db"),
		BaseURL:       strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		CookieSecure:  strings.ToLower(envOr("COOKIE_SECURE", "auto")),
		SessionHours:  12,
		DefaultRetain: 90,
	}
	if path := strings.TrimSpace(os.Getenv("DATABASE_PATH")); path != "" {
		cfg.DatabasePath = path
	}
	if cfg.CookieSecure != "auto" && cfg.CookieSecure != "true" && cfg.CookieSecure != "false" {
		return Config{}, fmt.Errorf("COOKIE_SECURE must be auto, true, or false")
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
