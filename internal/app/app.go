package app

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html static/*
var webFiles embed.FS

type App struct {
	cfg       Config
	store     *Store
	logger    *slog.Logger
	templates *template.Template
	limiter   *loginLimiter
	cancel    context.CancelFunc
}

type viewData struct {
	Title         string
	CSRF          string
	Error         string
	Message       string
	MustChange    bool
	Subscriptions []Subscription
	Subscription  Subscription
	IsNew         bool
	BaseURL       string
	Logs          LogPage
	FilterIP      string
	FilterClient  string
	PrevPage      int
	NextPage      int
	Settings      Settings
}

type authContext struct {
	Token   string
	Session Session
	Config  Settings
}

type contextKey string

const authContextKey contextKey = "admin-auth"

func New(cfg Config, logger *slog.Logger) (*App, error) {
	defaultHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg.DatabasePath, defaultHash, cfg.DefaultRetain)
	if err != nil {
		return nil, err
	}
	funcs := template.FuncMap{
		"formatTime": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"formatTimeValue": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
		"add":             func(a, b int) int { return a + b },
		"sub":             func(a, b int) int { return a - b },
	}
	templates, err := template.New("pages").Funcs(funcs).ParseFS(webFiles, "templates/*.html")
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		cfg: cfg, store: store, logger: logger, templates: templates,
		limiter: newLoginLimiter(), cancel: cancel,
	}
	go a.cleanupLoop(ctx)
	return a, nil
}

func (a *App) Close() error {
	a.cancel()
	return a.store.Close()
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /admin/login", a.loginPage)
	mux.HandleFunc("POST /admin/login", a.login)
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/", http.FileServer(http.FS(webFiles))))

	mux.Handle("GET /admin/", a.requireAdmin(http.HandlerFunc(a.dashboard)))
	mux.Handle("POST /admin/logout", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.logout))))
	mux.Handle("GET /admin/password", a.requireAdmin(http.HandlerFunc(a.passwordPage)))
	mux.Handle("POST /admin/password", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.changePassword))))
	mux.Handle("GET /admin/subscriptions/new", a.requireAdmin(http.HandlerFunc(a.newSubscriptionPage)))
	mux.Handle("POST /admin/subscriptions", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.createSubscription))))
	mux.Handle("POST /admin/subscriptions/batch-content", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.batchContent))))
	mux.Handle("GET /admin/subscriptions/{id}", a.requireAdmin(http.HandlerFunc(a.editSubscriptionPage)))
	mux.Handle("POST /admin/subscriptions/{id}", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.updateSubscription))))
	mux.Handle("POST /admin/subscriptions/{id}/delete", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.deleteSubscription))))
	mux.Handle("POST /admin/subscriptions/{id}/toggle", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.toggleSubscription))))
	mux.Handle("GET /admin/subscriptions/{id}/preview", a.requireAdmin(http.HandlerFunc(a.previewSubscription)))
	mux.Handle("GET /admin/subscriptions/{id}/qrcode", a.requireAdmin(http.HandlerFunc(a.subscriptionQRCode)))
	mux.Handle("GET /admin/subscriptions/{id}/logs", a.requireAdmin(http.HandlerFunc(a.subscriptionLogs)))
	mux.Handle("POST /admin/subscriptions/{id}/logs/clear", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.clearSubscriptionLogs))))
	mux.Handle("GET /admin/settings", a.requireAdmin(http.HandlerFunc(a.settingsPage)))
	mux.Handle("POST /admin/settings", a.requireAdmin(a.requireCSRF(http.HandlerFunc(a.updateSettings))))
	mux.HandleFunc("GET /", a.publicSubscription)

	return a.securityHeaders(a.requestLogger(mux))
}

func (a *App) cleanupLoop(ctx context.Context) {
	run := func() {
		settings, err := a.store.Settings(ctx)
		if err != nil {
			if ctx.Err() == nil {
				a.logger.Error("load cleanup settings", "error", err)
			}
			return
		}
		if count, err := a.store.CleanupLogs(ctx, settings.LogRetentionDays); err != nil {
			a.logger.Error("clean expired access logs", "error", err)
		} else if count > 0 {
			a.logger.Info("expired access logs removed", "count", count)
		}
		if err := a.store.PurgeExpiredSessions(ctx); err != nil {
			a.logger.Error("clean expired sessions", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			run()
		case <-ctx.Done():
			return
		}
	}
}

func (a *App) render(w http.ResponseWriter, name string, data viewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		a.logger.Error("render template", "template", name, "error", err)
	}
}

func (a *App) renderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	a.render(w, "error.html", viewData{Title: "出错了", Error: message})
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (a *App) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/admin/") {
			r.Body = http.MaxBytesReader(w, r.Body, 3*1024*1024)
		}
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/admin/static/") {
			loggedPath := "/subscription"
			if strings.HasPrefix(r.URL.Path, "/admin") {
				loggedPath = r.URL.Path
			}
			a.logger.Info("request", "method", r.Method, "path", loggedPath, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}

func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func messageFromQuery(value string) string {
	switch value {
	case "created":
		return "订阅已创建"
	case "updated":
		return "订阅已保存"
	case "deleted":
		return "订阅已删除"
	case "toggled":
		return "订阅状态已更新"
	case "batch-updated":
		return "选中的订阅内容已批量更新"
	case "logs-cleared":
		return "访问日志已清空（累计拉取次数保留）"
	case "settings-updated":
		return "系统设置已保存"
	default:
		return ""
	}
}

func parseID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fmt.Errorf("invalid id")
	}
	return id, nil
}

type loginAttempt struct {
	Count       int
	WindowStart time.Time
	LockedUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{attempts: make(map[string]loginAttempt)} }

func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[ip]
	return !time.Now().Before(a.LockedUntil)
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.attempts[ip]
	if a.WindowStart.IsZero() || now.Sub(a.WindowStart) > 15*time.Minute {
		a = loginAttempt{WindowStart: now}
	}
	a.Count++
	if a.Count >= 5 {
		a.LockedUntil = now.Add(15 * time.Minute)
	}
	l.attempts[ip] = a
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}
