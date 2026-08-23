package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestApp(t *testing.T) *App {
	return newTestAppWithTrustedProxies(t, "")
}

func newTestAppWithTrustedProxies(t *testing.T, trustedProxies string) *App {
	t.Helper()
	cfg := Config{
		Addr: ":0", DatabasePath: filepath.Join(t.TempDir(), "app.db"), CookieSecure: "false",
		TrustedProxies: trustedProxies, TrustAllByDefault: trustedProxies == "",
		SessionHours: 12, DefaultRetain: 90,
	}
	application, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	return application
}

func TestInitialLoginPasswordChangeAndSubscriptionFetch(t *testing.T) {
	application := newTestApp(t)
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	response := postForm(t, client, server.URL+"/admin/login", url.Values{"password": {"password"}})
	assertStatus(t, response, http.StatusSeeOther)
	if location := response.Header.Get("Location"); location != "/admin/password" {
		t.Fatalf("login redirect = %q", location)
	}
	response.Body.Close()

	response = get(t, client, server.URL+"/admin/")
	assertStatus(t, response, http.StatusSeeOther)
	if location := response.Header.Get("Location"); location != "/admin/password" {
		t.Fatalf("forced change redirect = %q", location)
	}
	response.Body.Close()

	response = get(t, client, server.URL+"/admin/password")
	csrf := extractCSRF(t, response)
	response.Body.Close()
	response = postForm(t, client, server.URL+"/admin/password", url.Values{
		"csrf_token": {csrf}, "new_password": {"test-pass"}, "confirm_password": {"test-pass"},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()

	response = get(t, client, server.URL+"/admin/")
	assertStatus(t, response, http.StatusOK)
	csrf = extractCSRF(t, response)
	response.Body.Close()

	rawContent := "ss://first\r\nss://second\r\n"
	response = postForm(t, client, server.URL+"/admin/subscriptions", url.Values{
		"csrf_token": {csrf}, "name": {"测试节点"}, "path": {"/ss"}, "content": {rawContent}, "enabled": {"1"},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/ss", nil)
	request.Header.Set("User-Agent", "Shadow"+"rocket/2.2.60")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, http.StatusOK)
	encoded, _ := io.ReadAll(response.Body)
	response.Body.Close()
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}
	if got, want := string(decoded), "ss://first\nss://second"; got != want {
		t.Fatalf("decoded content = %q, want %q", got, want)
	}

	subscriptions, err := application.store.ListSubscriptions(context.Background())
	if err != nil || len(subscriptions) != 1 {
		t.Fatalf("subscriptions = %d, error = %v", len(subscriptions), err)
	}
	if subscriptions[0].FetchCount != 1 || subscriptions[0].LastFetchedAt == nil {
		t.Fatalf("fetch statistics not updated: %+v", subscriptions[0])
	}
	response = get(t, client, server.URL+"/admin/subscriptions/"+strconv.FormatInt(subscriptions[0].ID, 10)+"/qrcode")
	assertStatus(t, response, http.StatusOK)
	if contentType := response.Header.Get("Content-Type"); contentType != "image/png" {
		t.Fatalf("QR content type = %q", contentType)
	}
	qrPNG, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if len(qrPNG) < 8 || string(qrPNG[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("QR response is not a PNG: %x", qrPNG)
	}
	logs, err := application.store.AccessLogs(context.Background(), subscriptions[0].ID, 1, 50, "", "")
	if err != nil || logs.Total != 1 {
		t.Fatalf("logs total = %d, error = %v", logs.Total, err)
	}
	if logs.Logs[0].ClientName != "iOS 代理客户端" || logs.Logs[0].UserAgent != "Shadow"+"rocket/2.2.60" {
		t.Fatalf("unexpected access log: %+v", logs.Logs[0])
	}
}

func TestTrustedProxiesCanBeConfiguredFromAdminPanel(t *testing.T) {
	application := newTestApp(t)
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	response := postForm(t, client, server.URL+"/admin/login", url.Values{"password": {"password"}})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	response = get(t, client, server.URL+"/admin/password")
	csrf := extractCSRF(t, response)
	response.Body.Close()
	response = postForm(t, client, server.URL+"/admin/password", url.Values{
		"csrf_token": {csrf}, "new_password": {"test-pass"}, "confirm_password": {"test-pass"},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()

	response = get(t, client, server.URL+"/admin/settings")
	assertStatus(t, response, http.StatusOK)
	csrf = extractCSRF(t, response)
	response.Body.Close()

	response = postForm(t, client, server.URL+"/admin/settings", url.Values{
		"csrf_token": {csrf}, "log_retention_days": {"90"}, "trusted_proxies": {"not-an-ip"},
	})
	assertStatus(t, response, http.StatusBadRequest)
	invalidBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(invalidBody), "无效的 IP 或 CIDR") {
		t.Fatalf("invalid proxy error not rendered: %s", invalidBody)
	}

	response = postForm(t, client, server.URL+"/admin/settings", url.Values{
		"csrf_token": {csrf}, "log_retention_days": {"90"}, "trusted_proxies": {"172.17.0.1, 10.0.0.0/8"},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	settings, err := application.store.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := settings.TrustedProxies, "172.17.0.1/32\n10.0.0.0/8"; got != want {
		t.Fatalf("stored trusted proxies = %q, want %q", got, want)
	}

	subscriptionID, err := application.store.CreateSubscription(context.Background(), "panel", "/panel", "ss://panel", true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/panel", nil)
	request.RemoteAddr = "172.17.0.1:54321"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("subscription status = %d", recorder.Code)
	}
	logs, err := application.store.AccessLogs(context.Background(), subscriptionID, 1, 50, "", "")
	if err != nil || len(logs.Logs) != 1 {
		t.Fatalf("access logs = %d, error = %v", len(logs.Logs), err)
	}
	if got, want := logs.Logs[0].ClientIP, "203.0.113.10"; got != want {
		t.Fatalf("logged client IP = %q, want %q", got, want)
	}

	response = postForm(t, client, server.URL+"/admin/settings", url.Values{
		"csrf_token": {csrf}, "log_retention_days": {"90"}, "trusted_proxies": {""},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	defaultID, err := application.store.CreateSubscription(context.Background(), "default-all", "/default-all", "ss://default", true)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "http://example.test/default-all", nil)
	request.RemoteAddr = "198.51.100.20:54321"
	request.Header.Set("X-Forwarded-For", "203.0.113.11")
	recorder = httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	logs, err = application.store.AccessLogs(context.Background(), defaultID, 1, 50, "", "")
	if err != nil || len(logs.Logs) != 1 || logs.Logs[0].ClientIP != "203.0.113.11" {
		t.Fatalf("default-all access logs = %+v, error = %v", logs.Logs, err)
	}
}

func TestBatchUpdateIsAtomicWhenAnIDIsMissing(t *testing.T) {
	application := newTestApp(t)
	ctx := context.Background()
	id, err := application.store.CreateSubscription(ctx, "one", "/one", "ss://old", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.store.BatchUpdateContent(ctx, []int64{id, id + 9999}, "ss://new"); err == nil {
		t.Fatal("expected missing subscription error")
	}
	sub, err := application.store.SubscriptionByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Content != "ss://old" {
		t.Fatalf("content changed despite rollback: %q", sub.Content)
	}
}

func TestDisabledAndUnknownSubscriptionsReturnNotFoundWithoutLogging(t *testing.T) {
	application := newTestApp(t)
	id, err := application.store.CreateSubscription(context.Background(), "off", "/off", "ss://node", false)
	if err != nil {
		t.Fatal(err)
	}
	handler := application.Handler()
	for _, path := range []string{"/off", "/missing"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
	logs, err := application.store.AccessLogs(context.Background(), id, 1, 50, "", "")
	if err != nil || logs.Total != 0 {
		t.Fatalf("disabled subscription was logged: total=%d err=%v", logs.Total, err)
	}
}

func TestClientIPResolver(t *testing.T) {
	tests := []struct {
		name, trusted, remote, forwardedFor, realIP, want string
	}{
		{
			name: "unconfigured ignores spoofed headers", remote: "203.0.113.10:1234",
			forwardedFor: "198.51.100.8", realIP: "192.0.2.8", want: "203.0.113.10",
		},
		{
			name: "trusted Caddy IPv4", trusted: "172.17.0.1/32", remote: "172.17.0.1:49152",
			forwardedFor: "203.0.113.10", want: "203.0.113.10",
		},
		{
			name: "trusted IPv6 proxy and IPv6 client", trusted: "2001:db8::1/128", remote: "[2001:db8::1]:443",
			forwardedFor: "2001:db8:1::10", want: "2001:db8:1::10",
		},
		{
			name: "multi proxy chain skips trusted hops from right", trusted: "172.17.0.1,10.0.0.0/8", remote: "172.17.0.1:8081",
			forwardedFor: "198.51.100.77, 10.0.0.9", want: "198.51.100.77",
		},
		{
			name: "untrusted right hop blocks spoofed left value", trusted: "172.17.0.1/32", remote: "172.17.0.1:8081",
			forwardedFor: "203.0.113.55, 198.51.100.9", want: "198.51.100.9",
		},
		{
			name: "single IP configuration applies", trusted: "172.17.0.1", remote: "172.17.0.1:8081",
			realIP: "203.0.113.20", want: "203.0.113.20",
		},
		{
			name: "CIDR configuration applies", trusted: "10.0.0.0/8", remote: "10.44.0.2:8081",
			realIP: "203.0.113.21", want: "203.0.113.21",
		},
		{
			name: "malformed XFF falls back even with valid real IP", trusted: "172.17.0.1/32", remote: "172.17.0.1:8081",
			forwardedFor: "203.0.113.10, not-an-ip", realIP: "198.51.100.8", want: "172.17.0.1",
		},
		{
			name: "empty XFF falls back", trusted: "172.17.0.1/32", remote: "172.17.0.1:8081",
			forwardedFor: " ", realIP: "198.51.100.8", want: "172.17.0.1",
		},
		{
			name: "single real IP used when XFF absent", trusted: "172.17.0.1/32", remote: "172.17.0.1:8081",
			realIP: "198.51.100.8", want: "198.51.100.8",
		},
		{
			name: "comma separated real IP falls back", trusted: "172.17.0.1/32", remote: "172.17.0.1:8081",
			realIP: "198.51.100.8, 203.0.113.8", want: "172.17.0.1",
		},
		{
			name: "IPv4 mapped addresses are normalized", trusted: "172.17.0.1", remote: "[::ffff:172.17.0.1]:8081",
			forwardedFor: "::ffff:203.0.113.10", want: "203.0.113.10",
		},
		{
			name: "all trusted forwarded hops fall back to direct peer", trusted: "172.17.0.1,10.0.0.0/8", remote: "172.17.0.1:8081",
			forwardedFor: "10.0.0.8, 10.0.0.9", want: "172.17.0.1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := newClientIPResolver(test.trusted)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/ss", nil)
			request.RemoteAddr = test.remote
			if test.forwardedFor != "" {
				request.Header.Set("X-Forwarded-For", test.forwardedFor)
			}
			if test.realIP != "" {
				request.Header.Set("X-Real-IP", test.realIP)
			}
			if got := resolver.resolve(request).ClientIP; got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMultipleRealIPHeadersFallBackToRemote(t *testing.T) {
	resolver, err := newClientIPResolver("172.17.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "172.17.0.1:8081"
	request.Header.Add("X-Real-IP", "203.0.113.10")
	request.Header.Add("X-Real-IP", "198.51.100.10")
	if got := resolver.resolve(request).ClientIP; got != "172.17.0.1" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestTrustedProxiesEnvironmentValidation(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "172.17.0.1,10.0.0.0/8,2001:db8::1")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := "172.17.0.1/32\n10.0.0.0/8\n2001:db8::1/128"
	if cfg.TrustedProxies != want {
		t.Fatalf("TRUSTED_PROXIES = %q, want %q", cfg.TrustedProxies, want)
	}
	if cfg.TrustAllByDefault {
		t.Fatal("explicit TRUSTED_PROXIES unexpectedly enabled trust-all default")
	}

	for _, invalid := range []string{"*", "172.17.0.999", "10.0.0.0/99"} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", invalid)
			_, err := LoadConfig()
			if err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") || !strings.Contains(err.Error(), invalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTrustedProxiesDefaultToAllDirectPeers(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TrustAllByDefault || cfg.TrustedProxies != "" {
		t.Fatalf("default proxy config = %+v", cfg)
	}
	resolver, err := newClientIPResolver(cfg.TrustedProxies, cfg.TrustAllByDefault)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ss", nil)
	request.RemoteAddr = "198.51.100.20:8080"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	if got, want := resolver.resolve(request).ClientIP, "203.0.113.10"; got != want {
		t.Fatalf("default client IP = %q, want %q", got, want)
	}
}

func TestProductionProxyAccessIsRecordedWithResolvedClientIP(t *testing.T) {
	application := newTestAppWithTrustedProxies(t, "172.17.0.1/32")
	id, err := application.store.CreateSubscription(context.Background(), "production", "/production", "ss://node", true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/production", nil)
	request.RemoteAddr = "172.17.0.1:8081"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	logs, err := application.store.AccessLogs(context.Background(), id, 1, 50, "", "")
	if err != nil || logs.Total != 1 {
		t.Fatalf("logs total = %d, error = %v", logs.Total, err)
	}
	if logs.Logs[0].ClientIP != "203.0.113.10" {
		t.Fatalf("recorded client IP = %q", logs.Logs[0].ClientIP)
	}
	subscription, err := application.store.SubscriptionByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if subscription.LastFetchedIP != "203.0.113.10" {
		t.Fatalf("last fetched IP = %q", subscription.LastFetchedIP)
	}
}

func TestLoginRateLimiterUsesResolvedClientIP(t *testing.T) {
	application := newTestAppWithTrustedProxies(t, "172.17.0.1/32")
	handler := application.Handler()
	login := func(clientIP string) int {
		values := url.Values{"password": {"wrong-password"}}
		request := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("X-Forwarded-For", clientIP)
		request.RemoteAddr = "172.17.0.1:8081"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	for attempt := 0; attempt < 5; attempt++ {
		if status := login("203.0.113.10"); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d", attempt+1, status)
		}
	}
	if status := login("203.0.113.10"); status != http.StatusTooManyRequests {
		t.Fatalf("limited client status = %d", status)
	}
	if status := login("198.51.100.10"); status != http.StatusUnauthorized {
		t.Fatalf("independent proxied client status = %d", status)
	}
}

func TestRequestAuditLogUsesResolvedClientIP(t *testing.T) {
	var output bytes.Buffer
	cfg := Config{
		Addr: ":0", DatabasePath: filepath.Join(t.TempDir(), "app.db"), CookieSecure: "false",
		TrustedProxies: "172.17.0.1/32", SessionHours: 12, DefaultRetain: 90,
	}
	application, err := New(cfg, slog.New(slog.NewTextHandler(&output, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	request := httptest.NewRequest(http.MethodGet, "/missing", nil)
	request.RemoteAddr = "172.17.0.1:8081"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	if !strings.Contains(output.String(), "client_ip=203.0.113.10") {
		t.Fatalf("request log did not use resolved client IP: %s", output.String())
	}
}

func TestSubscriptionPathValidation(t *testing.T) {
	valid := []string{"/ss", "/hk-01", "/node_test"}
	for _, path := range valid {
		if err := validateSubscription("name", path, "ss://node"); err != nil {
			t.Errorf("%s unexpectedly invalid: %v", path, err)
		}
	}
	invalid := []string{"ss", "/admin", "/a/b", "/空格", "/"}
	for _, path := range invalid {
		if err := validateSubscription("name", path, "ss://node"); err == nil {
			t.Errorf("%s unexpectedly valid", path)
		}
	}
}

func TestSubscriptionQRPayload(t *testing.T) {
	got := subscriptionQRPayload("http://66.42.61.17:8080/s-8xfbXW84a-e8")
	want := "sub://aHR0cDovLzY2LjQyLjYxLjE3OjgwODAvcy04eGZiWFc4NGEtZTg"
	if got != want {
		t.Fatalf("QR payload = %q, want %q", got, want)
	}
}

func TestFileSubscriptionsDeduplicateAndKeepIndependentStatistics(t *testing.T) {
	application := newTestApp(t)
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	client, csrf := authenticatedClient(t, server.URL)
	fileContent := []byte("proxies:\n  - name: shared\n")

	for _, item := range []struct{ name, path string }{{"文件一", "/file-a"}, {"文件二", "/file-b"}} {
		response := postMultipart(t, client, server.URL+"/admin/subscriptions", map[string]string{
			"csrf_token": csrf, "type": SubscriptionTypeFile, "name": item.name, "path": item.path, "enabled": "1",
		}, "file", "配置.yaml", fileContent)
		assertStatus(t, response, http.StatusSeeOther)
		response.Body.Close()
	}

	files, err := application.store.ListFiles(context.Background())
	if err != nil || len(files) != 1 {
		t.Fatalf("deduplicated files = %d, error = %v", len(files), err)
	}
	if files[0].AssociationCount != 2 {
		t.Fatalf("association count = %d", files[0].AssociationCount)
	}
	if files[0].MD5 == "" || files[0].SHA256 == "" {
		t.Fatalf("missing digests: %+v", files[0])
	}
	response := get(t, client, server.URL+"/admin/files")
	assertStatus(t, response, http.StatusOK)
	pageBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(pageBody), "创建关联订阅") || !strings.Contains(string(pageBody), files[0].MD5) {
		t.Fatalf("file manager page is incomplete: %s", pageBody)
	}
	response = get(t, client, fmt.Sprintf("%s/admin/files/%d", server.URL, files[0].ID))
	assertStatus(t, response, http.StatusOK)
	detailBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(detailBody), "/file-a") || !strings.Contains(string(detailBody), "/file-b") {
		t.Fatalf("file detail associations are incomplete: %s", detailBody)
	}

	for _, path := range []string{"/file-a", "/file-b"} {
		response = get(t, client, server.URL+path)
		assertStatus(t, response, http.StatusOK)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if !bytes.Equal(body, fileContent) {
			t.Fatalf("%s body = %q", path, body)
		}
		if disposition := response.Header.Get("Content-Disposition"); !strings.Contains(disposition, "attachment") {
			t.Fatalf("%s content disposition = %q", path, disposition)
		}
	}

	subscriptions, err := application.store.ListSubscriptionsByType(context.Background(), SubscriptionTypeFile)
	if err != nil || len(subscriptions) != 2 {
		t.Fatalf("file subscriptions = %d, error = %v", len(subscriptions), err)
	}
	for _, sub := range subscriptions {
		if sub.FetchCount != 1 || sub.FileID != files[0].ID {
			t.Fatalf("unexpected subscription statistics: %+v", sub)
		}
	}
	file, err := application.store.FileByID(context.Background(), files[0].ID)
	if err != nil || file.DownloadCount != 2 {
		t.Fatalf("file download count = %d, error = %v", file.DownloadCount, err)
	}
	response = get(t, client, fmt.Sprintf("%s/admin/files/%d/download", server.URL, file.ID))
	assertStatus(t, response, http.StatusOK)
	response.Body.Close()
	headRequest, _ := http.NewRequest(http.MethodHead, server.URL+"/file-a", nil)
	response, err = client.Do(headRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, response, http.StatusOK)
	response.Body.Close()
	fileAfterNonCountedRequests, _ := application.store.FileByID(context.Background(), file.ID)
	if fileAfterNonCountedRequests.DownloadCount != 2 {
		t.Fatalf("admin download or HEAD changed count to %d", fileAfterNonCountedRequests.DownloadCount)
	}
	associations, err := application.store.FileAssociations(context.Background(), file.ID)
	if err != nil || len(associations) != 2 {
		t.Fatalf("file associations = %d, error = %v", len(associations), err)
	}
	for _, association := range associations {
		if association.DownloadCount != 1 {
			t.Fatalf("association download count = %d", association.DownloadCount)
		}
	}

	response = get(t, client, server.URL+"/admin/subscriptions/"+strconv.FormatInt(subscriptions[0].ID, 10)+"/qrcode")
	assertStatus(t, response, http.StatusNotFound)
	response.Body.Close()
}

func TestCreateFileSubscriptionFromFileManagerAndDetach(t *testing.T) {
	application := newTestApp(t)
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	client, csrf := authenticatedClient(t, server.URL)

	response := postMultipart(t, client, server.URL+"/admin/subscriptions", map[string]string{
		"csrf_token": csrf, "type": SubscriptionTypeFile, "name": "源订阅", "path": "/source", "enabled": "1",
	}, "file", "source.txt", []byte("shared-file"))
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	files, _ := application.store.ListFiles(context.Background())
	if len(files) != 1 {
		t.Fatalf("files = %d", len(files))
	}

	response = postForm(t, client, fmt.Sprintf("%s/admin/files/%d/subscriptions", server.URL, files[0].ID), url.Values{
		"csrf_token": {csrf}, "type": {SubscriptionTypeFile}, "name": {"复用订阅"}, "path": {"/reused"}, "enabled": {"1"},
	})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	files, _ = application.store.ListFiles(context.Background())
	if files[0].AssociationCount != 2 {
		t.Fatalf("association count after reuse = %d", files[0].AssociationCount)
	}

	subs, _ := application.store.ListSubscriptionsByType(context.Background(), SubscriptionTypeFile)
	var reused Subscription
	for _, sub := range subs {
		if sub.Path == "/reused" {
			reused = sub
		}
	}
	response = postForm(t, client, fmt.Sprintf("%s/admin/subscriptions/%d/file/delete", server.URL, reused.ID), url.Values{"csrf_token": {csrf}})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	reused, err := application.store.SubscriptionByID(context.Background(), reused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reused.FileID != 0 || reused.Enabled {
		t.Fatalf("detached subscription = %+v", reused)
	}
	files, _ = application.store.ListFiles(context.Background())
	if len(files) != 1 || files[0].AssociationCount != 1 {
		t.Fatalf("file was not retained after detach: %+v", files)
	}
}

func TestReplaceFilePreservesSubscriptionCountAndSeparatesFileCount(t *testing.T) {
	application := newTestApp(t)
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	client, csrf := authenticatedClient(t, server.URL)

	response := postMultipart(t, client, server.URL+"/admin/subscriptions", map[string]string{
		"csrf_token": csrf, "type": SubscriptionTypeFile, "name": "替换测试", "path": "/replace", "enabled": "1",
	}, "file", "old.txt", []byte("old-content"))
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	response = get(t, client, server.URL+"/replace")
	response.Body.Close()
	subs, _ := application.store.ListSubscriptionsByType(context.Background(), SubscriptionTypeFile)
	if len(subs) != 1 {
		t.Fatalf("subscriptions = %d", len(subs))
	}
	oldFileID := subs[0].FileID

	response = postMultipart(t, client, fmt.Sprintf("%s/admin/subscriptions/%d/file", server.URL, subs[0].ID), map[string]string{
		"csrf_token": csrf,
	}, "file", "new.txt", []byte("new-content"))
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	response = get(t, client, server.URL+"/replace")
	assertStatus(t, response, http.StatusOK)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "new-content" {
		t.Fatalf("replacement response = %q", body)
	}
	sub, _ := application.store.SubscriptionByID(context.Background(), subs[0].ID)
	if sub.FetchCount != 2 || sub.FileID == oldFileID {
		t.Fatalf("subscription after replacement = %+v", sub)
	}
	oldFile, _ := application.store.FileByID(context.Background(), oldFileID)
	newFile, _ := application.store.FileByID(context.Background(), sub.FileID)
	if oldFile.DownloadCount != 1 || oldFile.AssociationCount != 0 || newFile.DownloadCount != 1 || newFile.AssociationCount != 1 {
		t.Fatalf("file counts after replacement: old=%+v new=%+v", oldFile, newFile)
	}

	response = postForm(t, client, fmt.Sprintf("%s/admin/files/%d/delete", server.URL, newFile.ID), url.Values{"csrf_token": {csrf}})
	assertStatus(t, response, http.StatusConflict)
	response.Body.Close()
	response = postForm(t, client, fmt.Sprintf("%s/admin/files/%d/delete", server.URL, oldFile.ID), url.Values{"csrf_token": {csrf}})
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	if _, err := application.store.FileByID(context.Background(), oldFile.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted file lookup error = %v", err)
	}
}

func TestLegacySubscriptionsMigrateToTextType(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE subscriptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', path TEXT NOT NULL UNIQUE,
		content TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, fetch_count INTEGER NOT NULL DEFAULT 0,
		last_fetched_at TEXT, last_fetched_ip TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	nowValue := dbTime(time.Now())
	if _, err := db.Exec(`INSERT INTO subscriptions(name, path, content, created_at, updated_at) VALUES ('legacy', '/legacy', 'ss://legacy', ?, ?)`, nowValue, nowValue); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(databasePath, []byte("hash"), 90)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sub, err := store.SubscriptionByPath(context.Background(), "/legacy")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Type != SubscriptionTypeText || sub.Content != "ss://legacy" {
		t.Fatalf("migrated subscription = %+v", sub)
	}
}

func authenticatedClient(t *testing.T, serverURL string) (*http.Client, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response := postForm(t, client, serverURL+"/admin/login", url.Values{"password": {"password"}})
	response.Body.Close()
	response = get(t, client, serverURL+"/admin/password")
	csrf := extractCSRF(t, response)
	response.Body.Close()
	response = postForm(t, client, serverURL+"/admin/password", url.Values{
		"csrf_token": {csrf}, "new_password": {"test-pass"}, "confirm_password": {"test-pass"},
	})
	response.Body.Close()
	response = get(t, client, serverURL+"/admin/")
	csrf = extractCSRF(t, response)
	response.Body.Close()
	return client, csrf
}

func postMultipart(t *testing.T, client *http.Client, endpoint string, fields map[string]string, fileField, filename string, content []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile(fileField, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, endpoint, &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func postForm(t *testing.T, client *http.Client, endpoint string, values url.Values) *http.Response {
	t.Helper()
	response, err := client.PostForm(endpoint, values)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func get(t *testing.T, client *http.Client, endpoint string) *http.Response {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func extractCSRF(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(string(body))
	if len(match) != 2 {
		t.Fatalf("csrf token not found in %s", strings.TrimSpace(string(body)))
	}
	return match[1]
}

func assertStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, want, body)
	}
}
