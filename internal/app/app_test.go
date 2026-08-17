package app

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	cfg := Config{
		Addr: ":0", DatabasePath: filepath.Join(t.TempDir(), "app.db"), CookieSecure: "false",
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

func TestClientIPOnlyTrustsConfiguredProxy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/ss", nil)
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.8")
	if got := clientIPForRequest(request, ""); got != "203.0.113.10" {
		t.Fatalf("untrusted proxy IP = %q", got)
	}

	request.RemoteAddr = "10.0.0.2:1234"
	request.Header.Set("X-Forwarded-For", "192.0.2.55, 10.0.0.1")
	if got := clientIPForRequest(request, "10.0.0.0/8"); got != "192.0.2.55" {
		t.Fatalf("trusted proxy client IP = %q", got)
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
