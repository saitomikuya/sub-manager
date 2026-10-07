package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func testStoredFile(t *testing.T, application *App, filename, content string) StoredFile {
	t.Helper()
	staged, err := application.fileStorage.Stage(strings.NewReader(content), filename, application.cfg.MaxUploadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.fileStorage.Commit(staged); err != nil {
		t.Fatal(err)
	}
	file, err := application.store.CreateFile(context.Background(), staged.md5, staged.sha256, staged.size, staged.contentType, staged.storageKey, staged.originalName)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestFileManagerReplacementUpdatesAllAssociationsAndResetsCurrentCounts(t *testing.T) {
	application := newTestApp(t)
	ctx := context.Background()
	oldFile := testStoredFile(t, application, "old.yaml", "old-content")
	newFile := testStoredFile(t, application, "existing.yaml", "new-content")
	var originalSubs []Subscription
	for _, item := range []struct {
		path    string
		fileID  int64
		enabled bool
	}{{"/team-a", oldFile.ID, true}, {"/team-b", oldFile.ID, true}, {"/disabled", oldFile.ID, false}, {"/existing", newFile.ID, true}} {
		id, err := application.store.CreateFileSubscription(ctx, item.path, item.path, item.fileID, "original.yaml", item.enabled)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := application.store.SubscriptionByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		originalSubs = append(originalSubs, sub)
	}
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	client, csrf := authenticatedClient(t, server.URL)
	for _, path := range []string{"/team-a", "/team-b", "/existing"} {
		response := get(t, client, server.URL+path)
		assertStatus(t, response, http.StatusOK)
		response.Body.Close()
	}

	response := get(t, client, fmt.Sprintf("%s/admin/files/%d", server.URL, oldFile.ID))
	page, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !bytes.Contains(page, []byte(fmt.Sprintf(`action="/admin/files/%d/replace"`, oldFile.ID))) || !bytes.Contains(page, []byte("更新替换文件")) {
		t.Fatalf("missing replacement form: %s", page)
	}
	response = postMultipart(t, client, fmt.Sprintf("%s/admin/files/%d/replace", server.URL, oldFile.ID), map[string]string{"csrf_token": csrf}, "file", "updated.yaml", []byte("new-content"))
	assertStatus(t, response, http.StatusSeeOther)
	if got, want := response.Header.Get("Location"), fmt.Sprintf("/admin/files/%d?message=file-associations-replaced", newFile.ID); got != want {
		t.Fatalf("replacement redirect = %q, want %q", got, want)
	}
	response.Body.Close()
	for i, original := range originalSubs {
		sub, err := application.store.SubscriptionByID(ctx, original.ID)
		if err != nil {
			t.Fatal(err)
		}
		if sub.Name != original.Name || sub.Path != original.Path || sub.Enabled != original.Enabled || sub.FileID != newFile.ID {
			t.Fatalf("association metadata changed unexpectedly: %+v", sub)
		}
		if i < 3 {
			if sub.CurrentFetchCount != 0 || sub.DownloadName != "updated.yaml" || sub.FileRevision != 1 {
				t.Fatalf("association not reset: %+v", sub)
			}
		} else if sub.CurrentFetchCount != 1 || sub.DownloadName != "original.yaml" || sub.FileRevision != 0 {
			t.Fatalf("pre-existing target association changed: %+v", sub)
		}
		wantTotal := int64(1)
		if !original.Enabled {
			wantTotal = 0
		}
		if sub.FetchCount != wantTotal {
			t.Fatalf("lifetime count changed: %+v", sub)
		}
		logs, err := application.store.AccessLogs(ctx, sub.ID, 1, 50, "", "")
		if err != nil || int64(logs.Total) != wantTotal {
			t.Fatalf("historical logs changed: %+v, %v", logs, err)
		}
	}
	files, err := application.store.ListFiles(ctx)
	if err != nil || len(files) != 2 {
		t.Fatalf("replacement should reuse target file: %+v, %v", files, err)
	}
	oldFile, _ = application.store.FileByID(ctx, oldFile.ID)
	newFile, _ = application.store.FileByID(ctx, newFile.ID)
	if oldFile.AssociationCount != 0 || oldFile.DownloadCount != 2 || newFile.AssociationCount != 4 || newFile.DownloadCount != 1 {
		t.Fatalf("file history changed: old=%+v new=%+v", oldFile, newFile)
	}
	response = get(t, client, server.URL+"/admin/?type=file")
	page, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if !bytes.Contains(page, []byte("更新后拉取")) || bytes.Contains(page, []byte("<th>累计拉取</th>")) || bytes.Count(page, []byte("<strong>0</strong> 次")) != 3 {
		t.Fatalf("file list should display current counts: %s", page)
	}
	for _, path := range []string{"/team-a", "/team-b"} {
		response = get(t, client, server.URL+path)
		assertStatus(t, response, http.StatusOK)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != "new-content" || !strings.Contains(response.Header.Get("Content-Disposition"), "updated.yaml") || response.Header.Get("ETag") != `"md5-`+newFile.MD5+`"` {
			t.Fatalf("%s did not serve replacement: %q, %v", path, body, response.Header)
		}
	}
	response = get(t, client, server.URL+"/disabled")
	assertStatus(t, response, http.StatusNotFound)
	response.Body.Close()
	for _, original := range originalSubs[:2] {
		sub, _ := application.store.SubscriptionByID(ctx, original.ID)
		if sub.FetchCount != 2 || sub.CurrentFetchCount != 1 {
			t.Fatalf("post-update statistics = %+v", sub)
		}
	}
	// Re-uploading the same bytes must not reset any target associations.
	response = postMultipart(t, client, fmt.Sprintf("%s/admin/files/%d/replace", server.URL, newFile.ID), map[string]string{"csrf_token": csrf}, "file", "same.yaml", []byte("new-content"))
	assertStatus(t, response, http.StatusSeeOther)
	if !strings.Contains(response.Header.Get("Location"), "message=file-unchanged") {
		t.Fatalf("same-content redirect = %s", response.Header.Get("Location"))
	}
	response.Body.Close()
	for _, original := range originalSubs[:2] {
		sub, _ := application.store.SubscriptionByID(ctx, original.ID)
		if sub.CurrentFetchCount != 1 || sub.FileRevision != 1 || sub.DownloadName != "updated.yaml" {
			t.Fatalf("same-content upload changed association: %+v", sub)
		}
	}
	// Reusing historical content starts a new count, even when pair totals exist.
	response = postMultipart(t, client, fmt.Sprintf("%s/admin/files/%d/replace", server.URL, newFile.ID), map[string]string{"csrf_token": csrf}, "file", "restored.yaml", []byte("old-content"))
	assertStatus(t, response, http.StatusSeeOther)
	response.Body.Close()
	associations, err := application.store.FileAssociations(ctx, oldFile.ID)
	if err != nil || len(associations) != 4 {
		t.Fatalf("restored associations = %+v, %v", associations, err)
	}
	for _, association := range associations {
		if association.Subscription.CurrentFetchCount != 0 {
			t.Fatalf("historical file count was revived: %+v", association)
		}
	}
	response = get(t, client, server.URL+"/team-a")
	response.Body.Close()
	sub, _ := application.store.SubscriptionByID(ctx, originalSubs[0].ID)
	if sub.CurrentFetchCount != 1 || sub.FetchCount != 3 {
		t.Fatalf("restored file counts = %+v", sub)
	}
	if err := application.store.ClearAccessLogs(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	sub, _ = application.store.SubscriptionByID(ctx, sub.ID)
	if sub.CurrentFetchCount != 1 || sub.FetchCount != 3 {
		t.Fatalf("clearing logs changed persistent counters: %+v", sub)
	}
}

func TestFileReplacementFailuresLeaveAssociationsUnchanged(t *testing.T) {
	application := newTestApp(t)
	application.cfg.MaxUploadBytes = 16
	ctx := context.Background()
	oldFile := testStoredFile(t, application, "old.txt", "old-content")
	orphan := testStoredFile(t, application, "orphan.txt", "no-associations")
	id, err := application.store.CreateFileSubscription(ctx, "test", "/test", oldFile.ID, "old.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(application.Handler())
	t.Cleanup(server.Close)
	client, csrf := authenticatedClient(t, server.URL)
	endpoint := fmt.Sprintf("%s/admin/files/%d/replace", server.URL, oldFile.ID)
	for _, item := range []struct {
		name, csrf string
		content    []byte
		status     int
	}{{"csrf", "invalid", []byte("new-content"), http.StatusForbidden}, {"empty", csrf, nil, http.StatusBadRequest}, {"too large", csrf, bytes.Repeat([]byte("x"), 17), http.StatusBadRequest}} {
		t.Run(item.name, func(t *testing.T) {
			response := postMultipart(t, client, endpoint, map[string]string{"csrf_token": item.csrf}, "file", "new.txt", item.content)
			assertStatus(t, response, item.status)
			response.Body.Close()
		})
	}
	response := postForm(t, client, endpoint, url.Values{"csrf_token": {csrf}})
	assertStatus(t, response, http.StatusBadRequest)
	response.Body.Close()
	response = postMultipart(t, client, server.URL+"/admin/files/99999/replace", map[string]string{"csrf_token": csrf}, "file", "new.txt", []byte("new-content"))
	assertStatus(t, response, http.StatusNotFound)
	response.Body.Close()
	response = postMultipart(t, client, fmt.Sprintf("%s/admin/files/%d/replace", server.URL, orphan.ID), map[string]string{"csrf_token": csrf}, "file", "new.txt", []byte("new-content"))
	assertStatus(t, response, http.StatusConflict)
	response.Body.Close()
	response = postMultipart(t, &http.Client{CheckRedirect: client.CheckRedirect}, endpoint, nil, "file", "new.txt", []byte("new-content"))
	assertStatus(t, response, http.StatusSeeOther)
	if response.Header.Get("Location") != "/admin/login" {
		t.Fatalf("unauthenticated replacement redirect = %s", response.Header.Get("Location"))
	}
	response.Body.Close()
	sub, _ := application.store.SubscriptionByID(ctx, id)
	files, _ := application.store.ListFiles(ctx)
	if sub.FileID != oldFile.ID || sub.FileRevision != 0 || sub.CurrentFetchCount != 0 || len(files) != 2 {
		t.Fatalf("failed upload changed data: sub=%+v files=%+v", sub, files)
	}

	newFile := testStoredFile(t, application, "new.txt", "new-content")
	secondID, err := application.store.CreateFileSubscription(ctx, "second", "/second", oldFile.ID, "old.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	// Abort one row of the SQL statement to verify the entire replacement rolls back.
	if _, err := application.store.db.Exec(`CREATE TRIGGER fail_replace BEFORE UPDATE OF file_id ON subscriptions
		WHEN OLD.path = '/second' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := application.store.ReplaceFileAssociations(ctx, oldFile.ID, newFile.ID, "new.txt"); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	for _, subID := range []int64{id, secondID} {
		sub, _ := application.store.SubscriptionByID(ctx, subID)
		if sub.FileID != oldFile.ID || sub.FileRevision != 0 || sub.DownloadName != "old.txt" {
			t.Fatalf("replacement partially committed: %+v", sub)
		}
	}
	if _, err := application.store.ReplaceFileAssociations(ctx, oldFile.ID, 99999, "missing.txt"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing replacement error = %v", err)
	}
	if _, err := application.store.ReplaceFileAssociations(ctx, orphan.ID, newFile.ID, "new.txt"); !errors.Is(err, errNoFileAssociations) {
		t.Fatalf("missing associations error = %v", err)
	}
}

func TestSingleReplacementAndStaleFetchesUseCurrentFileRevision(t *testing.T) {
	application := newTestApp(t)
	ctx := context.Background()
	oldFile := testStoredFile(t, application, "old.txt", "old-content")
	newFile := testStoredFile(t, application, "new.txt", "new-content")
	id, err := application.store.CreateFileSubscription(ctx, "test", "/test", oldFile.ID, "old.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot, _ := application.store.SubscriptionByID(ctx, id)
	record := func(sub Subscription) {
		t.Helper()
		if err := application.store.RecordAccess(ctx, sub, sub.FileID, "203.0.113.1", "test", "test", "GET", 200); err != nil {
			t.Fatal(err)
		}
	}
	record(oldSnapshot)
	if err := application.store.ReplaceSubscriptionFile(ctx, id, oldFile.ID, "renamed.txt"); err != nil {
		t.Fatal(err)
	}
	sub, _ := application.store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 1 || sub.FileRevision != 0 {
		t.Fatalf("same file reset statistics: %+v", sub)
	}
	if err := application.store.ReplaceSubscriptionFile(ctx, id, newFile.ID, "new.txt"); err != nil {
		t.Fatal(err)
	}
	record(oldSnapshot)
	sub, _ = application.store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 0 || sub.FetchCount != 2 {
		t.Fatalf("old-file fetch mixed into current count: %+v", sub)
	}
	record(sub)
	if err := application.store.ReplaceSubscriptionFile(ctx, id, oldFile.ID, "old.txt"); err != nil {
		t.Fatal(err)
	}
	record(oldSnapshot)
	sub, _ = application.store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 0 || sub.FetchCount != 4 || sub.FileRevision != 2 {
		t.Fatalf("old revision revived after reattaching historical content: %+v", sub)
	}
	record(sub)
	if err := application.store.DetachSubscriptionFile(ctx, id); err != nil {
		t.Fatal(err)
	}
	sub, _ = application.store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 0 || sub.FetchCount != 5 || sub.FileID != 0 || sub.Enabled {
		t.Fatalf("detached counts = %+v", sub)
	}
}

func TestCurrentFetchCountMigrationIsPersistent(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "app.db")
	store, err := OpenStore(databasePath, []byte("hash"), 90)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	oldFile, err := store.CreateFile(ctx, "old-md5", "old-sha", 1, "text/plain", "old-key", "old.txt")
	if err != nil {
		t.Fatal(err)
	}
	newFile, err := store.CreateFile(ctx, "new-md5", "new-sha", 1, "text/plain", "new-key", "new.txt")
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.CreateFileSubscription(ctx, "test", "/test", oldFile.ID, "old.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := store.SubscriptionByID(ctx, id)
	if err := store.RecordAccess(ctx, sub, oldFile.ID, "ip", "client", "ua", "GET", 200); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceSubscriptionFile(ctx, id, newFile.ID, "new.txt"); err != nil {
		t.Fatal(err)
	}
	sub, _ = store.SubscriptionByID(ctx, id)
	if err := store.RecordAccess(ctx, sub, newFile.ID, "ip", "client", "ua", "GET", 200); err != nil {
		t.Fatal(err)
	}
	// Removing the new column reproduces the previous release's persisted schema.
	if _, err := store.db.Exec(`ALTER TABLE subscriptions DROP COLUMN current_fetch_count`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(databasePath, []byte("hash"), 90)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ = store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 1 || sub.FetchCount != 2 {
		t.Fatalf("migration should seed current-file count, not lifetime total: %+v", sub)
	}
	if err := store.ReplaceSubscriptionFile(ctx, id, oldFile.ID, "old.txt"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(databasePath, []byte("hash"), 90)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ = store.SubscriptionByID(ctx, id)
	if sub.CurrentFetchCount != 0 || sub.FetchCount != 2 {
		t.Fatalf("restart revived historical counters: %+v", sub)
	}
}
