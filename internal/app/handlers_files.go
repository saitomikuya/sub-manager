package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func (a *App) createUploadedFileSubscription(w http.ResponseWriter, r *http.Request, auth authContext, sub Subscription) {
	sub.Type = SubscriptionTypeFile
	if err := validateSubscriptionMetadata(sub.Name, sub.Path); err != nil {
		a.renderNewFileSubscriptionError(w, auth, sub, err.Error())
		return
	}
	upload, header, err := r.FormFile("file")
	if err != nil {
		a.renderNewFileSubscriptionError(w, auth, sub, a.fileSelectionError(err))
		return
	}
	defer upload.Close()
	file, err := a.saveUploadedFile(r.Context(), upload, header)
	if err != nil {
		a.logger.Error("save uploaded file", "error", err)
		a.renderNewFileSubscriptionError(w, auth, sub, uploadErrorMessage(err, a.cfg.MaxUploadBytes))
		return
	}
	if sub.Name == "" {
		sub.Name = strings.TrimPrefix(sub.Path, "/")
	}
	if _, err := a.store.CreateFileSubscription(r.Context(), sub.Name, sub.Path, file.ID, headerFilename(header), sub.Enabled); err != nil {
		message := "无法创建文件订阅，文件已保存在文件管理中"
		if isUniquePathError(err) {
			message = "该订阅路径已经存在；上传文件已保存在文件管理中"
		}
		a.renderNewFileSubscriptionError(w, auth, sub, message)
		return
	}
	http.Redirect(w, r, subscriptionListURL(SubscriptionTypeFile, "created"), http.StatusSeeOther)
}

func (a *App) renderNewFileSubscriptionError(w http.ResponseWriter, auth authContext, sub Subscription, message string) {
	w.WriteHeader(http.StatusBadRequest)
	a.render(w, "subscription_form.html", viewData{
		Title: "新增文件订阅", CSRF: auth.Session.CSRFToken, IsNew: true,
		SubscriptionType: SubscriptionTypeFile, Subscription: sub, Error: message,
		MaxUploadMiB: a.cfg.MaxUploadBytes / (1024 * 1024),
	})
}

func (a *App) saveUploadedFile(ctx context.Context, upload multipart.File, header *multipart.FileHeader) (StoredFile, error) {
	staged, err := a.fileStorage.Stage(upload, headerFilename(header), a.cfg.MaxUploadBytes)
	if err != nil {
		return StoredFile{}, err
	}
	a.fileMu.Lock()
	defer a.fileMu.Unlock()

	existing, err := a.store.FileByDigests(ctx, staged.md5, staged.sha256)
	if err == nil {
		if existing.MD5 != staged.md5 || existing.Size != staged.size {
			a.fileStorage.Discard(staged)
			return StoredFile{}, errors.New("stored file digest metadata mismatch")
		}
		if err := a.fileStorage.Commit(staged); err != nil {
			a.fileStorage.Discard(staged)
			return StoredFile{}, err
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		a.fileStorage.Discard(staged)
		return StoredFile{}, err
	}
	if bySHA, shaErr := a.store.FileBySHA256(ctx, staged.sha256); shaErr == nil {
		a.fileStorage.Discard(staged)
		return StoredFile{}, fmt.Errorf("stored file digest metadata mismatch for file %d", bySHA.ID)
	} else if !errors.Is(shaErr, sql.ErrNoRows) {
		a.fileStorage.Discard(staged)
		return StoredFile{}, shaErr
	}
	if err := a.fileStorage.Commit(staged); err != nil {
		a.fileStorage.Discard(staged)
		return StoredFile{}, err
	}
	created, err := a.store.CreateFile(ctx, staged.md5, staged.sha256, staged.size, staged.contentType, staged.storageKey, staged.originalName)
	if err != nil {
		if existing, lookupErr := a.store.FileByDigests(ctx, staged.md5, staged.sha256); lookupErr == nil {
			return existing, nil
		}
		// Keep the content-addressed blob as an orphan on a database failure.
		// This avoids deleting a blob another process may already reference, and
		// a later upload of the same content will safely reuse it.
		return StoredFile{}, err
	}
	return created, nil
}

func headerFilename(header *multipart.FileHeader) string {
	if header == nil {
		return "download"
	}
	return sanitizeFilename(header.Filename)
}

func (a *App) replaceSubscriptionFile(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	if sub.Type != SubscriptionTypeFile {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	upload, header, err := r.FormFile("file")
	if err != nil {
		a.renderError(w, http.StatusBadRequest, a.fileSelectionError(err))
		return
	}
	defer upload.Close()
	file, err := a.saveUploadedFile(r.Context(), upload, header)
	if err != nil {
		a.logger.Error("replace subscription file", "subscription_id", sub.ID, "error", err)
		a.renderError(w, http.StatusBadRequest, uploadErrorMessage(err, a.cfg.MaxUploadBytes))
		return
	}
	if err := a.store.ReplaceSubscriptionFile(r.Context(), sub.ID, file.ID, headerFilename(header)); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法替换订阅文件")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/subscriptions/%d?message=file-replaced", sub.ID), http.StatusSeeOther)
}

func (a *App) fileSelectionError(err error) string {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) || strings.Contains(strings.ToLower(err.Error()), "request body too large") {
		return fmt.Sprintf("文件不能超过 %d MiB", a.cfg.MaxUploadBytes/(1024*1024))
	}
	return "请选择需要上传的文件"
}

func (a *App) detachSubscriptionFile(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	if sub.Type != SubscriptionTypeFile {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if err := a.store.DetachSubscriptionFile(r.Context(), sub.ID); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法删除订阅文件")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/subscriptions/%d?message=file-detached", sub.ID), http.StatusSeeOther)
}

func (a *App) downloadSubscriptionFile(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	if sub.Type != SubscriptionTypeFile || sub.FileID == 0 {
		a.renderError(w, http.StatusNotFound, "该订阅没有关联文件")
		return
	}
	file, err := a.store.FileByID(r.Context(), sub.FileID)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "文件不存在")
		return
	}
	a.serveStoredFile(w, r, file, sub.DownloadName, r.URL.Query().Get("view") == "1")
}

func (a *App) filesPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	files, err := a.store.ListFiles(r.Context())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取文件列表")
		return
	}
	a.render(w, "files.html", viewData{
		Title: "文件管理", CSRF: auth.Session.CSRFToken, Files: files,
		Message: messageFromQuery(r.URL.Query().Get("message")),
	})
}

func (a *App) fileDetailsPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	file, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	associations, err := a.store.FileAssociations(r.Context(), file.ID)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取文件关联订阅")
		return
	}
	a.render(w, "file_details.html", viewData{
		Title: file.OriginalName, CSRF: auth.Session.CSRFToken, File: file,
		FileAssociations: associations, BaseURL: a.baseURL(r), Message: messageFromQuery(r.URL.Query().Get("message")),
		MaxUploadMiB: a.cfg.MaxUploadBytes / (1024 * 1024),
	})
}

func (a *App) replaceStoredFile(w http.ResponseWriter, r *http.Request) {
	oldFile, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	if oldFile.AssociationCount == 0 {
		a.renderError(w, http.StatusConflict, "该文件没有关联订阅，请先创建关联订阅")
		return
	}
	upload, header, err := r.FormFile("file")
	if err != nil {
		a.renderError(w, http.StatusBadRequest, a.fileSelectionError(err))
		return
	}
	defer upload.Close()
	file, err := a.saveUploadedFile(r.Context(), upload, header)
	if err != nil {
		a.logger.Error("replace stored file", "file_id", oldFile.ID, "error", err)
		a.renderError(w, http.StatusBadRequest, uploadErrorMessage(err, a.cfg.MaxUploadBytes))
		return
	}
	if _, err := a.store.ReplaceFileAssociations(r.Context(), oldFile.ID, file.ID, headerFilename(header)); err != nil {
		if errors.Is(err, errNoFileAssociations) || errors.Is(err, sql.ErrNoRows) {
			a.renderError(w, http.StatusConflict, "文件关联已变更，请返回文件管理刷新后重试；上传文件已保存在文件管理中")
		} else {
			a.logger.Error("replace file associations", "file_id", oldFile.ID, "error", err)
			a.renderError(w, http.StatusInternalServerError, "无法更新关联订阅；上传文件已保存在文件管理中")
		}
		return
	}
	message := "file-associations-replaced"
	if oldFile.ID == file.ID {
		message = "file-unchanged"
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/files/%d?message=%s", file.ID, message), http.StatusSeeOther)
}

func (a *App) downloadStoredFile(w http.ResponseWriter, r *http.Request) {
	file, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	a.serveStoredFile(w, r, file, file.OriginalName, r.URL.Query().Get("view") == "1")
}

func (a *App) newFileAssociationPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	file, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	path, err := generateSubscriptionPath()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法生成订阅路径")
		return
	}
	a.render(w, "subscription_form.html", viewData{
		Title: "创建关联订阅", CSRF: auth.Session.CSRFToken, IsNew: true,
		SubscriptionType: SubscriptionTypeFile, Subscription: Subscription{Type: SubscriptionTypeFile, Path: path, Enabled: true},
		File: file, MaxUploadMiB: a.cfg.MaxUploadBytes / (1024 * 1024),
	})
}

func (a *App) createFileAssociation(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	file, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	sub := subscriptionFromForm(r)
	sub.Type = SubscriptionTypeFile
	if err := validateSubscriptionMetadata(sub.Name, sub.Path); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{
			Title: "创建关联订阅", CSRF: auth.Session.CSRFToken, IsNew: true,
			SubscriptionType: SubscriptionTypeFile, Subscription: sub, File: file, Error: err.Error(),
		})
		return
	}
	if sub.Name == "" {
		sub.Name = strings.TrimPrefix(sub.Path, "/")
	}
	if _, err := a.store.CreateFileSubscription(r.Context(), sub.Name, sub.Path, file.ID, file.OriginalName, sub.Enabled); err != nil {
		message := "无法创建关联订阅"
		if isUniquePathError(err) {
			message = "该订阅路径已经存在"
		}
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{
			Title: "创建关联订阅", CSRF: auth.Session.CSRFToken, IsNew: true,
			SubscriptionType: SubscriptionTypeFile, Subscription: sub, File: file, Error: message,
		})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/files/%d?message=association-created", file.ID), http.StatusSeeOther)
}

func (a *App) deleteStoredFile(w http.ResponseWriter, r *http.Request) {
	file, ok := a.loadStoredFile(w, r)
	if !ok {
		return
	}
	a.fileMu.Lock()
	defer a.fileMu.Unlock()
	file, err := a.store.FileByID(r.Context(), file.ID)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "文件不存在")
		return
	}
	if file.AssociationCount > 0 {
		a.renderError(w, http.StatusConflict, "该文件仍有关联订阅，不能删除")
		return
	}
	if err := a.store.DeleteFile(r.Context(), file.ID); err != nil {
		a.renderError(w, http.StatusConflict, "文件已被订阅关联，不能删除")
		return
	}
	if err := a.fileStorage.Remove(file.StorageKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The database record is already gone, so a failed removal is only an
		// unreferenced blob. A later upload of the same content can safely reuse it.
		a.logger.Error("remove unreferenced file", "file_id", file.ID, "error", err)
	}
	http.Redirect(w, r, "/admin/files?message=file-deleted", http.StatusSeeOther)
}

func (a *App) publicFileSubscription(w http.ResponseWriter, r *http.Request, sub Subscription, ip, userAgent string) {
	if sub.FileID == 0 {
		http.NotFound(w, r)
		return
	}
	file, err := a.store.FileByID(r.Context(), sub.FileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			a.renderError(w, http.StatusInternalServerError, "无法读取订阅文件")
		}
		return
	}
	handle, err := a.fileStorage.Open(file.StorageKey)
	if err != nil {
		a.logger.Error("open subscription file", "subscription_id", sub.ID, "file_id", file.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "订阅文件暂时不可用")
		return
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "订阅文件暂时不可用")
		return
	}
	if r.Method == http.MethodGet {
		if err := a.store.RecordAccess(r.Context(), sub, file.ID, ip, detectClient(userAgent), userAgent, r.Method, http.StatusOK); err != nil {
			a.logger.Error("record file subscription access", "subscription_id", sub.ID, "file_id", file.ID, "error", err)
			a.renderError(w, http.StatusInternalServerError, "暂时无法下载订阅文件")
			return
		}
	}
	setFileResponseHeaders(w, file, sub.DownloadName, false, info)
	if r.Method == http.MethodHead {
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, handle); err != nil {
		a.logger.Warn("stream subscription file", "subscription_id", sub.ID, "file_id", file.ID, "error", err)
	}
}

func (a *App) serveStoredFile(w http.ResponseWriter, r *http.Request, file StoredFile, filename string, inline bool) {
	handle, err := a.fileStorage.Open(file.StorageKey)
	if err != nil {
		a.logger.Error("open stored file", "file_id", file.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "文件暂时不可用")
		return
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "文件暂时不可用")
		return
	}
	setFileResponseHeaders(w, file, filename, inline, info)
	if r.Method == http.MethodHead {
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, handle); err != nil {
		a.logger.Warn("stream stored file", "file_id", file.ID, "error", err)
	}
}

func setFileResponseHeaders(w http.ResponseWriter, file StoredFile, filename string, inline bool, info os.FileInfo) {
	if filename == "" {
		filename = file.OriginalName
	}
	disposition := "attachment"
	if inline {
		disposition = "inline"
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	}
	w.Header().Set("Content-Type", file.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": sanitizeFilename(filename)}))
	w.Header().Set("ETag", `"md5-`+file.MD5+`"`)
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (a *App) loadStoredFile(w http.ResponseWriter, r *http.Request) (StoredFile, bool) {
	id, err := parseID(r)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "文件不存在")
		return StoredFile{}, false
	}
	file, err := a.store.FileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.renderError(w, http.StatusNotFound, "文件不存在")
		} else {
			a.renderError(w, http.StatusInternalServerError, "无法读取文件")
		}
		return StoredFile{}, false
	}
	return file, true
}
