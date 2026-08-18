package app

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := a.store.Ping(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, err := a.store.Session(r.Context(), cookie.Value); err == nil {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
	}
	a.render(w, "login.html", viewData{Title: "管理员登录"})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.Settings(r.Context())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取系统设置")
		return
	}
	ip := a.clientIP(r)
	if !a.limiter.allowed(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		a.render(w, "login.html", viewData{Title: "管理员登录", Error: "登录失败次数过多，请 15 分钟后重试"})
		return
	}
	password := r.FormValue("password")
	if bcrypt.CompareHashAndPassword(settings.PasswordHash, []byte(password)) != nil {
		a.limiter.fail(ip)
		w.WriteHeader(http.StatusUnauthorized)
		a.render(w, "login.html", viewData{Title: "管理员登录", Error: "密码不正确"})
		return
	}
	a.limiter.success(ip)
	token, err := randomToken(32)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法创建登录会话")
		return
	}
	csrf, err := randomToken(24)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法创建登录会话")
		return
	}
	expires := now().Add(sessionDuration(a.cfg.SessionHours))
	if err := a.store.CreateSession(r.Context(), token, csrf, settings.SessionVersion, expires); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法创建登录会话")
		return
	}
	a.setSessionCookie(w, r, token, expires)
	if settings.MustChange {
		http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	if err := a.store.DeleteSession(r.Context(), auth.Token); err != nil {
		a.logger.Error("delete session", "error", err)
	}
	a.clearSessionCookie(w, r)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) passwordPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	a.render(w, "password.html", viewData{
		Title: "修改密码", CSRF: auth.Session.CSRFToken, MustChange: auth.Config.MustChange,
	})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	data := viewData{Title: "修改密码", CSRF: auth.Session.CSRFToken, MustChange: auth.Config.MustChange}
	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmation := r.FormValue("confirm_password")
	if !auth.Config.MustChange && bcrypt.CompareHashAndPassword(auth.Config.PasswordHash, []byte(current)) != nil {
		data.Error = "当前密码不正确"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "password.html", data)
		return
	}
	if utf8.RuneCountInString(newPassword) < 4 {
		data.Error = "新密码至少需要 4 位"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "password.html", data)
		return
	}
	if len(newPassword) > 72 {
		data.Error = "新密码不能超过 72 字节"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "password.html", data)
		return
	}
	if newPassword != confirmation {
		data.Error = "两次输入的新密码不一致"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "password.html", data)
		return
	}
	if bcrypt.CompareHashAndPassword(auth.Config.PasswordHash, []byte(newPassword)) == nil {
		data.Error = "新密码不能与当前密码相同"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "password.html", data)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法保存新密码")
		return
	}
	version, err := a.store.ChangePassword(r.Context(), hash)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法保存新密码")
		return
	}
	token, _ := randomToken(32)
	csrf, _ := randomToken(24)
	expires := now().Add(sessionDuration(a.cfg.SessionHours))
	if token == "" || csrf == "" || a.store.CreateSession(r.Context(), token, csrf, version, expires) != nil {
		a.clearSessionCookie(w, r)
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	a.setSessionCookie(w, r, token, expires)
	http.Redirect(w, r, "/admin/?message=password-updated", http.StatusSeeOther)
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	subscriptions, err := a.store.ListSubscriptions(r.Context())
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取订阅列表")
		return
	}
	message := messageFromQuery(r.URL.Query().Get("message"))
	if r.URL.Query().Get("message") == "password-updated" {
		message = "密码已修改，其他登录会话已失效"
	}
	a.render(w, "dashboard.html", viewData{
		Title: "订阅管理", CSRF: auth.Session.CSRFToken, Subscriptions: subscriptions,
		BaseURL: a.baseURL(r), Message: message,
	})
}

func (a *App) newSubscriptionPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	path, err := generateSubscriptionPath()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法生成订阅路径")
		return
	}
	a.render(w, "subscription_form.html", viewData{
		Title: "新增订阅", CSRF: auth.Session.CSRFToken, IsNew: true,
		Subscription: Subscription{Path: path, Enabled: true},
	})
}

func (a *App) createSubscription(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	sub := subscriptionFromForm(r)
	if err := validateSubscription(sub.Name, sub.Path, sub.Content); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{Title: "新增订阅", CSRF: auth.Session.CSRFToken, IsNew: true, Subscription: sub, Error: err.Error()})
		return
	}
	if sub.Name == "" {
		sub.Name = strings.TrimPrefix(sub.Path, "/")
	}
	_, err := a.store.CreateSubscription(r.Context(), sub.Name, sub.Path, normalizeContent(sub.Content), sub.Enabled)
	if err != nil {
		message := "无法创建订阅"
		if isUniquePathError(err) {
			message = "该订阅路径已经存在"
		}
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{Title: "新增订阅", CSRF: auth.Session.CSRFToken, IsNew: true, Subscription: sub, Error: message})
		return
	}
	http.Redirect(w, r, "/admin/?message=created", http.StatusSeeOther)
}

func (a *App) editSubscriptionPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	a.render(w, "subscription_form.html", viewData{Title: "编辑订阅", CSRF: auth.Session.CSRFToken, Subscription: sub})
}

func (a *App) updateSubscription(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	id, err := parseID(r)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	sub := subscriptionFromForm(r)
	sub.ID = id
	if err := validateSubscription(sub.Name, sub.Path, sub.Content); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{Title: "编辑订阅", CSRF: auth.Session.CSRFToken, Subscription: sub, Error: err.Error()})
		return
	}
	if sub.Name == "" {
		sub.Name = strings.TrimPrefix(sub.Path, "/")
	}
	err = a.store.UpdateSubscription(r.Context(), id, sub.Name, sub.Path, normalizeContent(sub.Content), sub.Enabled)
	if err != nil {
		message := "无法保存订阅"
		if isUniquePathError(err) {
			message = "该订阅路径已经存在"
		}
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "subscription_form.html", viewData{Title: "编辑订阅", CSRF: auth.Session.CSRFToken, Subscription: sub, Error: message})
		return
	}
	http.Redirect(w, r, "/admin/?message=updated", http.StatusSeeOther)
}

func (a *App) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil || a.store.DeleteSubscription(r.Context(), id) != nil {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	http.Redirect(w, r, "/admin/?message=deleted", http.StatusSeeOther)
}

func (a *App) toggleSubscription(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	if err := a.store.SetSubscriptionEnabled(r.Context(), sub.ID, !sub.Enabled); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法更新订阅状态")
		return
	}
	http.Redirect(w, r, "/admin/?message=toggled", http.StatusSeeOther)
}

func (a *App) batchContent(w http.ResponseWriter, r *http.Request) {
	idsRaw := r.Form["subscription_ids"]
	if len(idsRaw) == 0 || len(idsRaw) > 5000 {
		a.renderError(w, http.StatusBadRequest, "请选择 1 到 5000 个订阅")
		return
	}
	seen := make(map[int64]bool)
	ids := make([]int64, 0, len(idsRaw))
	for _, raw := range idsRaw {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			a.renderError(w, http.StatusBadRequest, "包含无效的订阅编号")
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	content := normalizeContent(r.FormValue("content"))
	if content == "" || len(content) > 2*1024*1024 {
		a.renderError(w, http.StatusBadRequest, "节点内容不能为空且不能超过 2 MiB")
		return
	}
	updated, err := a.store.BatchUpdateContent(r.Context(), ids, content)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.renderError(w, http.StatusBadRequest, "部分订阅不存在，请刷新页面后重试；所有订阅均未修改")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "批量更新失败，所有订阅均未修改")
		return
	}
	if updated != int64(len(ids)) {
		a.renderError(w, http.StatusBadRequest, "部分订阅不存在，请刷新页面后重试")
		return
	}
	http.Redirect(w, r, "/admin/?message=batch-updated", http.StatusSeeOther)
}

func (a *App) previewSubscription(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(normalizeContent(sub.Content)))))
}

func (a *App) subscriptionQRCode(w http.ResponseWriter, r *http.Request) {
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	subscriptionURL := a.baseURL(r) + sub.Path
	png, err := qrcode.Encode(subscriptionQRPayload(subscriptionURL), qrcode.Medium, 320)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法生成订阅二维码")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="subscription-%d.png"`, sub.ID))
	_, _ = w.Write(png)
}

func subscriptionQRPayload(subscriptionURL string) string {
	return "sub://" + base64.RawStdEncoding.EncodeToString([]byte(subscriptionURL))
}

func (a *App) subscriptionLogs(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	sub, ok := a.loadSubscription(w, r)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	client := strings.TrimSpace(r.URL.Query().Get("client"))
	logs, err := a.store.AccessLogs(r.Context(), sub.ID, page, 50, ip, client)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取访问日志")
		return
	}
	data := viewData{
		Title: "访问日志", CSRF: auth.Session.CSRFToken, Subscription: sub, Logs: logs,
		FilterIP: ip, FilterClient: client, Message: messageFromQuery(r.URL.Query().Get("message")),
	}
	if logs.Page > 1 {
		data.PrevPage = logs.Page - 1
	}
	if logs.Page < logs.TotalPages {
		data.NextPage = logs.Page + 1
	}
	a.render(w, "logs.html", data)
}

func (a *App) clearSubscriptionLogs(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if err := a.store.ClearAccessLogs(r.Context(), id); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法清空访问日志")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/subscriptions/%d/logs?message=logs-cleared", id), http.StatusSeeOther)
}

func (a *App) settingsPage(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	a.render(w, "settings.html", viewData{
		Title: "系统设置", CSRF: auth.Session.CSRFToken, Settings: auth.Config,
		EnvTrustedProxies: a.cfg.TrustedProxies,
		TrustAllByDefault: a.cfg.TrustAllByDefault,
		Message:           messageFromQuery(r.URL.Query().Get("message")),
	})
}

func (a *App) updateSettings(w http.ResponseWriter, r *http.Request) {
	auth, _ := getAuth(r)
	retention, err := strconv.Atoi(r.FormValue("log_retention_days"))
	data := viewData{
		Title: "系统设置", CSRF: auth.Session.CSRFToken, Settings: auth.Config,
		EnvTrustedProxies: a.cfg.TrustedProxies, TrustAllByDefault: a.cfg.TrustAllByDefault,
	}
	if err != nil || retention < 0 || retention > 36500 {
		data.Error = "日志保留天数必须是 0 到 36500 之间的整数"
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "settings.html", data)
		return
	}
	proxies, err := normalizeTrustedProxies(r.FormValue("trusted_proxies"))
	if err != nil {
		data.Error = err.Error()
		data.Settings.LogRetentionDays = retention
		data.Settings.TrustedProxies = r.FormValue("trusted_proxies")
		w.WriteHeader(http.StatusBadRequest)
		a.render(w, "settings.html", data)
		return
	}
	if err := a.store.UpdateSettings(r.Context(), retention, proxies); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法保存系统设置")
		return
	}
	if err := a.ipResolver.setConfigured(proxies); err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法应用可信代理设置")
		return
	}
	http.Redirect(w, r, "/admin/settings?message=settings-updated", http.StatusSeeOther)
}

func (a *App) publicSubscription(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/admin") {
		http.NotFound(w, r)
		return
	}
	sub, err := a.store.SubscriptionByPath(r.Context(), r.URL.Path)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		a.renderError(w, http.StatusInternalServerError, "无法读取订阅")
		return
	}
	userAgent := r.UserAgent()
	if len(userAgent) > 1024 {
		userAgent = userAgent[:1024]
		for !utf8.ValidString(userAgent) && len(userAgent) > 0 {
			userAgent = userAgent[:len(userAgent)-1]
		}
	}
	ip := a.clientIP(r)
	if err := a.store.RecordAccess(r.Context(), sub.ID, ip, detectClient(userAgent), userAgent, r.Method, http.StatusOK); err != nil {
		a.logger.Error("record subscription access", "subscription_id", sub.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "暂时无法生成订阅")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(normalizeContent(sub.Content)))))
}

func (a *App) loadSubscription(w http.ResponseWriter, r *http.Request) (Subscription, bool) {
	id, err := parseID(r)
	if err != nil {
		a.renderError(w, http.StatusNotFound, "订阅不存在")
		return Subscription{}, false
	}
	sub, err := a.store.SubscriptionByID(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			a.renderError(w, http.StatusNotFound, "订阅不存在")
		} else {
			a.renderError(w, http.StatusInternalServerError, "无法读取订阅")
		}
		return Subscription{}, false
	}
	return sub, true
}

func subscriptionFromForm(r *http.Request) Subscription {
	return Subscription{
		Name: strings.TrimSpace(r.FormValue("name")), Path: strings.TrimSpace(r.FormValue("path")),
		Content: r.FormValue("content"), Enabled: r.FormValue("enabled") == "1",
	}
}

func (a *App) baseURL(r *http.Request) string {
	if a.cfg.BaseURL != "" {
		return a.cfg.BaseURL
	}
	scheme := "http"
	if r.TLS != nil || (a.requestNetworkInfo(r).FromTrustedProxy && strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")) {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	return scheme + "://" + host
}

func logFilterQuery(ip, client string) string {
	values := url.Values{}
	if ip != "" {
		values.Set("ip", ip)
	}
	if client != "" {
		values.Set("client", client)
	}
	return values.Encode()
}

func uniqueClients(logs []AccessLog) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range logs {
		if !seen[item.ClientName] {
			seen[item.ClientName] = true
			out = append(out, item.ClientName)
		}
	}
	sort.Strings(out)
	return out
}
