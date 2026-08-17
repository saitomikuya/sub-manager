package app

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "sub_manager_session"

func (a *App) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			a.redirectLogin(w, r)
			return
		}
		session, err := a.store.Session(r.Context(), cookie.Value)
		if err != nil {
			if err != sql.ErrNoRows {
				a.logger.Error("load session", "error", err)
			}
			a.clearSessionCookie(w, r)
			a.redirectLogin(w, r)
			return
		}
		settings, err := a.store.Settings(r.Context())
		if err != nil {
			a.renderError(w, http.StatusInternalServerError, "无法读取系统设置")
			return
		}
		if settings.MustChange && r.URL.Path != "/admin/password" && r.URL.Path != "/admin/logout" {
			http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
			return
		}
		auth := authContext{Token: cookie.Value, Session: session, Config: settings}
		next.ServeHTTP(w, r.WithContext(withAuth(r.Context(), auth)))
	})
}

func (a *App) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := getAuth(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := r.FormValue("csrf_token")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(auth.Session.CSRFToken)) != 1 {
			a.renderError(w, http.StatusForbidden, "页面已过期，请返回后重试")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withAuth(ctx context.Context, auth authContext) context.Context {
	return context.WithValue(ctx, authContextKey, auth)
}

func getAuth(r *http.Request) (authContext, bool) {
	auth, ok := r.Context().Value(authContextKey).(authContext)
	return auth, ok
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/admin", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: a.isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/admin", MaxAge: -1, Expires: time.Unix(1, 0),
		HttpOnly: true, Secure: a.isSecureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) redirectLogin(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/admin/") {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
