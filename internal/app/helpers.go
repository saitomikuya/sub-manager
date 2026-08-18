package app

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

var subscriptionPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_-]{1,64}$`)

var reservedPaths = map[string]bool{
	"/admin": true, "/api": true, "/healthz": true, "/static": true, "/favicon.ico": true,
}

func validateSubscription(name, path, content string) error {
	if utf8.RuneCountInString(name) > 100 {
		return errors.New("订阅名称不能超过 100 个字符")
	}
	if !subscriptionPathPattern.MatchString(path) {
		return errors.New("路径必须以 / 开头，且只能包含字母、数字、短横线和下划线（最长 64 个字符）")
	}
	if reservedPaths[strings.ToLower(path)] {
		return errors.New("该路径为系统保留路径，请更换")
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("节点内容不能为空")
	}
	if len(content) > 2*1024*1024 {
		return errors.New("节点内容不能超过 2 MiB")
	}
	return nil
}

func normalizeContent(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	return strings.TrimSpace(content)
}

func generateSubscriptionPath() (string, error) {
	token, err := randomToken(9)
	if err != nil {
		return "", err
	}
	return "/s-" + token, nil
}

func detectClient(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "shadow") && strings.Contains(ua, "rocket"):
		return "iOS 代理客户端"
	case strings.Contains(ua, "quantumult"):
		return "Quantumult X"
	case strings.Contains(ua, "stash"):
		return "Stash"
	case strings.Contains(ua, "surge"):
		return "Surge"
	case strings.Contains(ua, "clash"):
		return "Clash"
	case strings.Contains(ua, "curl"):
		return "curl"
	case strings.Contains(ua, "wget"):
		return "wget"
	case strings.Contains(ua, "mozilla") || strings.Contains(ua, "safari") || strings.Contains(ua, "chrome"):
		return "浏览器"
	default:
		return "未知客户端"
	}
}

func normalizeTrustedProxies(value string) (string, error) {
	return canonicalTrustedProxies(value)
}

func (a *App) isSecureRequest(r *http.Request) bool {
	switch a.cfg.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !a.requestNetworkInfo(r).FromTrustedProxy {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func isUniquePathError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
