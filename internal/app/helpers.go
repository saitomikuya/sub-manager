package app

import (
	"errors"
	"net"
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
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	seen := make(map[string]bool)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return "", errors.New("可信代理必须是有效的 IP 或 CIDR")
			}
			if ip.To4() != nil {
				part = ip.String() + "/32"
			} else {
				part = ip.String() + "/128"
			}
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return "", errors.New("可信代理必须是有效的 IP 或 CIDR")
		}
		canonical := network.String()
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	return strings.Join(result, "\n"), nil
}

func parseNetworks(value string) []*net.IPNet {
	parts := strings.Fields(value)
	result := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		_, network, err := net.ParseCIDR(part)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}

func trustedIP(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func clientIPForRequest(r *http.Request, trustedProxyText string) string {
	remote := remoteIP(r)
	if remote == nil {
		return "unknown"
	}
	networks := parseNetworks(trustedProxyText)
	if !trustedIP(remote, networks) {
		return remote.String()
	}

	chain := make([]net.IP, 0)
	for _, item := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(item)); ip != nil {
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			return ip.String()
		}
		return remote.String()
	}
	// Walk from the application outward. The first untrusted hop is the client;
	// anything further left may have been supplied by that client.
	for i := len(chain) - 1; i >= 0; i-- {
		if !trustedIP(chain[i], networks) {
			return chain[i].String()
		}
	}
	return chain[0].String()
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
	settings, err := a.store.Settings(r.Context())
	if err != nil || !trustedIP(remoteIP(r), parseNetworks(settings.TrustedProxies)) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func isUniquePathError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
