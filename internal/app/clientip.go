package app

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

type clientIPResolver struct {
	mu          sync.RWMutex
	environment []netip.Prefix
	configured  []netip.Prefix
}

type requestNetworkInfo struct {
	ClientIP         string
	RemoteIP         netip.Addr
	FromTrustedProxy bool
}

type requestNetworkInfoContextKey struct{}

func newClientIPResolver(environment string) (*clientIPResolver, error) {
	prefixes, err := parseTrustedProxyPrefixes(environment)
	if err != nil {
		return nil, err
	}
	return &clientIPResolver{environment: prefixes}, nil
}

func (r *clientIPResolver) setConfigured(value string) error {
	prefixes, err := parseTrustedProxyPrefixes(value)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.configured = prefixes
	r.mu.Unlock()
	return nil
}

func (r *clientIPResolver) isTrusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = normalizeIPAddr(addr)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, prefix := range r.environment {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range r.configured {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *clientIPResolver) resolve(request *http.Request) requestNetworkInfo {
	remote, ok := parseRemoteIP(request.RemoteAddr)
	if !ok {
		return requestNetworkInfo{ClientIP: "unknown"}
	}
	info := requestNetworkInfo{ClientIP: remote.String(), RemoteIP: remote}
	if !r.isTrusted(remote) {
		return info
	}
	info.FromTrustedProxy = true

	chain, present, valid := parseForwardedFor(request.Header)
	if present {
		if !valid {
			return info
		}
		for index := len(chain) - 1; index >= 0; index-- {
			if !r.isTrusted(chain[index]) {
				info.ClientIP = chain[index].String()
				return info
			}
		}
		return info
	}

	if realIP, ok := parseRealIP(request.Header); ok {
		info.ClientIP = realIP.String()
	}
	return info
}

func (a *App) clientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := a.ipResolver.resolve(r)
		ctx := context.WithValue(r.Context(), requestNetworkInfoContextKey{}, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) requestNetworkInfo(r *http.Request) requestNetworkInfo {
	if info, ok := r.Context().Value(requestNetworkInfoContextKey{}).(requestNetworkInfo); ok {
		return info
	}
	return a.ipResolver.resolve(r)
}

func (a *App) clientIP(r *http.Request) string {
	return a.requestNetworkInfo(r).ClientIP
}

func parseTrustedProxyPrefixes(value string) ([]netip.Prefix, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	seen := make(map[netip.Prefix]bool)
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := parseTrustedProxyPrefix(part)
		if err != nil {
			return nil, fmt.Errorf("无效的 IP 或 CIDR %q", part)
		}
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

func parseTrustedProxyPrefix(value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		addr = normalizeIPAddr(addr)
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("ambiguous IPv4-mapped IPv6 prefix")
		}
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func parseRemoteIP(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return normalizeIPAddr(addrPort.Addr()), true
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalizeIPAddr(addr), true
}

func parseForwardedFor(header http.Header) ([]netip.Addr, bool, bool) {
	values := header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil, false, true
	}
	raw := strings.Join(values, ",")
	if strings.TrimSpace(raw) == "" {
		return nil, true, false
	}
	parts := strings.Split(raw, ",")
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, ok := parseForwardedIP(part)
		if !ok {
			return nil, true, false
		}
		chain = append(chain, addr)
	}
	return chain, true, true
}

func parseRealIP(header http.Header) (netip.Addr, bool) {
	values := header.Values("X-Real-IP")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return netip.Addr{}, false
	}
	return parseForwardedIP(values[0])
}

func parseForwardedIP(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return normalizeIPAddr(addr), true
}

func normalizeIPAddr(addr netip.Addr) netip.Addr {
	return addr.WithZone("").Unmap()
}

func canonicalTrustedProxies(value string) (string, error) {
	prefixes, err := parseTrustedProxyPrefixes(value)
	if err != nil {
		return "", err
	}
	items := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		items[index] = prefix.String()
	}
	return strings.Join(items, "\n"), nil
}
