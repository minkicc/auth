package plugins

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func allowlistForRequest(baseHost string, configured []string) []string {
	rules := make([]string, 0, len(configured)+1)
	if baseHost = strings.TrimSpace(strings.ToLower(baseHost)); baseHost != "" {
		rules = append(rules, baseHost)
	}
	for _, item := range configured {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			rules = append(rules, item)
		}
	}
	return rules
}

func requireHostAllowed(kind string, parsed *url.URL, allowlist []string, allowAnyWhenEmpty bool) error {
	if parsed == nil {
		return fmt.Errorf("%s url is required", kind)
	}
	if len(allowlist) == 0 && allowAnyWhenEmpty {
		return nil
	}
	if hostAllowed(parsed, allowlist) {
		return nil
	}
	return fmt.Errorf("%s host %q is not allowed", kind, parsed.Host)
}

func hostAllowed(parsed *url.URL, allowlist []string) bool {
	if parsed == nil {
		return false
	}
	host := strings.TrimSpace(strings.ToLower(parsed.Host))
	hostname := strings.TrimSpace(strings.ToLower(parsed.Hostname()))
	for _, rule := range allowlist {
		rule = strings.TrimSpace(strings.ToLower(rule))
		if rule == "" {
			continue
		}
		switch {
		case strings.HasPrefix(rule, "*."):
			suffix := strings.TrimPrefix(rule, "*.")
			if hostname != suffix && strings.HasSuffix(hostname, "."+suffix) {
				return true
			}
		case strings.HasPrefix(rule, "."):
			suffix := strings.TrimPrefix(rule, ".")
			if hostname == suffix || strings.HasSuffix(hostname, "."+suffix) {
				return true
			}
		case strings.Contains(rule, ":"):
			if host == rule {
				return true
			}
		default:
			if hostname == rule {
				return true
			}
		}
	}
	return false
}

func newRestrictedHTTPClient(timeout time.Duration, allowlist []string, allowPrivateNetworks bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialRestricted(ctx, network, address, allowPrivateNetworks)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return requireHostAllowed("redirect target", req.URL, allowlist, false)
		},
	}
}

func dialRestricted(ctx context.Context, network, address string, allowPrivateNetworks bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	for _, ip := range ips {
		if err := requireRemoteIPAllowed(host, ip.IP, allowPrivateNetworks); err != nil {
			return nil, err
		}
	}

	dialer := &net.Dialer{}
	target := net.JoinHostPort(ips[0].IP.String(), port)
	return dialer.DialContext(ctx, network, target)
}

func requireRemoteIPAllowed(host string, ip net.IP, allowPrivateNetworks bool) error {
	if allowPrivateNetworks {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("remote host %q resolved to invalid address %q", host, ip.String())
	}
	addr = addr.Unmap()
	if isBlockedRemoteAddress(addr) {
		return fmt.Errorf("remote host %q resolved to blocked address %s", host, addr.String())
	}
	return nil
}

func isBlockedRemoteAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return true
	}
	if addr.Is4() {
		return isAddrInPrefix(addr, "100.64.0.0/10") ||
			isAddrInPrefix(addr, "169.254.0.0/16") ||
			isAddrInPrefix(addr, "192.0.0.0/24") ||
			isAddrInPrefix(addr, "192.0.2.0/24") ||
			isAddrInPrefix(addr, "198.18.0.0/15") ||
			isAddrInPrefix(addr, "198.51.100.0/24") ||
			isAddrInPrefix(addr, "203.0.113.0/24") ||
			isAddrInPrefix(addr, "240.0.0.0/4")
	}
	return isAddrInPrefix(addr, "2001:db8::/32")
}

func isAddrInPrefix(addr netip.Addr, cidr string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	return err == nil && prefix.Contains(addr)
}
