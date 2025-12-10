package utils

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/proxy"
	"kiro2api/config"
)

var (
	// SharedHTTPClient 共享的HTTP客户端实例，优化了连接池和性能配置
	SharedHTTPClient *http.Client
)

func init() {
	// 检查TLS配置并记录日志
	skipTLS := shouldSkipTLSVerify()
	if skipTLS {
		os.Stderr.WriteString("[WARNING] TLS证书验证已禁用 - 仅适用于开发/调试环境\n")
	}

	// 获取 SOCKS5 代理配置
	socks5Proxy := os.Getenv("SOCKS5_PROXY")

	// 创建 DialContext 函数
	dialContext := createDialContext(socks5Proxy)

	// 创建统一的HTTP客户端
	SharedHTTPClient = &http.Client{
		Transport: &http.Transport{
			// 连接建立配置
			DialContext: dialContext,

			// TLS配置
			TLSHandshakeTimeout: config.HTTPClientTLSHandshakeTimeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLS,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_128_GCM_SHA256,
				},
			},

			// HTTP配置
			ForceAttemptHTTP2:  false,
			DisableCompression: false,
		},
	}
}

// createDialContext 创建连接拨号函数，支持 SOCKS5 代理
// 代理格式: socks5://user:pass@host:port 或 host:port
func createDialContext(socks5Proxy string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	// 基础 Dialer 配置
	baseDialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: config.HTTPClientKeepAlive,
		DualStack: true,
	}

	// 如果没有配置代理，直接返回基础 Dialer
	if socks5Proxy == "" {
		return baseDialer.DialContext
	}

	// 解析代理地址和认证信息
	var auth *proxy.Auth
	var proxyAddr string

	// 尝试解析为 URL 格式
	if u, err := url.Parse(socks5Proxy); err == nil && u.Host != "" {
		proxyAddr = u.Host
		if u.User != nil {
			auth = &proxy.Auth{
				User: u.User.Username(),
			}
			if pass, ok := u.User.Password(); ok {
				auth.Password = pass
			}
		}
	} else {
		// 纯 host:port 格式
		proxyAddr = socks5Proxy
	}

	// 创建 SOCKS5 代理 Dialer
	proxyDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, baseDialer)
	if err != nil {
		os.Stderr.WriteString("[ERROR] SOCKS5 代理配置失败: " + err.Error() + "，将使用直连\n")
		return baseDialer.DialContext
	}

	if auth != nil {
		os.Stderr.WriteString("[INFO] 已启用 SOCKS5 代理(带认证): " + proxyAddr + "\n")
	} else {
		os.Stderr.WriteString("[INFO] 已启用 SOCKS5 代理: " + proxyAddr + "\n")
	}

	// 返回支持 context 的 DialContext 函数
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// 使用代理拨号
		return proxyDialer.Dial(network, addr)
	}
}

// shouldSkipTLSVerify 根据GIN_MODE决定是否跳过TLS证书验证
func shouldSkipTLSVerify() bool {
	return os.Getenv("GIN_MODE") == "debug"
}

// DoRequest 执行HTTP请求
func DoRequest(req *http.Request) (*http.Response, error) {
	return SharedHTTPClient.Do(req)
}
