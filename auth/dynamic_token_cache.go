package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"kiro2api/config"
	"kiro2api/logger"
	"kiro2api/types"
	"sync"
	"time"
)

// DynamicTokenCache 动态 Token 缓存
// 用于缓存通过 refresh token 动态获取的 access token
type DynamicTokenCache struct {
	tokens map[string]*DynamicCachedToken
	mutex  sync.RWMutex
	ttl    time.Duration
}

// DynamicCachedToken 缓存的动态 token
type DynamicCachedToken struct {
	Token    types.TokenInfo
	CachedAt time.Time
}

// 全局动态 Token 缓存实例
var dynamicTokenCache *DynamicTokenCache
var dynamicTokenCacheOnce sync.Once

// GetDynamicTokenCache 获取动态 Token 缓存单例
func GetDynamicTokenCache() *DynamicTokenCache {
	dynamicTokenCacheOnce.Do(func() {
		dynamicTokenCache = &DynamicTokenCache{
			tokens: make(map[string]*DynamicCachedToken),
			ttl:    config.TokenCacheTTL,
		}
		logger.Info("动态Token缓存初始化完成",
			logger.Duration("ttl", config.TokenCacheTTL))
	})
	return dynamicTokenCache
}

// hashRefreshToken 对 refresh token 进行哈希，作为缓存 key
func hashRefreshToken(refreshToken string) string {
	hash := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(hash[:])
}

// GetOrRefresh 获取缓存的 token，如果不存在或过期则刷新
// 返回: token, error
func (dtc *DynamicTokenCache) GetOrRefresh(refreshToken string) (types.TokenInfo, error) {
	cacheKey := hashRefreshToken(refreshToken)

	// 先尝试读取缓存
	dtc.mutex.RLock()
	if cached, exists := dtc.tokens[cacheKey]; exists {
		// 检查是否过期（缓存 TTL 或 token 本身过期）
		if time.Since(cached.CachedAt) <= dtc.ttl && !cached.Token.IsExpired() {
			dtc.mutex.RUnlock()
			logger.Debug("动态Token缓存命中",
				logger.String("cache_key_preview", cacheKey[:8]+"..."))
			return cached.Token, nil
		}
	}
	dtc.mutex.RUnlock()

	// 缓存未命中或过期，需要刷新
	logger.Debug("动态Token缓存未命中，开始刷新",
		logger.String("cache_key_preview", cacheKey[:8]+"..."))

	// 使用 Social 认证方式刷新（refresh token 默认走 Social）
	token, err := refreshSocialToken(refreshToken)
	if err != nil {
		return types.TokenInfo{}, fmt.Errorf("刷新token失败: %w", err)
	}

	// 更新缓存
	dtc.mutex.Lock()
	dtc.tokens[cacheKey] = &DynamicCachedToken{
		Token:    token,
		CachedAt: time.Now(),
	}
	dtc.mutex.Unlock()

	logger.Debug("动态Token刷新成功并缓存",
		logger.String("cache_key_preview", cacheKey[:8]+"..."),
		logger.String("expires_at", token.ExpiresAt.Format("2006-01-02 15:04:05")))

	return token, nil
}

// CleanExpired 清理过期的缓存条目
func (dtc *DynamicTokenCache) CleanExpired() int {
	dtc.mutex.Lock()
	defer dtc.mutex.Unlock()

	cleaned := 0
	for key, cached := range dtc.tokens {
		if time.Since(cached.CachedAt) > dtc.ttl || cached.Token.IsExpired() {
			delete(dtc.tokens, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		logger.Debug("清理过期的动态Token缓存",
			logger.Int("cleaned_count", cleaned))
	}

	return cleaned
}

// Size 返回缓存大小
func (dtc *DynamicTokenCache) Size() int {
	dtc.mutex.RLock()
	defer dtc.mutex.RUnlock()
	return len(dtc.tokens)
}
