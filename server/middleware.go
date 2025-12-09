package server

import (
	"net/http"
	"strings"

	"kiro2api/auth"
	"kiro2api/logger"
	"kiro2api/types"
	"kiro2api/utils"

	"github.com/gin-gonic/gin"
)

// Context keys for dynamic token
const (
	DynamicTokenKey = "dynamic_token"
)

// PathBasedAuthMiddleware 创建基于路径的API密钥验证中间件
func PathBasedAuthMiddleware(authToken string, protectedPrefixes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// 检查是否需要认证
		if !requiresAuth(path, protectedPrefixes) {
			logger.Debug("跳过认证", logger.String("path", path))
			c.Next()
			return
		}

		if !validateAPIKey(c, authToken) {
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware 为每个请求注入 request_id 并通过响应头返回
// - 优先使用客户端的 X-Request-ID
// - 若无则生成一个UUID（utils.GenerateUUID）
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		if rid == "" {
			rid = "req_" + utils.GenerateUUID()
		}
		c.Set("request_id", rid)
		c.Writer.Header().Set("X-Request-ID", rid)
		c.Next()
	}
}

// GetRequestID 从上下文读取 request_id（若不存在返回空串）
func GetRequestID(c *gin.Context) string {
	if v, ok := c.Get("request_id"); ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

// GetMessageID 从上下文读取 message_id（若不存在返回空串）
func GetMessageID(c *gin.Context) string {
	if v, ok := c.Get("message_id"); ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

// addReqFields 注入标准请求字段，统一上下游日志可追踪（DRY）
func addReqFields(c *gin.Context, fields ...logger.Field) []logger.Field {
	rid := GetRequestID(c)
	mid := GetMessageID(c)
	// 预留容量避免重复分配
	out := make([]logger.Field, 0, len(fields)+2)
	if rid != "" {
		out = append(out, logger.String("request_id", rid))
	}
	if mid != "" {
		out = append(out, logger.String("message_id", mid))
	}
	out = append(out, fields...)
	return out
}

// requiresAuth 检查指定路径是否需要认证
func requiresAuth(path string, protectedPrefixes []string) bool {
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// extractAPIKey 提取API密钥的通用逻辑
func extractAPIKey(c *gin.Context) string {
	apiKey := c.GetHeader("Authorization")
	if apiKey == "" {
		apiKey = c.GetHeader("x-api-key")
	} else {
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
	}
	return apiKey
}

// validateAPIKey 验证API密钥 - 支持两种认证模式
// 1. 预配置的 KIRO_CLIENT_TOKEN（原有模式）
// 2. 动态传入的 refresh token（新增模式）
func validateAPIKey(c *gin.Context, authToken string) bool {
	providedApiKey := extractAPIKey(c)

	if providedApiKey == "" {
		logger.Warn("请求缺少Authorization或x-api-key头")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "401"})
		return false
	}

	// 模式1: 验证预配置的 KIRO_CLIENT_TOKEN（如果已配置）
	if authToken != "" && providedApiKey == authToken {
		return true
	}

	// 模式2: 尝试作为 refresh token 处理
	// refresh token 通常是较长的字符串（JWT 或 UUID 格式）
	if len(providedApiKey) > 20 {
		logger.Debug("尝试作为refresh token处理",
			logger.Int("token_length", len(providedApiKey)))

		// 使用动态 Token 缓存获取或刷新 token
		dynamicCache := auth.GetDynamicTokenCache()
		token, err := dynamicCache.GetOrRefresh(providedApiKey)
		if err != nil {
			logger.Warn("refresh token刷新失败",
				logger.Err(err),
				logger.String("token_preview", providedApiKey[:min(10, len(providedApiKey))]+"..."))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": map[string]any{
					"message": "Invalid refresh token: " + err.Error(),
					"code":    "invalid_token",
				},
			})
			return false
		}

		// 将动态获取的 token 存入 context
		c.Set(DynamicTokenKey, token)
		logger.Debug("refresh token认证成功",
			logger.String("token_preview", providedApiKey[:min(10, len(providedApiKey))]+"..."))
		return true
	}

	// 既不是预配置 token，也不是有效的 refresh token
	logger.Error("authToken验证失败",
		logger.String("expected", "***"),
		logger.String("provided", "***"))
	c.JSON(http.StatusUnauthorized, gin.H{"error": "401"})
	return false
}

// GetDynamicToken 从 context 中获取动态 token（如果存在）
func GetDynamicToken(c *gin.Context) (types.TokenInfo, bool) {
	if v, ok := c.Get(DynamicTokenKey); ok {
		if token, ok := v.(types.TokenInfo); ok {
			return token, true
		}
	}
	return types.TokenInfo{}, false
}
