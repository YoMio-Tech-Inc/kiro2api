package auth

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/types"
)

// AuthService 认证服务（推荐使用依赖注入方式）
type AuthService struct {
	tokenManager *TokenManager
	configs      []AuthConfig
}

// NewAuthService 创建新的认证服务（推荐使用此方法而不是全局函数）
// 如果没有配置 KIRO_AUTH_TOKEN，仍然可以创建 AuthService，仅支持动态 refresh token 认证
func NewAuthService() (*AuthService, error) {
	logger.Info("创建AuthService实例")

	// 加载配置（现在允许返回空配置）
	configs, err := loadConfigs()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 如果没有配置，创建一个只支持动态 token 的 AuthService
	if len(configs) == 0 {
		logger.Info("AuthService创建完成（仅动态token模式）")
		return &AuthService{
			tokenManager: nil, // 没有预配置的 token 管理器
			configs:      configs,
		}, nil
	}

	// 创建token管理器
	tokenManager := NewTokenManager(configs)

	// 预热第一个可用token
	_, warmupErr := tokenManager.getBestToken()
	if warmupErr != nil {
		logger.Warn("token预热失败", logger.Err(warmupErr))
	}

	logger.Info("AuthService创建完成", logger.Int("config_count", len(configs)))

	return &AuthService{
		tokenManager: tokenManager,
		configs:      configs,
	}, nil
}

// GetToken 获取可用的token
func (as *AuthService) GetToken() (types.TokenInfo, error) {
	if as.tokenManager == nil {
		return types.TokenInfo{}, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.getBestToken()
}

// GetTokenWithUsage 获取可用的token（包含使用信息）
func (as *AuthService) GetTokenWithUsage() (*types.TokenWithUsage, error) {
	if as.tokenManager == nil {
		return nil, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.GetBestTokenWithUsage()
}

// GetTokenManager 获取底层的TokenManager（用于高级操作）
func (as *AuthService) GetTokenManager() *TokenManager {
	return as.tokenManager
}

// GetConfigs 获取认证配置
func (as *AuthService) GetConfigs() []AuthConfig {
	return as.configs
}
