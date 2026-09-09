// Package config 负责读取服务进程的配置文件。
package config

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config 是服务进程的全部可配置项。
type Config struct {
	Server     string    `yaml:"server"`
	Port       int       `yaml:"port"`
	Username   string    `yaml:"username"`
	Password   string    `yaml:"password"`
	TOTPSecret string    `yaml:"totp_secret"`
	Proxy      string    `yaml:"proxy"`
	WireGuard  WireGuard `yaml:"wireguard"`
	IPC        IPC       `yaml:"ipc"`
	MTU        int       `yaml:"mtu"`
	Log        Log       `yaml:"log"`
}

type WireGuard struct {
	ListenPort    int    `yaml:"listen_port"`
	PrivateKey    string `yaml:"private_key"`
	PeerPublicKey string `yaml:"peer_public_key"`
	PeerAddress   string `yaml:"peer_address"`
}

type IPC struct {
	Endpoint string `yaml:"endpoint"`
}

type Log struct {
	Level string `yaml:"level"`
}

// DefaultPath 返回当前平台的默认配置文件路径。
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\njuvpn\config.yaml`
	}
	return "/etc/njuvpn/config.yaml"
}

// Load 读取配置文件。path 为空时使用 DefaultPath。
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("配置文件 %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Port == 0 {
		c.Port = 443
	}
	if c.MTU == 0 {
		c.MTU = 1320
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.WireGuard.ListenPort == 0 {
		c.WireGuard.ListenPort = 51820
	}
	if c.WireGuard.PeerAddress == "" {
		c.WireGuard.PeerAddress = "10.66.66.2"
	}
}

func (c *Config) validate() error {
	if c.Server == "" {
		return fmt.Errorf("缺少 server")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port 超出范围: %d", c.Port)
	}
	if c.Username == "" {
		return fmt.Errorf("缺少 username")
	}
	if c.Password == "" {
		return fmt.Errorf("缺少 password")
	}
	return nil
}

// ServerAddr 返回 "host:port" 形式的目标地址。
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}
