package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
)

// EndpointFor 按配置文件的身份派生 IPC 端点。
//
// 同一份配置总是得到同一个端点，不同的配置得到不同的端点——同机跑多个
// 实例时，CLI 才不会把命令发给另一个实例（那会静默地操作错账号）。
//
// 只依赖路径这个身份，不依赖文件内容：服务进程启动时会生成 WireGuard
// 私钥并写回配置，wg-peer 也会写回客户端公钥。按内容派生的话，端点在
// 第一次启动之后就会漂移，CLI 再也找不到正在跑的那个进程。
//
// configPath 为空时返回固定标识 default：只有手工构造的配置才会走到，
// 正常路径上 config.Load 一定会填好来源路径。
func EndpointFor(configPath string) string {
	return endpointPath(InstanceTag(configPath))
}

// InstanceTag 返回配置文件的短标识，8 个十六进制字符。
//
// 实例的本地痕迹都从这一个标识派生（IPC 端点、日志文件名、状态输出），
// 多实例时对得上号。它由路径决定，与配置内容无关。
//
// 规范化是为了让同一份配置总得到同一个标识：相对路径按当前工作目录
// 确定下来，符号链接归一到真实路径。EvalSymlinks 失败时回落到 Abs 的结果
// ——配置文件还不存在时也要能算出端点。
func InstanceTag(configPath string) string {
	if configPath == "" {
		return "default"
	}
	p := configPath
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	// Windows 的文件系统不区分大小写，同一份配置写成 Config.yaml 与
	// config.yaml 会派生出两个端点，所以哈希输入统一小写。
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:4])
}
