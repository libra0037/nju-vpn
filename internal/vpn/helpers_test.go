package vpn

import "runtime"

// runtimeGoroutines 返回当前 goroutine 数量，用于泄漏检查。
func runtimeGoroutines() int { return runtime.NumGoroutine() }
