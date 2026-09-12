package ipc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEndpointForIsStableForSameConfig 验证同一份配置总是得到同一个端点。
func TestEndpointForIsStableForSameConfig(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "config.yaml")

	if first, second := EndpointFor(path), EndpointFor(path); first != second {
		t.Fatalf("同一路径两次派生不一致: %q != %q", first, second)
	}
}

// TestEndpointForDependsOnlyOnPath 验证端点只依赖路径身份。
//
// 内容是会变的：服务进程启动时会往配置里写回 WireGuard 私钥，
// wg-peer 会写回客户端公钥。按内容派生的话，端点在第一次启动后就漂移，
// CLI 再也找不到正在跑的那个进程。
func TestEndpointForDependsOnlyOnPath(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "config.yaml")
	before := EndpointFor(path)

	if err := os.WriteFile(path, []byte("server: y\nprivate_key: abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if after := EndpointFor(path); after != before {
		t.Fatalf("内容变化影响了端点: %q -> %q", before, after)
	}
}

// TestEndpointForDifferentConfigs 验证不同配置得到不同端点。
func TestEndpointForDifferentConfigs(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.yaml")
	b := writeConfig(t, dir, "b.yaml")

	if EndpointFor(a) == EndpointFor(b) {
		t.Fatal("两份不同的配置得到了同一个端点")
	}
}

// TestEndpointForRelativePath 验证相对路径按当前工作目录规范化。
func TestEndpointForRelativePath(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml")
	t.Chdir(dir)

	if got, want := EndpointFor("config.yaml"), EndpointFor(path); got != want {
		t.Fatalf("相对路径与绝对路径派生不一致: %q != %q", got, want)
	}
	roundabout := filepath.Join("..", filepath.Base(dir), "config.yaml")
	if got, want := EndpointFor(roundabout), EndpointFor(path); got != want {
		t.Fatalf("含 .. 的路径与绝对路径派生不一致: %q != %q", got, want)
	}
}

// TestEndpointForSymlink 验证符号链接归一到真实路径。
func TestEndpointForSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上创建符号链接需要特权")
	}
	dir := t.TempDir()
	target := writeConfig(t, dir, "real.yaml")
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if EndpointFor(link) != EndpointFor(target) {
		t.Fatal("符号链接与真实路径派生出了不同的端点")
	}
}

// TestEndpointForMissingFile 验证配置文件还不存在时也能算出端点。
func TestEndpointForMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-yet.yaml")

	if EndpointFor(missing) != EndpointFor(missing) {
		t.Fatal("文件不存在时派生结果不稳定")
	}
}

// TestEndpointForEmpty 验证空路径得到固定标识。
func TestEndpointForEmpty(t *testing.T) {
	if got, want := EndpointFor(""), endpointPath("default"); got != want {
		t.Fatalf("空路径应得到 default 端点，得到 %q", got)
	}
}

// writeConfig 写一份最小配置并返回路径。
func writeConfig(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("server: vpn.example.edu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
