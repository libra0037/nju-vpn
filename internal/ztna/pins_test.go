package ztna

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func derOf(s string) []byte { return []byte("DER:" + s) }

func hashOf(s string) [sha256.Size]byte { return sha256.Sum256(derOf(s)) }

func hexOf(s string) string {
	sum := hashOf(s)
	return hex.EncodeToString(sum[:])
}

// TestNodePinsAcceptsConfiguredFingerprint 验证配置里给的指纹直接放行。
func TestNodePinsAcceptsConfiguredFingerprint(t *testing.T) {
	pins := newNodePins([][sha256.Size]byte{hashOf("node-a")}, "", false, t.Logf)
	if err := pins.verify("10.0.0.1:441", derOf("node-a")); err != nil {
		t.Fatalf("配置里的指纹应当放行，得到 %v", err)
	}
}

// TestNodePinsRemembersFirstUse 验证陌生节点按“首次记录、之后比对”处理：
// 第一次接受并落盘，同一张证书再来仍然接受，换一张就报错并打印两边的指纹。
func TestNodePinsRemembersFirstUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml.node-pins")
	addr := "10.0.0.1:441"

	first := newNodePins(nil, path, false, t.Logf)
	if err := first.verify(addr, derOf("node-a")); err != nil {
		t.Fatalf("第一次见到该节点应当接受（并记录），得到 %v", err)
	}
	if err := first.verify(addr, derOf("node-a")); err != nil {
		t.Fatalf("同一张证书再来应当接受，得到 %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("记录应当落盘: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("记录文件权限 = %04o，期望 0600", perm)
	}

	// 新进程（重新读状态文件）必须仍然认它。
	second := newNodePins(nil, path, false, t.Logf)
	if err := second.verify(addr, derOf("node-a")); err != nil {
		t.Fatalf("记录应当跨进程生效，得到 %v", err)
	}
	err = second.verify(addr, derOf("node-b"))
	if err == nil {
		t.Fatal("换了一张证书应当拒绝")
	}
	msg := err.Error()
	for _, want := range []string{addr, "pinned_node_sha256", strings.ToUpper(hexOf("node-a")), strings.ToUpper(hexOf("node-b"))} {
		if !strings.Contains(msg, want) {
			t.Errorf("错误串应当包含 %q，得到: %s", want, msg)
		}
	}
}

// TestNodePinsStrictRejectsUnknown 验证用户在配置里写了指纹之后不再首次记录：
// 陌生节点被拒绝，并把观测到的指纹打出来（那正是要填进配置的值）。
func TestNodePinsStrictRejectsUnknown(t *testing.T) {
	pins := newNodePins([][sha256.Size]byte{hashOf("other")}, "", true, t.Logf)
	err := pins.verify("10.0.0.9:441", derOf("node-x"))
	if err == nil {
		t.Fatal("严格模式下陌生节点应当被拒绝")
	}
	if want := strings.ToUpper(hexOf("node-x")); !strings.Contains(err.Error(), want) {
		t.Errorf("错误串应当带上观测到的指纹 %s，得到 %v", want, err)
	}
}

// TestNodePinsRejectsMissingCertificate 验证对端不出示证书时直接拒绝。
func TestNodePinsRejectsMissingCertificate(t *testing.T) {
	pins := newNodePins(nil, "", false, t.Logf)
	if err := pins.verify("10.0.0.1:441", nil); err == nil {
		t.Fatal("没有证书应当拒绝")
	}
}

// TestNodePinsSaveIgnoresPreplacedTempFile 验证写回不会被同目录里预置的临时
// 文件牵着走。
//
// 旧实现用固定名 <path>.tmp 且不带 O_EXCL，别人预先放一个同名文件或符号链接
// 就能让这次写落到他挑的目标上；这条用例把预置文件摆在那里，写回之后它必须
// 一个字都没变。
func TestNodePinsSaveIgnoresPreplacedTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml.node-pins")
	squat := path + ".tmp"
	const planted = "别人预置的内容\n"
	if err := os.WriteFile(squat, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}

	pins := newNodePins(nil, path, false, t.Logf)
	if err := pins.verify("10.0.0.1:441", derOf("node-a")); err != nil {
		t.Fatalf("首次记录应当接受: %v", err)
	}

	got, err := os.ReadFile(squat)
	if err != nil || string(got) != planted {
		t.Fatalf("预置文件被改动了（内容 %q，错误 %v）——写回必须落在自己新建的文件上", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "10.0.0.1:441") {
		t.Fatalf("指纹记录没有写进 %s: %v", path, err)
	}
}
