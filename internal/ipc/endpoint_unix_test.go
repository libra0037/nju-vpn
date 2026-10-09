//go:build !windows

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointPathFitsShortestSupportedUnixSocket(t *testing.T) {
	for _, runtimeDir := range []string{"", "/short-runtime", "/runtime/" + strings.Repeat("r", 150)} {
		t.Run(fmt.Sprint(len(runtimeDir)), func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			t.Setenv("TMPDIR", "/var/folders/"+strings.Repeat("t", 100)+"/T")
			endpoint := EndpointFor("/private/config.yaml")
			if len(endpoint) > 103 || !strings.HasSuffix(endpoint, ".sock") {
				t.Fatal("128 位标识超过 macOS 套接字预算", len(endpoint))
			}
			if runtimeDir == "/short-runtime" {
				if filepath.Dir(endpoint) != runtimeDir {
					t.Fatal("可用的运行目录没有被采用")
				}
			} else if filepath.Dir(endpoint) != filepath.Join("/tmp", fmt.Sprintf("njuvpn-%d", os.Getuid())) {
				t.Fatal("长临时路径没有进入经过权限检查的短目录")
			}
		})
	}
}
