package ipc

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsConfigIdentityIsCaseInsensitive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "MixedCase.yaml")
	lower, upper := strings.ToLower(path), strings.ToUpper(path)
	if ConfigIdentity(lower) != ConfigIdentity(upper) || EndpointFor(lower) != EndpointFor(upper) {
		t.Fatal("同一 Windows 配置因大小写被分成两个实例")
	}
	if NewClient(lower).identity != NewClient(upper).identity {
		t.Fatal("连接核验与端点派生的大小写规则不一致")
	}
}
