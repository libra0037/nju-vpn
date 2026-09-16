package ztna

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// nodePins 认隧道节点的身份。
//
// 节点用自签证书（CN=sdp，与节点地址无关），链与名称都不可能校验，指纹是
// 唯一可行的判据。规则：配置里给的与内置的已知指纹与地址无关，直接放行；
// 其余节点按“首次记录、之后比对”处理——记录下来的那一台换证书会明确报错，
// 而不是悄悄接受。
//
// 允许首次记录的理由是节点地址来自控制面，而控制面已经走系统信任链（见
// control.go），一次会话里可能有多台节点轮换；记录之后即锁定，中间人只在
// “第一次见这台节点”的窗口里有机会，而那之后必须一直持有同一张证书。
type nodePins struct {
	trusted [][sha256.Size]byte
	path    string
	strict  bool
	warnf   func(format string, args ...any)

	mu      sync.Mutex
	learned map[string]string // 节点地址 -> 指纹（大写十六进制）
}

// newNodePins 构造指纹校验器。path 为空表示不落盘（只在本进程内记忆）；
// strict 为真时不再对陌生节点做“首次记录”，只认给定的指纹（用户在配置里
// 明确写了指纹，就该按他写的来）。
func newNodePins(trusted [][sha256.Size]byte, path string, strict bool, warnf func(string, ...any)) *nodePins {
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	p := &nodePins{trusted: trusted, path: path, strict: strict, warnf: warnf, learned: map[string]string{}}
	p.load()
	return p
}

// verify 校验一张叶子证书，返回 nil 表示可以继续。
func (p *nodePins) verify(addr string, leafDER []byte) error {
	if len(leafDER) == 0 {
		return fmt.Errorf("节点 %s 没有出示证书", addr)
	}
	sum := sha256.Sum256(leafDER)
	for _, trusted := range p.trusted {
		if hmac.Equal(trusted[:], sum[:]) {
			return nil
		}
	}

	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	p.mu.Lock()
	defer p.mu.Unlock()
	if known, ok := p.learned[addr]; ok {
		if strings.EqualFold(known, hexSum) {
			return nil
		}
		return fmt.Errorf("节点 %s 的证书指纹变了：\n  之前: %s\n  现在: %s\n"+
			"确认这不是中间人之后，把新指纹加进配置 tls.pinned_node_sha256；"+
			"同一地址背后有多台设备时（实测本部署就是这样）这属于正常轮换，"+
			"删掉 %s 里对应的一行也会重新记录", addr, known, hexSum, p.path)
	}
	if p.strict {
		return fmt.Errorf("节点 %s 的证书指纹不在配置里：观测到 %s\n"+
			"确认无误后把它加到 tls.pinned_node_sha256（或删掉该项改用首次记录）", addr, hexSum)
	}

	// 第一次见这个地址：记下来，之后就必须一直是它。
	p.learned[addr] = hexSum
	if err := p.save(); err != nil {
		p.warnf("警告: 记录了节点 %s 的证书指纹但没能落盘（%v）；下次启动会重新记录", addr, err)
		return nil
	}
	p.warnf("已记录节点 %s 的证书指纹 %s；之后与它不一致就会拒绝连接", addr, hexSum)
	return nil
}

// load 读回上次记录的指纹。读不出来只当没有记录过：状态文件丢了不该挡住
// 建隧道，代价是重新记录一次。
func (p *nodePins) load() {
	if p.path == "" {
		return
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		p.learned[fields[0]] = strings.ToUpper(fields[1])
	}
}

// save 原子写回状态文件（临时文件加改名），权限 0600：文件本身不是秘密，
// 但改它等于允许别人替换节点证书。
func (p *nodePins) save() error {
	if p.path == "" {
		return nil
	}
	addrs := make([]string, 0, len(p.learned))
	for addr := range p.learned {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	var b strings.Builder
	b.WriteString("# 隧道节点的证书指纹（首次连接时记录）。\n")
	b.WriteString("# 节点换证书后会拒绝连接，确认新指纹无误后删掉对应行即可重新记录。\n")
	for _, addr := range addrs {
		fmt.Fprintf(&b, "%s %s\n", addr, p.learned[addr])
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
