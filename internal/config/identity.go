package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func readConfig(path string) ([]byte, error) {
	f, err := openConfig(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxConfigBytes {
		return nil, errors.New("配置须为不超过 256 KiB 的普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("配置超过 256 KiB")
	}
	return data, nil
}

func configDocument(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("配置 YAML 解析失败")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("配置只允许一个 YAML 文档")
	}
	count := 0
	var visit func(*yaml.Node, int) bool
	visit = func(n *yaml.Node, depth int) bool {
		count++
		// 别名展开可远大于输入；配置没有复用锚点的契约，直接拒绝。
		if depth > 32 || count > 8192 || n.Kind == yaml.AliasNode {
			return false
		}
		for _, c := range n.Content {
			if !visit(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !visit(&doc, 0) {
		return nil, errors.New("配置嵌套、节点数量或别名超出约束")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置须为 YAML 映射")
	}
	return &doc, nil
}

// InitializeIdentity 在已独占实例端点的启动事务内调用；重新读取磁盘，
// 一次写回两个字段，并返回实际落盘的完整配置。失败时不发布临时身份。
func InitializeIdentity(path string, generate func() (deviceID, privateKey string, err error)) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	path = CanonicalPath(path)
	data, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	cfg, err := parseConfig(data, path)
	if err != nil {
		return nil, err
	}
	if cfg.DeviceID != "" && cfg.WireGuard.PrivateKey != "" {
		return cfg, nil
	}
	id, key, err := generate()
	if err != nil {
		return nil, err
	}
	if id == "" || key == "" {
		return nil, errors.New("生成的身份为空")
	}
	doc, err := configDocument(data)
	if err != nil {
		return nil, err
	}
	root := doc.Content[0]
	if cfg.DeviceID == "" {
		setScalar(root, "device_id", id)
		cfg.DeviceID = id
	}
	if cfg.WireGuard.PrivateKey == "" {
		wg := mappingValue(root, "wireguard")
		if wg == nil {
			wg = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "wireguard"}, wg)
		}
		if wg.Tag == "!!null" {
			*wg = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		if wg.Kind != yaml.MappingNode {
			return nil, errors.New("wireguard 须为映射")
		}
		setScalar(wg, "private_key", key)
		cfg.WireGuard.PrivateKey = key
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, errors.New("身份配置编码失败")
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if out.Len() > maxConfigBytes {
		return nil, errors.New("写回后的配置超过 256 KiB")
	}
	if err := replacePrivateFile(cfg.SourcePath(), out.Bytes()); err != nil {
		return nil, fmt.Errorf("身份持久化失败: %w", err)
	}
	return cfg, nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func setScalar(n *yaml.Node, key, value string) {
	if v := mappingValue(n, key); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!str"
		v.Value = value
		v.Content = nil
		return
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func replacePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := checkIdentityDirectory(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".njuvpn-identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
