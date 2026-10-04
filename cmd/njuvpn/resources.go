package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

func cmdResources(args []string) error {
	fs := flag.NewFlagSet("resources", flag.ContinueOnError)
	path := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	endpoint, err := endpointFor(*path)
	if err != nil {
		return err
	}
	resp, err := call(endpoint, ipc.Request{Command: ipc.CmdResources}, 5*time.Second)
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return errors.New(resp.Message)
	}
	var resources ztna.L3Resources
	if err := json.Unmarshal([]byte(resp.Message), &resources); err != nil || resources.IP == nil || resources.NodeGroup == nil {
		return errors.New("资源快照响应格式非法")
	}
	return printResources(os.Stdout, resources)
}

func printResources(w io.Writer, resources ztna.L3Resources) error {
	// IPC 是新的输入边界；校验所有显示字段后再输出，避免部分非法表。
	for _, rule := range resources.IP {
		if !rule.Host.Addr().Is4() || rule.Host != rule.Host.Masked() || rule.Port[0] == 0 || rule.Port[0] > rule.Port[1] {
			return errors.New("IPv4 资源规则格式非法")
		}
		switch rule.Protocol {
		case ztna.ResourceProtocolAll, ztna.ResourceProtocolTCP, ztna.ResourceProtocolUDP:
		default:
			return errors.New("IPv4 资源协议非法")
		}
	}
	for _, dns := range []string{resources.DNS.FirstDNS, resources.DNS.SecondDNS} {
		if dns != "" {
			if addr, err := netip.ParseAddr(dns); err != nil || !addr.Is4() {
				return errors.New("校园 DNS 地址格式非法")
			}
		}
	}
	if len(resources.IP) == 0 {
		if _, err := fmt.Fprintln(w, "IPv4 资源表为空"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "IPv4 资源表"); err != nil {
			return err
		}
		for _, rule := range resources.IP {
			port := fmt.Sprint(rule.Port[0])
			if rule.Port[0] != rule.Port[1] {
				port = fmt.Sprintf("%d-%d", rule.Port[0], rule.Port[1])
			}
			if _, err := fmt.Fprintf(w, "%-8s%-24s%s\n", rule.Protocol, rule.Host, port); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\nDNS 服务器\n首选  %s  备选  %s\n", resources.DNS.FirstDNS, resources.DNS.SecondDNS)
	return err
}
