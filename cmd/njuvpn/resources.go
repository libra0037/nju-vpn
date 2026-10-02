package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
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
	var resources []ztna.Resource
	if err := json.Unmarshal([]byte(resp.Message), &resources); err != nil || resources == nil {
		return errors.New("资源快照响应格式非法")
	}
	return printResources(os.Stdout, resources)
}

func printResources(w io.Writer, resources []ztna.Resource) error {
	for i := range resources {
		for j := range resources[i].AddressList {
			sort.Strings(resources[i].AddressList[j].IP)
		}
		sort.SliceStable(resources[i].AddressList, func(a, b int) bool {
			x, y := resources[i].AddressList[a], resources[i].AddressList[b]
			if x.Host != y.Host {
				return x.Host < y.Host
			}
			if x.Protocol != y.Protocol {
				return x.Protocol < y.Protocol
			}
			if x.Port != y.Port {
				return x.Port < y.Port
			}
			return slices.Compare(x.IP, y.IP) < 0
		})
	}
	sort.SliceStable(resources, func(i, j int) bool {
		a, _ := json.Marshal(resources[i])
		b, _ := json.Marshal(resources[j])
		return string(a) < string(b)
	})
	if len(resources) == 0 {
		_, err := fmt.Fprintln(w, "VPN 资源列表为空")
		return err
	}
	if _, err := fmt.Fprintln(w, "应用 ID\t访问模式\t节点组 ID\t地址\t协议\t端口\tIP 列表"); err != nil {
		return err
	}
	quote := strconv.QuoteToASCII
	for _, resource := range resources {
		model := resource.AccessModel
		if model == "" {
			model = "未标注"
		}
		addresses := resource.AddressList
		if len(addresses) == 0 {
			addresses = []ztna.ResourceAddress{{}}
		}
		for _, addr := range addresses {
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", quote(resource.ID), quote(model), quote(resource.NodeGroupID), quote(addr.Host), quote(addr.Protocol), quote(addr.Port), quote(strings.Join(addr.IP, ", "))); err != nil {
				return err
			}
		}
	}
	return nil
}
