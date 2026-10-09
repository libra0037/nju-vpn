//go:build ignore

// 需要穷尽的内部枚举由源码中的类型化常量驱动；新增值必须补齐消费者。
// 用法：go run scripts/check-enums.go
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
)

func main() {
	specs := []struct{ file, typ, fn, expr string }{
		{"internal/service/service.go", "commandKind", "String", "k"},
		{"internal/service/service.go", "commandKind", "dispatch", "cmd.kind"},
		{"internal/service/status.go", "State", "validTransition", "from"},
		{"internal/ztna/conntrack.go", "flowState", "queuePacket", "f.state"},
		{"internal/ztna/resource.go", "ResourceProtocol", "String", "p"},
		{"internal/wireguard/bind.go", "ListenHost", "newBind", "host"},
		{"internal/packetlog/packet.go", "Kind", "prefix", "k"},
		{"internal/packetlog/packet.go", "Reason", "description", "r"},
	}
	failed := false
	for _, s := range specs {
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, s.file, nil, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		constants := map[string]bool{}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			typ := ""
			for _, item := range g.Specs {
				v := item.(*ast.ValueSpec)
				if v.Type != nil {
					typ = render(fs, v.Type)
				} else if len(v.Values) != 0 {
					typ = ""
				}
				if typ == s.typ {
					for _, name := range v.Names {
						constants[name.Name] = true
					}
				}
			}
		}
		var handled map[string]bool
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != s.fn {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sw, ok := n.(*ast.SwitchStmt)
				if !ok || sw.Tag == nil || render(fs, sw.Tag) != s.expr {
					return true
				}
				cases := map[string]bool{}
				for _, item := range sw.Body.List {
					for _, e := range item.(*ast.CaseClause).List {
						cases[render(fs, e)] = true
					}
				}
				if len(cases) > len(handled) {
					handled = cases
				}
				return true
			})
		}
		if len(constants) == 0 || len(handled) == 0 {
			fmt.Fprintf(os.Stderr, "%s：枚举或消费者未找到（%s.%s）\n", s.file, s.typ, s.fn)
			failed = true
		}
		for name := range constants {
			if !handled[name] {
				fmt.Fprintf(os.Stderr, "%s：%s 缺少 %s 的显式分支\n", s.file, s.fn, name)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

func render(fs *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := format.Node(&b, fs, n); err != nil {
		panic(err)
	}
	return b.String()
}
