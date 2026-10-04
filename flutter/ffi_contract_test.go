package main

// Flutter FFI 导出符号的**契约测试**。
//
// 为什么必须有这条：Flutter 侧 lib/services/proxy_manager.dart 用
// `DynamicLibrary.lookupFunction` 按**名字**取这 12 个符号，编译器不做任何检查。
// 少一个不会编译报错、不会 analyze 报错，只会在真机上 lookupFunction 抛
// ArgumentError —— 表现为 App 启动即崩，且崩在 Dart 侧、错误信息与 Go 侧对不上，
// 排查成本极高。
//
// 判据可证伪：删掉任一 //export 函数，本测试立刻失败。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// flutterFFIRequired 列出 Dart 侧 lookupFunction 实际会取的全部符号。
// 新增导出函数不必加进来；但**删改任何一个已有的**都会被这条抓住。
var flutterFFIRequired = []string{
	"ECHGetLog",
	"ECHGetLogCount",
	"ECHInit",
	"ECHInitLastError",
	"ECHInitReady",
	"ECHInitWithBootstrap",
	"ECHSetDohURL",
	"FreeCString",
	"GetProxyPort",
	"IsEchReady",
	"StartProxy",
	"StopProxy",
}

func TestFlutterEntryExportsAllFFISymbols(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("解析 flutter/main.go 失败: %v", err)
	}
	got := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		for _, c := range fn.Doc.List {
			if strings.HasPrefix(c.Text, "//export ") {
				got[strings.TrimSpace(strings.TrimPrefix(c.Text, "//export "))] = true
			}
		}
	}
	var missing []string
	for _, sym := range flutterFFIRequired {
		if !got[sym] {
			missing = append(missing, sym)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("flutter/main.go 缺少 Flutter FFI 必需的导出符号: %v\n" +
			"这些符号由 Dart 侧 lookupFunction 按名字取，缺任何一个都会让真机 App " +
			"启动即崩，且 Dart 侧看不出是 Go 侧的问题。", missing)
	}
}

// TestFlutterEntryDoesNotDependOnWintools 守住迁移的完成度：
// flutter/main.go 一旦重新 import wintools，本仓库就不再是 ech-proxy 的自包含
// 产物，flutter 依赖 ech-proxy repo 这个目标就作废了。
//
// 查的是 **import 块**而不是全文：文件头的说明文档里提到 wintools 是历史沿革的
// 正常叙述（原先它就是 wintools 版），按全文匹配会把这个测试自己写死的文档
// 判成违规 —— 这是本测试第一版犯过的错，留此注释以免再犯。
func TestFlutterEntryDoesNotDependOnWintools(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("解析 flutter/main.go 失败: %v", err)
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.Contains(path, "Hana-ame/wintools") {
			t.Fatalf("flutter/main.go 仍 import %s —— ECH 核心应改用本仓库的 echproxy/ech", path)
		}
	}
}

// TestFlutterEntryUsesLocalEchPackage 正面确认 import 的是本仓库的 ech 核心，
// 而不是别的什么同功能包（防止将来有人改成一个第三方 ech 实现）。
func TestFlutterEntryUsesLocalEchPackage(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean("main.go"))
	if err != nil {
		t.Fatalf("读 main.go 失败: %v", err)
	}
	want := `"github.com/Hana-ame/ech-proxy/echproxy/ech"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("flutter/main.go 没有 import 本仓库的 echproxy/ech")
	}
}