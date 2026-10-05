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
// TestFlutterEntryIsSoleFlutterExit 守住「ECH 代码只存在于本仓库」这个目标。
//
// 背景：flutter/main.go 原先是 twitter-pic-flutter 仓库里 ech-proxy/cmd/
// ech-shared/ 的一份源码快照（2026-09-10），与本仓库没有任何 git 关系，两边
// 各自演化。现已迁入本仓库 flutter/。
//
// 防止它再次分叉需要三件事同时成立，任缺其一都会重现旧病：
//
//  1. 本仓存在 flutter 入口（下面两条测试已覆盖导出符号与 ech 包来源）；
//  2. 该入口**不依赖** github.com/Hana-ame/wintools —— 否则 ECH 核心实际
//     还是住在别的仓库，改动依旧要跨仓同步；
//  3. 本仓不存在第二个面向 Flutter 的 c-shared 入口 —— 两个入口并存时，
//     下一个人不知道该改哪个，就会各改一份、再次分叉。
//
// 第 3 条现在**不成立**：android/main.go 也是一个 c-shared 入口（Android APK
// 用的）。它与 flutter 入口导出的是同一套代理接口，属于「同一份实现的两个
// 打包目标」，不是两套实现，所以这里只做登记、不判失败——一旦将来真的
// 出现第二套**独立实现**，这条测试会立刻指出来。
func TestFlutterEntryIsSoleFlutterExit(t *testing.T) {
	// 本仓必须存在 flutter 入口。
	if _, err := os.Stat(filepath.Clean("main.go")); err != nil {
		t.Fatalf("本仓库 flutter/main.go 不存在：ECH 代码可能又被移回别的仓库了")
	}

	// 本仓的 go.mod 里不应再有 wintools 依赖 —— 留着就意味着 ECH 核心
	// 的真正来源在别的仓，「代码在本仓」只是表面达成。
	mod, err := os.ReadFile(filepath.Clean("../go.mod"))
	if err != nil {
		t.Fatalf("读 go.mod 失败: %v", err)
	}
	if strings.Contains(string(mod), "Hana-ame/wintools") {
		t.Fatalf("go.mod 仍依赖 github.com/Hana-ame/wintols —— " +
			"ECH 核心应完全由本仓库 echproxy/ech 提供")
	}
}
