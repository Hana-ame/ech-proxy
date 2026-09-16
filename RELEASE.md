### ech-proxy（Windows / Linux 桌面版）

ECH (Encrypted Client Hello) 域前置反向代理，多上游路由：

- TLS 模式监听 127.0.0.1:8443，启动成功后自动打开浏览器访问入口列表 https://l.moonchan.xyz:8443
- 启动 banner 的入口域名带监听端口，与浏览器访问地址一致
- 入口示例：twimg.l.moonchan.xyz:8443（Twitter CDN）、asmr.l.moonchan.xyz:8443（ASMR Online）、iwara.l.moonchan.xyz:8443（Iwara）、dlsite.l.moonchan.xyz:8443（DLsite）等，完整列表见启动 banner 与入口页
- 通配子域名入口：iwara-* / dlsite-* / asmr-* 映射到对应上游子域
- --http 进入本地 HTTP 代理模式（无 TLS），-addr 自定义监听地址，-v 打开每请求日志
