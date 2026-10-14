# Issue #7：`NewServer` 在 TLS 证书加载失败时静默降级为明文 HTTP

* **定位**：`echproxy/server.go` (`NewServer` @ `0xba7cd4`)
* **问题描述**：
  在非 `-http` 模式下，当 `LoadTLSCert` 失败（如网络无法拉取远端证书或本地证书文件损坏）时，`NewServer` 仅打印一行 `"加载证书失败，将降级运行: %v"`，随后将 `IsTLS` 置为 `false`，在 `8443` 或 `443` 端口上**以明文 HTTP 启动服务**。客户端用 `https://` 访问 443/8443 时会收到大量 TLS 记录层错误，极难排查。
* **修复方案**：
  除非用户显式传入 `-http`，否则 TLS 证书（或本地 CA）初始化失败时应直接返回 `error` 终止启动，绝不静默在 HTTPS 端口上降级为明文 HTTP。
