# ClashVPN for Windows 10 Mobile

Clash 配置格式的 UWP VPN 客户端，目标平台：Windows 10 Mobile（Lumia 950 / Build 10240+）。

---

## 项目结构

```
ClashVPN/
├── ClashVPN/                   ← 主 UWP 项目（前台 App）
│   ├── Models/
│   │   └── ClashModels.cs      ← Clash 数据模型
│   ├── Services/
│   │   ├── ClashConfigParser.cs  ← YAML 解析器（手写，YamlDotNet RepresentationModel）
│   │   └── VpnManager.cs         ← VPN 配置注册 / 连接管理 / 延迟测试
│   ├── Pages/
│   │   ├── HomePage.xaml(.cs)    ← 主页：连接开关 + 状态 + 流量
│   │   ├── NodesPage.xaml(.cs)   ← 节点列表 + 延迟测试 + 选择
│   │   └── ConfigPage.xaml(.cs)  ← 配置导入（文件 / URL）
│   ├── AppState.cs             ← 全局状态单例
│   ├── App.xaml(.cs)           ← 启动入口，加载缓存配置
│   └── Package.appxmanifest    ← VPN Plugin 扩展声明
│
└── ClashVPN.Plugin/            ← Windows Runtime Component（VPN 插件主体）
    ├── ClashVpnPlugin.cs       ← 实现 IVpnPlugin，包含 Connect/Disconnect/Encapsulate/Decapsulate
    ├── Socks5Client.cs         ← SOCKS5 协议客户端（RFC 1928 + RFC 1929）
    └── TcpSessionTracker.cs    ← TCP 会话追踪 + IP 包解析/构造
```

---

## 环境要求

| 工具 | 版本 |
|------|------|
| Visual Studio | 2015 Update 3（或 2017） |
| Windows 10 SDK | 10240 或更高 |
| Windows Mobile Extensions | 必须安装 |
| NuGet 包 | YamlDotNet（版本 ≤ 8.x，确认支持 UWP/ARM） |

---

## 配置步骤

### 1. 创建两个项目

在 Visual Studio 中：
- **ClashVPN**：`新建 → 通用 Windows → 空白应用（Universal Windows）`
- **ClashVPN.Plugin**：`新建 → Windows Universal → Windows 运行时组件`

### 2. 添加 YamlDotNet NuGet 包

仅在 **ClashVPN** 项目中安装：
```
Install-Package YamlDotNet -Version 8.1.2
```

### 3. Plugin 项目引用

- **ClashVPN** 引用 **ClashVPN.Plugin**（Add Reference → Projects）

### 4. 修改 Package.appxmanifest

在图形界面 `Declarations` 选项卡中添加：
- Declaration：`VPN Plugin`
- Entry Point：`ClashVPN.Plugin.ClashVpnPlugin`

在 `Capabilities` 中勾选：
- `Internet (Client & Server)`
- `Private Networks (Client & Server)`

### 5. 部署目标

- Platform：`ARM`
- Target：`Device`（USB 连接 Lumia 950）

---

## 当前实现进度

### ✅ 已完成
- [x] Clash YAML 解析（proxies / proxy-groups / rules）
- [x] 支持节点类型：`ss` / `vmess` / `trojan` / `socks5` / `http`
- [x] 规则匹配：`DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `IP-CIDR` / `MATCH`
- [x] SOCKS5 客户端（RFC 1928/1929，含用户名密码认证）
- [x] VPN Plugin 框架（`IVpnPlugin` 实现骨架）
- [x] TCP 会话追踪器（五元组 → SOCKS5 连接映射）
- [x] UI：主页 / 节点列表 / 配置导入
- [x] 延迟测试（TCP Connect 耗时）
- [x] 从文件或 URL 导入配置，本地缓存

### 🚧 待实现
- [ ] **Shadowsocks 加密**：需要 `AEAD-AES-128-GCM` / `ChaCha20-Poly1305` 实现
  - 推荐用 BouncyCastle.UWP 或手写 ChaCha20
- [ ] **VMess 协议**：V2Ray 私有协议，需移植 C# 实现
- [ ] **Trojan**：TLS 包装，Windows.Networking.Sockets 的 `SslProtocols` 支持
- [ ] **TCP SEQ/ACK 精确管理**：当前 BuildTcpPacket 使用固定 SEQ=1，
       实际需要维护每个会话的序列号状态机
- [ ] **DNS 拦截**：对 UDP:53 包做 DoH 转发 + 规则匹配
- [ ] **GeoIP 数据库**：集成 MaxMind GeoLite2-Country（mmdb 解析）
- [ ] **流量统计**：Plugin → App 的 LocalSettings 通信管道

---

## 关键注意事项

### VPN Plugin 的 TCP 重写问题

当前 `TcpSessionTracker` 里的 IP 包构造（`BuildTcpPacket`）是简化版，
**SEQ/ACK 固定为 1**，实际上需要维护每个 TCP 会话的：
- 初始序列号（ISN，通常随机）
- 发送序列号（SND.NXT）
- 接收确认号（RCV.NXT）

这是实现正确性的关键，否则系统协议栈会 RST 连接。

### 替代方案：TUN 模式

如果上述 TCP 重写太复杂，可以考虑 **SOCKS5 本地代理模式**：
- 不使用 VPN Plugin
- 在 App 内启动一个本地 SOCKS5 服务器（监听 127.0.0.1:1080）
- 需要代理的应用手动配置代理地址
- 缺点：不能全局透明代理

---

## License

MIT
