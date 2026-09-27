# dlna-toolkit

一组 **DLNA / UPnP 调试工具**，外加一个在桌面运行 **arm64 Android `.so`** 的实验性加载器。

起初这些脚本是为了排查一个投屏兼容性问题（某个投屏 App 下手机会不会把高码率流交给接收端）
陆续攒出来的。排查结束后，把其中**与具体 App 无关**的部分整理成了这个仓库 ——
所以这里没有协议抓包结论，只有能复用的工具。

## 包含什么

| 模块 | 说明 | 依赖 |
|---|---|---|
| [`tools/dlna_cast.py`](tools/dlna_cast.py) | **通用 DLNA 控制器**：扮演发送端给任意 UPnP 渲染器发 `SetAVTransportURI` / `Play` / `Pause` / `Stop` / `GetTransportInfo` | 无（标准库） |
| [`tools/ssdp_scan.py`](tools/ssdp_scan.py) | **SSDP 扫描器**：组播发现 + 组播出不去时自动回落**单播全网段扫描**，并把设备描述里的身份字段打出来 | 无（标准库） |
| [`tools/http_proxy_capture.py`](tools/http_proxy_capture.py) | **只记录不解密的 HTTP / WebSocket 代理**，用来观察某个 App 到底请求了哪些地址（HTTPS 只记 CONNECT 隧道） | 无（标准库） |
| [`tools/report_proxy_session.py`](tools/report_proxy_session.py) | 把上面那个代理的日志汇总成一份人类可读的会话报告 | 无（标准库） |
| [`native-bridge/`](native-bridge/) | 用 **unicorn + capstone** 在桌面加载并调用 **arm64 Android `.so`**，自带迷你 ELF 加载器和假 `JNIEnv` | unicorn 等 |

## 快速开始

```bash
git clone https://github.com/<you>/dlna-toolkit.git
cd dlna-toolkit
```

### 1. 找到局域网里的 DLNA 设备

```bash
python tools/ssdp_scan.py
```

输出里每个设备会打印 `LOCATION`（设备描述 URL）、`friendlyName`、`manufacturer`、
`modelName`、`UDN`。**下一步要用 LOCATION。**

> 有些环境（多网卡、防火墙、交换机开了 IGMP snooping）组播根本出不去，
> 这时脚本会自动改用单播逐个 IP 探测，通常仍能扫到。

### 2. 给它投一个地址

```bash
python tools/dlna_cast.py \
    --base "http://192.168.1.50:36657/upnp/dev/<UDN>/desc" \
    --res  "http://example.com/live.m3u8" \
    --title "Test Stream" \
    --play
```

控制与查询：

```bash
python tools/dlna_cast.py --base "<desc-url>" --status
python tools/dlna_cast.py --base "<desc-url>" --pause
python tools/dlna_cast.py --base "<desc-url>" --stop
```

**它是排查投屏问题最直接的一把刀**：绕开 App，直接验证「是渲染器的问题，还是发送端的问题」。
比如 App 投不上、但 `dlna_cast.py` 投得上，那问题就在 App 那一侧。

### 3. 观察某个 App 的明文请求

```bash
python tools/http_proxy_capture.py --port 8888 --verbose
# 然后把被测设备的 Wi-Fi 代理设成「<本机IP>:8888」，操作一遍
python tools/report_proxy_session.py       # 出报告
```

只能看到**明文 HTTP 和 WebSocket**；HTTPS 只会记录 `CONNECT 目标:443`（不解密）。

### 4. native-bridge

```bash
cd native-bridge
pip install -r requirements.txt
python run.py --so /path/to/libfoo.so --list     # 先列一下有哪些 JNI 导出
python run.py --so /path/to/libfoo.so --call Java_com_example_Foo_bar
```

详见 [`native-bridge/README.md`](native-bridge/README.md)。

## 使用须知

* 这些工具会**主动连接你指定的设备**并发指令。请只在你拥有或获授权操作的网络上使用。
* `http_proxy_capture.py` 是**中间人位置的转发代理**，只做记录、不解密、不篡改；
  请勿在未告知他人的情况下抓取他人流量。
* `native-bridge` 需要你自己合法取得的 `.so`；本仓库不包含任何动态库、APK 或反编译产物。

## 为什么 native-bridge 会出现在这里

它和 DLNA 没关系，但同样来自那次排查：研究对象的核心逻辑在一个只有 arm64 版本的
Android 动态库里，而手上只有 Windows。用 unicorn 把 `.so` 跑起来比装模拟器省事得多，
这套「迷你 ELF 加载器 + 假 JNIEnv」后来被证明是通用技巧，就一起放进来了。

## License

[MIT](LICENSE)
