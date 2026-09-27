# native-bridge：在桌面上运行 arm64 Android `.so`

一个**迷你 ELF 加载器 + 用户态模拟层**，用 **unicorn**（CPU 模拟）和 **capstone**（反汇编）
把 arm64 的 Android 动态库在普通桌面系统上跑起来，然后像调普通 Python 函数一样调用它导出的
native 函数。

**不需要 Android 设备、不需要 qemu、不需要 root、不需要 C 编译器。**

## 解决的痛点

你手上有个 arm64 的 Android `.so`，里面的逻辑（签名、指纹、编解码…）你只想要它的计算结果：

* 装模拟器太重；
* 交叉编译 + qemu-user 要配 bionic sysroot，很容易卡在 libc 上；
* 反汇编重写成 Python 又太费时。

这套东西走的是第三条路：**让它自己跑，只是把操作系统那层用 Python 顶掉。**
用到什么 libc 函数、什么 JNI 调用，补什么。

## 组成

| 文件 | 作用 |
|---|---|
| `loader.py` | 迷你 ELF64 加载器：解析 `PT_LOAD`、映射段、处理 `R_AARCH64_RELATIVE / GLOB_DAT / JUMP_SLOT / ABS64` 重定位 | 
| `emu.py` | 用户态模拟层：上百个 libc 符号的 Python 实现、`syscall` 转发（`getrandom` / `clock_gettime`…）、locale 与宽字符、**假 JNIEnv** |
| `run.py` | 命令行入口：列出导出函数、调用指定函数 |

### 它是怎么工作的

guest 每次调用外部函数，PC 都会落在一张「钩子页」上；用 `UC_HOOK_CODE` 拦下来，
执行对应的 Python 实现，把返回值写进 `x0`，再把 PC 设回 `LR` —— 等价于一次 `ret`。
这样就不需要真的去链接任何 libc。

JNI 那一侧同理：`JNIEnv*` 在 ABI 上是指针的指针（`(*env)->NewStringUTF(...)`），
所以假 `JNIEnv` 返回一个**持有函数表地址的槽位**，而不是函数表本身。

## 用法

```bash
pip install -r requirements.txt

# 1) 看这个 .so 导出了哪些 JNI 函数
python run.py --so /path/to/libfoo.so --list

# 2) 调一个无参、返回字符串的函数
python run.py --so /path/to/libfoo.so --call Java_com_example_Foo_getVersion

# 3) 调一个接收字符串的函数
python run.py --so /path/to/libfoo.so --call Java_com_example_Foo_hash --arg hello

# 4) 只做装载自检
python run.py --so /path/to/libfoo.so --selftest
```

`.so` 需要你自己合法取得。**本仓库不包含任何动态库、APK 或反编译产物。**

## 已知的坑（都已在代码里处理）

* **栈保护字**：arm64 通过 `TPIDR_EL0` 取 TLS，必须布置好 TCB，
  否则一进函数就崩在 canary 上。
* **`__vsnprintf_chk` / `__snprintf_chk` 的参数布局和 `snprintf` 不同**（多 `flag` / `slen`），
  按 `snprintf` 处理会静默产出乱码 —— 这类错误最难查，因为不报错。
* **时间源**：如果 guest 用 `clock_gettime` 取时间，钩子必须返回真实时间。
  返回常量会让生成的、带时间戳的输出直接失效。
* **没实现的符号要显式报错**，带上符号名，而不是让模拟悄悄跑歪。

## 适用范围

* ✅ 纯计算的导出函数：哈希、签名、编解码、序列化。
* ⚠️ 依赖真实系统服务的逻辑（网络、文件、硬件）需要自己补对应的钩子。
* ❌ 不是通用 Android 运行时：带 ART / JNI 回调 / 需要完整 Bionic 的复杂逻辑跑不了。

仅供研究与学习使用。
