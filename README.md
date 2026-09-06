<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Platform-Android-green" alt="Android">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-green" alt="Encryption">
  <img src="https://img.shields.io/badge/Compression-zstd-brightgreen" alt="Compression">
  <img src="https://img.shields.io/badge/Release-v4.0.0-blueviolet" alt="Release">
</p>

<h1 align="center">🔀 shuffle-arc</h1>

<p align="center">
  <b>双密码加密归档工具</b> — 加密保内容 · 打乱保顺序 · 三倍快于 7z<br>
  <i>Two-password encrypted archiver: content protection + order secrecy + 3× faster than 7z</i>
</p>

<p align="center">
  <a href="#zh">📖 中文版</a> · <a href="#en">📖 English</a>
</p>

<br>

---

<a id="zh"></a>

<br>

<h2 align="center">📖 中文版</h2>

<br>

## 💡 为什么需要双密码？

传统加密压缩只有一个密码，拿到密码的人能看到**所有信息**——文件数量、文件名、大小、原始顺序。

```
┌────────────────────────────────────────────┐
│  7z / RAR：单一密码 → 全部可见              │
│  拿到密码 = 知道文件名叫什么、多少文件、顺序  │
└────────────────────────────────────────────┘
```

**shuffle-arc 不一样：** 两个独立密码，各管各的。

```
┌────────────────────────────────────────────┐
│  加密密码 → 保护文件内容（AES-256-GCM）      │
│  打乱密码 → 保护文件顺序（Fisher-Yates 置换） │
│  两者缺一不可，置换不入档，不解              │
└────────────────────────────────────────────┘
```

> 即使归档和加密密码同时泄露，攻击者也**看不出数据的原始排列**——顺序由独立的打乱密码保护，而这个密码不在文件里。

<br>

## ✨ 特性一览

| | 特性 | 说明 |
|:-:|---|---|
| 🔑 | **双密码** | `-e` 加密 + `-s` 打乱，独立派生（PBKDF2-HMAC-SHA256，300k 迭代） |
| 🔒 | **AES-256-GCM** | 每块独立加密，随机 nonce，AAD 绑定存储槽位，防调包换序 |
| 🔀 | **分块打乱** | Fisher-Yates + HMAC-SHA256，置换不入档，完全由打乱密码决定 |
| 📦 | **zstd 压缩** | 每块独立 zstd，默认 level 1，可用 `-z` 调整 |
| 🗑️ | **块级去重** | 相同块 sha256 去重，只存一份；相似文件只存差异块 |
| 📋 | **明文清单** | `list` 命令无需密码即可查看归档内容 |
| 🎯 | **随机访问** | `unpack --chunk N` 只解出唯一块池中第 N 块 |
| ⚡ | **3 倍快于 7z** | 实测打包 150 MB/s，vs 7z 的 46 MB/s |

<br>

## 📊 性能对比

> 实测 3.1 GB 数据（Unity 素材，含不可压缩文件）

| 维度 | 🚀 shuffle-arc | 📦 7z (LZMA2 -mx=1) |
|:---|---:|---:|
| **打包** | **20.7 s** (150 MB/s) | 67.8 s (46 MB/s) |
| 解压 | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) |
| 压缩比 | 56.7% | **49.5%** |

**定位：** 打包快 3 倍（zstd level 1），压缩比略逊 LZMA2。解压 7z 略快（shuffle-arc 多付出 AES 解密 + 认证 + 置换还原）。

> 7z 没有「打乱保护顺序 + 免密清单 + 分块去重」——**不同工具，解决不同问题。**

<br>

## 🚀 快速开始

### 免安装（Windows exe）

从 [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases) 下载：

| 文件 | 说明 |
|---|---|
| `shuffle-arc-gui.exe` | 🖥️ GUI 面板（英文），双击即用 |
| `shuffle-arc-gui-zh.exe` | 🖥️ GUI 面板（中文） |
| `shuffle-arc-cli.exe` | ⌨️ 命令行（英文） |
| `shuffle-arc-cli-zh.exe` | ⌨️ 命令行（中文） |
| `shuffle-arc-android-debug.apk` | 📱 Android 应用（Kotlin 原生，minSdk 24） |

### 从源码运行

```bash
pip install -r requirements.txt
python shuffle_arc.py --help
```

> 需要 Python 3.9+。GUI 版：`python shuffle_arc_gui.py`

### 语言版本

| 语言 | 脚本 | exe |
|:---|---:|---:|
| 🇬🇧 English | `shuffle_arc.py` / `shuffle_arc_gui.py` | `shuffle-arc-gui.exe` / `shuffle-arc-cli.exe` |
| 🇨🇳 中文 | `shuffle_arc_zh.py` / `shuffle_arc_gui_zh.py` | `shuffle-arc-gui-zh.exe` / `shuffle-arc-cli-zh.exe` |

<br>

## ⌨️ 用法

### CLI 命令

```bash
# 打包
python shuffle_arc.py pack -i <文件/目录> -o out.far -e 加密密码 -s 打乱密码

# 解包
python shuffle_arc.py unpack -i out.far -o <输出> -e 加密密码 -s 打乱密码

# 查看清单（无需密码）
python shuffle_arc.py list -i out.far

# 随机访问
python shuffle_arc.py unpack -i out.far --chunk 3 -e ... -s ... -o <输出>
```

### 参数

| 参数 | 默认 | 说明 |
|:---|---:|---|
| `-c, --chunk-size` | 4 MiB | 块大小 = 去重粒度 = 加密块大小 |
| `-z, --zstd-level` | 1 | 压缩级别（越大越慢，压缩比越高） |
| `-I, --iter` | 300000 | PBKDF2 迭代次数 |
| `-j, --jobs` | CPU 数 | 并行进程数 |

> 密码不传则交互输入。两个密码**必须不同**。不带参数启动进入交互向导。

<br>

## 🏗️ 归档格式（v3）

```
 ┌─────────────────────────────────────────────────┐
 │ 头部（明文，固定长度）                            │
 │ magic "SFAR1" · version=3 · chunk_size · n      │
 │ iterations · manifest_len · orig_len · salt1/2  │
 │ perm_check(HMAC) · table_offset                  │
 ├─────────────────────────────────────────────────┤
 │ 明文清单（manifest）                              │
 │ 每行: {size}\t{relpath}\t{ref0},{ref1},...       │
 ├─────────────────────────────────────────────────┤
 │ 加密区：唯一块池（按打乱置换乱序写入）              │
 │ 每块: zstd → AES-256-GCM（AAD 绑定槽位）          │
 ├─────────────────────────────────────────────────┤
 │ 条目表: nonce / cipher_len / orig_len / offset   │
 └─────────────────────────────────────────────────┘
```

- 置换（`perm`）完全由打乱密码派生，**不入档**
- 仅支持 v3 归档（v1 旧档支持已移除）

<br>

## 🔧 构建 & 测试

```bash
# 构建 exe
pyinstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
pyinstaller --onefile --name shuffle-arc-cli shuffle_arc.py

# 测试
python _test_v3.py        # 核心功能测试
python _test_v4_stream.py  # 流式解包 + v1 移除回归测试
python _bench.py          # 性能基准
```

<br>

## ⚠️ 注意事项

- 自定义格式，仅支持 v3（v1 旧档支持已移除）
- 清单明文会泄露文件名/大小/块数——有意为之，换来免密查看
- 解包已流式化（LRU 缓存，内存封顶）；打包仍全量读入内存，峰值 ≈ 源数据大小
- **打乱保顺序，不保内容**——两个密码都必须足够强
- **忘记任意一个密码 = 数据永久不可恢复**

## 🛡️ 安全加固（2026-09-05）

针对「恶意构造的归档」做了解包侧防御（清单是明文，攻击者可伪造条目）：

- **路径穿越（Zip Slip）已封堵**：清单里的文件名/目录若含 `..`、绝对路径或
  Windows 盘符（`C:`），解包直接拒绝——绝不会写出输出目录之外。
  并做二次防御：解析后的每个目标路径都校验仍在输出根目录内。
- **头字段 DoS 已封堵**：`read_archive_meta` 对归档头里攻击者可控的字段
  （块数、PBKDF2 迭代次数、块大小、清单长度、条目表偏移）做合理性上限校验，
  恶意归档无法再让解包者陷入天文数字的 PBKDF2 循环或超大内存分配。
- **越界块引用已拒绝**：清单引用不存在的唯一块时立即报错而非崩溃/错乱。
- **条目表不完整 / 载荷越界已拒绝**：截断或指向文件末尾之外的条目直接报错。
- **错误密码一律拒绝**：GCM 认证失败、乱序校验失败均优雅退出。

提示：v3 清单明文是设计取舍（免密 `list`）；若未来需要隐藏文件名/防篡改，
需引入认证保护与加密清单（格式将升级，勿混用版本）。

---

<br>

<a id="en"></a>

<h2 align="center">📖 English</h2>

<br>

## 💡 Why Two Passwords?

Traditional archives use a single password — anyone who has it sees **everything**: file names, counts, sizes, and the original order.

**shuffle-arc's approach:** two independent passwords, each with its own job.

```
┌────────────────────────────────────────────┐
│  Encryption password → protects content    │
│  Shuffle password    → protects order      │
│  Both required. Permutation never stored.  │
└────────────────────────────────────────────┘
```

Even if someone gets the archive *and* the encryption password, they can't reconstruct the original layout.

<br>

## ✨ Features

| | Feature | Description |
|:-:|---|---|
| 🔑 | **Dual passwords** | `-e` encryption + `-s` shuffle, independent key derivation (PBKDF2-HMAC-SHA256, 300k iterations) |
| 🔒 | **AES-256-GCM** | Per-chunk encryption, random nonce, AAD binds slot position |
| 🔀 | **Chunk shuffling** | Fisher-Yates + HMAC-SHA256, never stored on disk |
| 📦 | **zstd compression** | Per-chunk zstd, level adjustable via `-z` |
| 🗑️ | **Block-level dedup** | Identical chunks stored once via sha256 |
| 📋 | **Plaintext manifest** | `list` command shows contents without a password |
| 🎯 | **Random access** | `unpack --chunk N` decrypts only the N-th chunk |
| ⚡ | **3× faster than 7z** | ~150 MB/s pack speed vs 7z's 46 MB/s |

<br>

## 📊 Performance

> 3.1 GB real-world data (Unity assets, partially incompressible)

| Metric | 🚀 shuffle-arc | 📦 7z (LZMA2 -mx=1) |
|:---|---:|---:|
| **Pack** | **20.7 s** (150 MB/s) | 67.8 s (46 MB/s) |
| Unpack | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) |
| Ratio | 56.7% | **49.5%** |

> 7z can't do order protection, password-free listing, or block-level dedup — **different tools, different jobs.**

<br>

## 🚀 Quick Start

### Windows exe

Download from [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases):

| File | Description |
|---|---|
| `shuffle-arc.exe` | 🖥️ GUI launcher |
| `shuffle-arc-cli.exe` | ⌨️ CLI (English) |
| `shuffle-arc-cli-zh.exe` | ⌨️ CLI (中文) |

### From source

```bash
pip install -r requirements.txt
python shuffle_arc.py --help
```

> Requires Python 3.9+. GUI: `python shuffle_arc_gui.py`

### Language variants

| Variant | Script | exe |
|:---|---:|---:|
| 🇬🇧 English | `shuffle_arc.py` / `shuffle_arc_gui.py` | `shuffle-arc-gui.exe` / `shuffle-arc-cli.exe` |
| 🇨🇳 中文 | `shuffle_arc_zh.py` / `shuffle_arc_gui_zh.py` | `shuffle-arc-gui-zh.exe` / `shuffle-arc-cli-zh.exe` |

<br>

## ⌨️ Usage

```bash
# pack
python shuffle_arc.py pack -i <path> -o out.far -e encpassword -s shuffpass

# unpack
python shuffle_arc.py unpack -i out.far -o <out> -e encpassword -s shuffpass

# list (no password needed)
python shuffle_arc.py list -i out.far

# random access
python shuffle_arc.py unpack -i out.far --chunk 3 -e ... -s ... -o <out>
```

### Options

| Option | Default | Description |
|:---|---:|---|
| `-c, --chunk-size` | 4 MiB | chunk size = dedup granularity = encryption block |
| `-z, --zstd-level` | 1 | zstd compression level |
| `-I, --iter` | 300000 | PBKDF2 iterations |
| `-j, --jobs` | CPU count | parallel processes |

> Passwords are prompted if omitted. The two passwords **must be different**. Run with no arguments for the interactive wizard.

<br>

## 🏗️ Archive Format (v3)

```
 ┌─────────────────────────────────────────────────┐
 │ header (plaintext, fixed length)                  │
 │ magic "SFAR1", version=3, chunk_size, n, ...      │
 │ iterations, manifest_len, orig_len, salt1, salt2  │
 │ perm_check(HMAC), table_offset                    │
 ├─────────────────────────────────────────────────┤
 │ plaintext manifest                                │
 │   {size}\t{relpath}\t{ref0},{ref1},...           │
 ├─────────────────────────────────────────────────┤
 │ encrypted unique-chunk pool (permuted order)      │
 │   each chunk: zstd → AES-256-GCM                 │
 ├─────────────────────────────────────────────────┤
 │ entry table: nonce / cipher_len / orig_len / off  │
 └─────────────────────────────────────────────────┘
```

- Permutation is derived from the shuffle password — **never stored**
- v3 only (v1 legacy support removed)

<br>

## 🔧 Build & Test

```bash
pyinstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
pyinstaller --onefile --name shuffle-arc-cli shuffle_arc.py

python _test_v3.py        # core functionality tests
python _test_v4_stream.py  # streaming unpack + v1-removal regression
python _bench.py          # performance benchmark
```

<br>

## ⚠️ Notes

- Custom format; v3 only (v1 legacy support removed)
- Plaintext manifest leaks filenames/sizes/chunk counts (trade-off for password-free listing)
- Unpack is streaming (LRU cache, bounded memory); pack still reads fully into memory, peak ≈ source size
- **Shuffle protects order, not content** — use strong random passwords
- **Forgetting either password = permanent data loss**

## 🛡️ Security Hardening (2026-09-05)

Defenses on the unpack side against crafted archives (the manifest is plaintext, so entries can be forged):

- **Zip-slip blocked**: filenames/directories in the manifest containing `..`, absolute
  paths, or Windows drive letters (`C:`) are rejected outright — extraction can never
  write outside the requested output directory. Defense-in-depth: every resolved target
  is verified to stay under the canonical output root.
- **Header-field DoS blocked**: `read_archive_meta` sanity-limits attacker-controlled
  header fields (chunk count, PBKDF2 iterations, chunk size, manifest length, table
  offset), so a crafted archive cannot force absurd KDF loops or huge allocations.
- **Out-of-range chunk refs rejected**: manifest references to nonexistent unique chunks
  fail fast instead of crashing/misassembling.
- **Truncated entry table / out-of-bounds payload rejected**.
- **Wrong passwords always fail**: GCM auth and permutation checks exit cleanly.

Note: the plaintext v3 manifest is an intentional design trade-off (password-free
`list`); hiding filenames or adding tamper-resistance requires an authenticated,
encrypted manifest — a format upgrade that will not interoperate with v3.

---

<br>

<p align="center">
  <sub>Made with ❤️ by one person who thinks encryption should do more than just hide content</sub>
</p>