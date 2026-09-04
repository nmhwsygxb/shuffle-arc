<div align="center">

# 🔀 shuffle-arc

**双密码「分块打乱加密压缩」归档工具** · **Dual-password chunked shuffle-encrypt archive tool**

先压缩加密，再把密文块按「打乱密码」派生的置换乱序写入归档——即使归档和加密密码同时泄露，攻击者也看不出内容的原始顺序。

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![Release](https://img.shields.io/badge/release-v3.0.0-blueviolet)
![Zero deps](https://img.shields.io/badge/zip%2B7z%20alternative-✓-brightgreen)

**🇨🇳 [中文](#-中文) · 🇬🇧 [English](#-english)**

</div>

---

<a id="zh"></a>
# 🇨🇳 中文

## 💡 它解决什么问题？

普通压缩工具（zip / 7z）即使加了密码，归档内部的结构也一览无余：**哪个文件大、有多少块、内容排列顺序**全都暴露。shuffle-arc 更进一步——它把密文块按第二个密码派生的置换**打乱顺序**再写入归档：

```
文件/目录 → 切块 → 逐块 zstd 压缩 → 逐块 AES-256-GCM 加密 → 按打乱密码置换乱序写入
```

> 🛡️ **两个完全独立的密码**
> - **加密密码 `-e`**：保护内容
> - **打乱密码 `-s`**：保护顺序（置换不入档，完全由密码派生）
>
> ⚠️ **安全提醒**：打乱保护的是【顺序】，不是【内容】。两个密码都必须足够强，「弱加密 + 打乱」并不能防暴力破解。**忘记任意一个密码 = 数据永久不可恢复。**

## ✨ 特性

| 🚀 特性 | 说明 |
|---|---|
| 🔑 **双密码** | `-e` 加密密码 + `-s` 打乱密码，独立派生两把密钥（PBKDF2-HMAC-SHA256，默认 300k 迭代） |
| 🔒 **强加密** | 每块独立 AES-256-GCM（随机 nonce，AAD 绑定存储槽位，防调包 / 换序） |
| 🗜️ **快速压缩** | 每块独立 zstd（默认 level 1，打包速度约为 7z LZMA2 的 **3 倍**） |
| 🎲 **顺序打乱** | Fisher-Yates + HMAC-SHA256 伪随机置换，置换**不入档**，完全由打乱密码决定 |
| ♻️ **分块去重** | 按块 sha256 去重：相同块只存一份，相似文件只存差异块 |
| 📋 **明文清单** | v3 起清单明文存储，`list` 命令**无需密码**即可查看归档内文件 |
| ⚡ **随机访问** | `unpack --chunk N` 只解出唯一块池中的第 N 块 |
| 🕰️ **向后兼容** | 可解 v1 旧档（旧档清单加密于第 0 块） |
| 🛡️ **防覆盖** | 输出文件已存在时自动改名 `name (1).far`，绝不静默覆盖 |

## 🚀 快速开始

### 方式一：免安装（Windows）

从 [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases) 下载：

| 文件 | 用途 |
|---|---|
| `shuffle-arc-gui.exe` / `shuffle-arc-gui-zh.exe` | 🖥️ GUI 面板（双击即用，中/英） |
| `shuffle-arc-cli.exe` / `shuffle-arc-cli-zh.exe` | ⌨️ 命令行（中/英） |
| `shuffle-arc-v3.zip` | 📦 全家桶：exe + 源码 + README |

### 方式二：从源码运行

```bash
pip install -r requirements.txt    # zstandard, pycryptodome
python shuffle_arc.py --help        # 或 python shuffle_arc_gui.py 打开图形界面
```

需要 Python **3.9+**（Windows 下用 `py -3.14` 亦可）。

## 📖 使用指南

### CLI 打包 / 解包 / 查看

```bash
# 📦 打包（文件或目录 → .far 归档）
python shuffle_arc.py pack -i <文件或目录> -o out.far -e 加密密码 -s 打乱密码

# 📂 解包（单文件归档 -o 为文件路径；多文件 -o 为输出目录）
python shuffle_arc.py unpack -i out.far -o <输出> -e 加密密码 -s 打乱密码

# 📋 查看归档清单（无需密码，v3 明文清单）
python shuffle_arc.py list -i out.far

# ⚡ 随机访问：只解出唯一块池中的原始第 N 块
python shuffle_arc.py unpack -i out.far -o <输出> -e ... -s ... --chunk 3
```

**参数一览：**

| 参数 | 默认 | 说明 |
|---|---|---|
| `-c, --chunk-size` | 4 MiB | 块大小 = 去重粒度 = 加密块大小 |
| `-z, --zstd-level` | 1 | zstd 压缩级别（越大压缩比越高、越慢） |
| `-I, --iter` | 300000 | PBKDF2 迭代次数 |
| `-j, --jobs` | CPU 数 | 并行进程数 |

> 💡 密码不传则交互输入（`input()` 明文回显；getpass 在冻结 exe 中不可用）。**两个密码必须不同。**

### 🖥️ GUI 面板

`shuffle-arc-gui.exe` 三步完成：**选文件 → 设双密码 → 进度条**。

不带参数启动（含双击 exe）会进入交互向导：`1=打包 2=解包 3=查看清单 q=退出`。

## ⚙️ 工作原理（归档格式 v3）

```
┌─ 头部（明文，固定长度）────────────────────────────┐
│ magic "SFAR1" · version=3 · chunk_size · n(唯一块数)  │
│ iterations · manifest_len · orig_len · salt1 · salt2 │
│ perm_check(HMAC) · table_offset                       │
├─ 明文清单（manifest）───────────────────────────────┤
│ 每行: {size}\t{relpath}\t{ref0},{ref1},...            │
├─ 加密区：唯一块池（按打乱置换乱序写入）────────────────┤
│ 每块: zstd 压缩 → AES-256-GCM（AAD 绑定槽位）          │
└─ 条目表：nonce / cipher_len / orig_len / payload_offset ┘
```

- 置换（`perm`）完全由打乱密码派生，**不入档**；`perm[slot]` = 存储于该槽位的原始块下标
- v1 旧档：manifest 为加密的第 0 块（`unpack` 自动识别版本）

## 📊 性能对比（3.1 GB 数据实测）

| 维度 | shuffle-arc | 7z (LZMA2 -mx=1) |
|---|---|---|
| 压缩 | **20.7s（150 MB/s）** 🏆 | 67.8s（46 MB/s） |
| 解压 | 41.8s（74 MB/s） | **36.1s（86 MB/s）** 🏆 |
| 压缩比 | 56.7% | **49.5%** 🏆 |

**定位**：主打**压缩快 3 倍**（zstd level 1），压缩比略逊 LZMA2（设计取舍，可用 `-z` 调高级别）。解压 7z 略快（shuffle-arc 多付出 AES 解密 + 认证 + 置换还原）。功能上 7z 没有「打乱保护顺序 + 免密清单 + 分块去重」。

## 🛠️ 开发 & 构建

```bash
# GUI（windowed，无控制台窗口）
py -3.14 -m PyInstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
# CLI（console）
py -3.14 -m PyInstaller --onefile --name shuffle-arc-cli shuffle_arc.py
```

## 🧪 测试

```bash
python _test_v3.py        # v3 功能：去重 / 还原 / list / 随机访问 / 错误密码
python _test_v1_gui.py    # v1 兼容 + GUI prebuilt 路径
python _bench.py          # 性能基准（D 盘临时目录，结束自动清理）
```

## ⚠️ 已知限制

- 自定义格式，无跨版本兼容承诺（v3 可解 v1；将来新版本会保留向后兼容）
- 清单明文会泄露文件名 / 大小 / 块数（为免密 list 做的权衡，用户已知并接受）
- 大文件全量读入内存（打包 / 解包峰值内存 ≈ 源数据大小）
- 打乱保护顺序不保护内容——请使用强随机密码

## 📄 License

[MIT](LICENSE) © 2026 nmhwsygxb

---

<a id="en"></a>
# 🇬🇧 English

A CLI/GUI archiver that compresses and encrypts files, then **shuffles the ciphertext blocks** using a permutation derived from a second, independent password.

```
files/dir → split into chunks → zstd-compress each → AES-256-GCM encrypt each → write in permuted order
```

Even if someone gets the archive *and* the encryption password, they cannot reconstruct the original data order — the order is protected by the separate shuffle password. **The permutation is never stored; it is derived from the shuffle password every time.**

**Two independent passwords, always different:**
- **encryption password** (`-e`) — protects content
- **shuffle password** (`-s`) — protects order

> ⚠️ **Warning:** shuffling protects *order*, not *content*. Both passwords must be strong. Forgetting either password means permanent data loss.

## What makes it different

| | shuffle-arc | 7z / zip |
|---|---|---|
| Encryption | AES-256-GCM per chunk | ✅ |
| Order protection | keyed permutation, **never stored** | ❌ |
| Dedup | identical chunks stored once | ❌ |
| Password-free listing | plaintext manifest, `list` | depends |
| Random access | `unpack --chunk N` | partial |

It is not a 7z replacement. It is for the case where the *layout of the data inside the archive* must stay secret too — which files are big, how many chunks, or that a "file" is actually a stream of repeated blocks.

## Quick start

**Windows (no install):** grab the GUI/CLI exe from the [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases) page.

**From source (Python 3.9+):**

```bash
pip install -r requirements.txt    # zstandard, pycryptodome
python shuffle_arc.py --help
```

## Usage

```bash
# pack a file or directory
python shuffle_arc.py pack -i <path> -o out.far -e encpassword -s shuffpass

# unpack (single-file archive: -o is a file; multi-file: -o is a directory)
python shuffle_arc.py unpack -i out.far -o <out> -e encpassword -s shuffpass

# list archive contents — no password needed (v3 plaintext manifest)
python shuffle_arc.py list -i out.far

# random access: decrypt only chunk N of the unique block pool
python shuffle_arc.py unpack -i out.far -o <out> -e ... -s ... --chunk 3
```

| Option | Default | Meaning |
|---|---|---|
| `-c, --chunk-size` | 4 MiB | chunk size = dedup granularity = encryption block |
| `-z, --zstd-level` | 1 | zstd level (higher = smaller but slower) |
| `-I, --iter` | 300000 | PBKDF2 iterations |
| `-j, --jobs` | CPU count | parallel processes |

Run with **no arguments** for the interactive wizard (`1=pack 2=unpack 3=list`). The GUI is a single window: pick source → set the two passwords → progress bar.

## Performance (3.1 GB measured)

| | shuffle-arc | 7z (LZMA2, -mx=1) |
|---|---|---|
| pack | **20.7 s** (150 MB/s) 🏆 | 67.8 s (46 MB/s) |
| unpack | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) 🏆 |
| size | 56.7% | **49.5%** 🏆 |

Packing is ~3× faster than 7z at default zstd level 1; 7z compresses somewhat better (LZMA2). Raise `-z` for a better ratio.

## Build & test

```bash
py -3.14 -m PyInstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
py -3.14 -m PyInstaller --onefile --name shuffle-arc-cli shuffle_arc.py

python _test_v3.py        # dedup / round-trip / list / random access / wrong password
python _test_v1_gui.py    # v1 compat + GUI prebuilt path
```

## Limitations

- Custom format; no forward-compatibility promise (v3 reads v1; future versions will keep reading old ones).
- The plaintext manifest leaks filenames / sizes / chunk counts (deliberate trade-off for password-free listing).
- Files are read fully into memory; peak memory ≈ source size.
- Use strong random passwords. Order protection ≠ content protection.

## License

[MIT](LICENSE) © 2026 nmhwsygxb
