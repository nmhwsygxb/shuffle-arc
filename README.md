<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-green" alt="Encryption">
  <img src="https://img.shields.io/badge/Compression-zstd-brightgreen" alt="Compression">
  <img src="https://img.shields.io/badge/Release-v5.0.1-blueviolet" alt="Release">
</p>

<h1 align="center">🔀 shuffle-arc</h1>

<p align="center">
  <b>双密码加密归档工具</b> — 加密保内容 · 打乱保顺序 · 去重省空间<br>
  <i>Two-password encrypted archiver: content protection + order secrecy + block-level dedup</i>
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

> 即使归档和加密密码同时泄露，攻击者也**看不出数据的原始排列**——顺序由独立的打乱密码保护，而这个密码不在文件里。分块置换将内容切成 4 MiB 碎块乱序存放，顺序信息完全是"档案外部"的秘密。

<br>

## ✨ 特性一览（v5.0.1）

| | 特性 | 说明 |
|:-:|---|---|
| 🔑 | **双密码** | `-e` 加密 + `-s` 打乱，独立派生（PBKDF2-HMAC-SHA256，300k 迭代） |
| 🔒 | **AES-256-GCM** | 每块独立加密，随机 nonce，AAD 绑定存储槽位，防调包换序 |
| 🔀 | **分块打乱** | Fisher-Yates + HMAC-SHA256，置换不入档，完全由打乱密码决定 |
| 📦 | **zstd 压缩** | 每块独立 zstd，CLI 默认 level 1（`-z` 调整）；GUI 可选 1/3/6/9/19 |
| 🗑️ | **块级去重** | 相同块 sha256 去重，只存一份；相似文件只存差异块 —— 7z/RAR **没有**这项能力 |
| 📋 | **明文清单** | `list` 命令无需密码即可查看归档内容（文件名+大小+块引用） |
| 🎯 | **随机访问** | `unpack --chunk N` 只解出唯一块池中第 N 块 —— 7z solid 归档做不到 |
| ⚡ | **并行流式解包** | v5 有界预取：大归档也能并行，同步解密 → 0，主线程几乎不等待（解 3GB 快约 23%） |
| 🧵 | **GUI 多核打包** | v5 GUI 默认使用全部 CPU 核心；压缩级别 zstd 1/3/6/9/19 可选 |
| 🐞 | **unpack --debug** | 打印 IO/解密/预取统计，定位卡顿用 |
| 🏷️ | **CLI --version** | 输出 `shuffle-arc 5.0.1 (disk format v3)` |

<br>

## 🔀 和其他工具有什么不同？

不是"更快的 7-Zip"，而是功能组合不同的工具：

| 能力 | shuffle-arc | 7-Zip | restic / borg | perfect-shuffle-crypto |
|:---|---:|:---:|:---:|:---:|
| 加密压缩 | ✅ | ✅ | ✅ | 仅演示 |
| **块级去重**（相似内容只存差异） | ✅ | ❌ | ✅（备份维度） | ❌ |
| **随机访问单块**（不碰其他数据） | ✅ | ⚠️ solid 归档需解前缀 | ✅ | ❌ |
| **顺序保密**（乱序存放，置换密码独立） | ✅ | ❌ | ❌ | 概念 |
| **AAD 绑定槽位**（防调包换序） | ✅ | 仅 CRC 校验 | ✅ | ❌ |
| 免密浏览归档清单 | ✅（`list`） | ⚠️ 不加密文件名可近似 | ❌ | ❌ |
| 单文件加密归档（非备份仓库） | ✅ | ✅ | ❌ | ✅ |

**结论：** 7-Zip 解决"压缩 + 加密"；restic 解决"增量备份"；shuffle-arc 解决的是 **"一个加密归档文件，内容、顺序、重复块三位一体保护"**。

<br>

## 🎯 什么时候用它？

- 📸 **照片/视频库归档**：大量相似内容，块级去重省空间，想随时 `list` 看里面有什么。
- 📁 **版本化文档集**：一个文件改了 20 版，整包重压浪费空间——去重只存差异块。
- 🔐 **需要"内容密码"和"顺序密码"分开保管的场景**：交给别人内容密码也看不到数据结构。
- 🖥️ **存档免安装 GUI 使用**：四个 exe 双击即用（中/英文 × GUI/CLI），无需 Python。
- ⏪ **旧档随时抽块**：`--chunk N` 随机访问，不整包解压。

不适合：追求极限压缩率的场景请用 7-Zip LZMA2；需要增量快照备份请用 restic/borg。

<br>

## 📊 性能对比

### 打包吞吐（3.1 GB 实测，Unity 素材含不可压缩文件）

| 维度 | 🚀 shuffle-arc (zstd L1) | 📦 7z (LZMA2 -mx=1) |
|:---|---:|---:|
| **打包** | **20.7 s** (150 MB/s) | 67.8 s (46 MB/s) |
| 解压 | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) |
| 压缩比 | 56.7% | **49.5%** |

> 打包快约 3 倍是因为默认 zstd level 1（7-Zip 21.02+ 也支持 zstd，速度不是本工具的护城河——**去重与随机访问才是**）。解压 7z 略快：shuffle-arc 多付出 AES 解密 + 认证 + 置换还原。

### v5 并行流式解包（3GB 归档 A/B，同负载）

| 指标 | v4 旧版 | v5.0.1 |
|:---|---:|---:|
| 解包耗时 | 40.6 s | **31.2 s（+23%）** |
| 同步解密次数 | 715 | **0** |
| 主线程等待 | 3 s | 0.4 s |
| 内存峰值 | — | 431 MiB（与归档大小无关） |

> v5 的预取预算只统计"在途"字节；块仅在仍有后续引用时驻留缓存。9.73GB / 894 文件实测：流式打包无换页，解包全出，抽样 SHA-256 全对。

<br>

## 🚀 快速开始

### 免安装（Windows exe）

从 [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases) 下载 v5.0.1：

| 文件 | 说明 |
|---|---|
| `shuffle-arc-gui.exe` | 🖥️ GUI 面板（英文），双击即用 |
| `shuffle-arc-gui-zh.exe` | 🖥️ GUI 面板（中文） |
| `shuffle-arc-cli.exe` | ⌨️ 命令行（英文） |
| `shuffle-arc-cli-zh.exe` | ⌨️ 命令行（中文） |

> 早期版本（v3/v4）发布过 `shuffle-arc-android-debug.apk` 实验性 Android 应用（Kotlin 原生，minSdk 24），可在历史 release 中找到。

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

# 随机访问单块
python shuffle_arc.py unpack -i out.far --chunk 3 -e ... -s ... -o <输出>

# 版本
python shuffle_arc.py --version

# 解包诊断（IO/解密/预取统计）
python shuffle_arc.py unpack -i out.far ... --debug
```

### 参数

| 参数 | 默认 | 说明 |
|:---|---:|---|
| `-c, --chunk-size` | 4 MiB | 块大小 = 去重粒度 = 加密块大小 |
| `-z, --zstd-level` | 1 | 压缩级别（CLI；越大越慢，压缩比越高）。GUI 可选 1/3/6/9/19 |
| `-I, --iter` | 300000 | PBKDF2 迭代次数 |
| `-j, --jobs` | CPU 数 | 并行进程数 |
| `--version` | — | 输出版本与磁盘格式 |
| `--debug` | — | 解包时打印 IO/解密/预取统计 |

> 密码不传则交互输入。两个密码**必须不同**。不带参数启动进入交互向导。

<br>

## 🏗️ 归档格式（v3 / v5 兼容）

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

- **磁盘格式自 v3 起未变**：v5 可解 v3/v4 归档，v4 也可解 v5 归档（双向兼容）。
- 置换（`perm`）完全由打乱密码派生，**不入档**。
- v5 的并行解包只改变读盘/预取策略，不改变字节格式。

<br>

## 🔧 构建 & 测试

```bash
# 构建 exe（GUI 与 CLI 各有中英两版）
pyinstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
pyinstaller --onefile --name shuffle-arc-cli shuffle_arc.py

# 回归测试（含随机 roundtrip、去重、流式打包、v4↔v5 兼容、免密 list）
python _test_v5.py
```

<br>

## ⚠️ 注意事项

- 自定义格式；v5 兼容 v3/v4，v1 旧档支持已移除。
- 清单明文会泄露文件名/大小/块数——有意为之，换来免密查看。
- **打乱保顺序，不保内容**——两个密码都必须足够强。
- **忘记任意一个密码 = 数据永久不可恢复**。

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

Even if someone gets the archive *and* the encryption password, they can't reconstruct the original layout. Content is cut into 4 MiB chunks and stored in permuted order — the ordering is a secret that lives outside the file.

<br>

## ✨ Features (v5.0.1)

| | Feature | Description |
|:-:|---|---|
| 🔑 | **Dual passwords** | `-e` encryption + `-s` shuffle, independent key derivation (PBKDF2-HMAC-SHA256, 300k iterations) |
| 🔒 | **AES-256-GCM** | Per-chunk encryption, random nonce, AAD binds slot position |
| 🔀 | **Chunk shuffling** | Fisher-Yates + HMAC-SHA256, never stored on disk |
| 📦 | **zstd compression** | Per-chunk zstd; CLI default level 1 (`-z`), GUI 1/3/6/9/19 |
| 🗑️ | **Block-level dedup** | Identical chunks stored once via sha256; similar files keep only diff chunks — **not offered by 7-Zip/RAR** |
| 📋 | **Plaintext manifest** | `list` command shows contents without a password |
| 🎯 | **Random access** | `unpack --chunk N` decrypts only the N-th unique chunk — impossible with 7z solid archives |
| ⚡ | **Parallel streaming unpack** | v5 bounded prefetch: parallel even for huge archives, 0 synchronous decryptions (~23% faster on 3 GB) |
| 🧵 | **GUI multi-core pack** | v5 GUI uses all CPU cores; zstd level 1/3/6/9/19 selectable |
| 🐞 | **unpack --debug** | Prints IO/decrypt/prefetch stats to diagnose stalls |
| 🏷️ | **CLI --version** | Prints `shuffle-arc 5.0.1 (disk format v3)` |

<br>

## 🔀 How is this different?

Not "a faster 7-Zip" — a different feature combination:

| Capability | shuffle-arc | 7-Zip | restic / borg | perfect-shuffle-crypto |
|:---|---:|:---:|:---:|:---:|
| Encrypted compression | ✅ | ✅ | ✅ | demo only |
| **Block-level dedup** (similar content → diff chunks) | ✅ | ❌ | ✅ (backup scope) | ❌ |
| **Random single-chunk access** | ✅ | ⚠️ solid needs prefix | ✅ | ❌ |
| **Order secrecy** (permuted storage, independent password) | ✅ | ❌ | ❌ | concept |
| **AAD-bound slots** (anti-swap/reorder) | ✅ | CRC only | ✅ | ❌ |
| Password-free archive listing | ✅ (`list`) | ⚠️ if filenames unencrypted | ❌ | ❌ |
| Single-file encrypted archive (not a backup repo) | ✅ | ✅ | ❌ | ✅ |

**Bottom line:** 7-Zip does "compress + encrypt"; restic/borg do "incremental backup"; shuffle-arc does **one encrypted archive file that protects content, order, and duplicate blocks together**.

<br>

## 🎯 When to use it

- 📸 **Photo/video library archives**: lots of similar content, dedup saves space, `list` anytime to see what's inside.
- 📁 **Versioned document sets**: a file edited 20 times — pack once, store only diffs.
- 🔐 **Split custody of passwords**: hand over the content password without revealing structure/order.
- 🖥️ **Portable GUI use**: double-click exe, no install, no Python needed (en/zh × GUI/CLI).
- ⏪ **Pull one chunk from an old archive** via `--chunk N` — no full extraction.

Not for: max compression ratio (use 7-Zip LZMA2) or incremental snapshot backup (use restic/borg).

<br>

## 📊 Performance

### Pack throughput (3.1 GB real data, Unity assets, partially incompressible)

| Metric | 🚀 shuffle-arc (zstd L1) | 📦 7z (LZMA2 -mx=1) |
|:---|---:|---:|
| **Pack** | **20.7 s** (150 MB/s) | 67.8 s (46 MB/s) |
| Unpack | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) |
| Ratio | 56.7% | **49.5%** |

> ~3× faster pack is because of zstd level 1 by default (7-Zip 21.02+ supports zstd too — speed is not the moat; **dedup + random access are**). 7z unpacks faster: shuffle-arc pays AES + auth + permutation restore.

### v5 parallel streaming unpack (3 GB archive, same load, A/B)

| Metric | v4 (old) | v5.0.1 |
|:---|---:|---:|
| Unpack time | 40.6 s | **31.2 s (+23%)** |
| Synchronous decryptions | 715 | **0** |
| Main-thread stalls | 3 s | 0.4 s |
| Peak memory | — | 431 MiB (archive-size independent) |

> Prefetch budget counts only in-flight bytes; chunks stay cached only while referenced. 9.73 GB / 894 files: streaming pack with no swapping, all extracted, sampled SHA-256 all correct.

<br>

## 🚀 Quick Start

### Portable Windows exe

Download v5.0.1 from [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases):

| File | Description |
|---|---|
| `shuffle-arc-gui.exe` | 🖥️ GUI (English), double-click to run |
| `shuffle-arc-gui-zh.exe` | 🖥️ GUI (中文) |
| `shuffle-arc-cli.exe` | ⌨️ CLI (English) |
| `shuffle-arc-cli-zh.exe` | ⌨️ CLI (中文) |

> Early releases (v3/v4) shipped an experimental `shuffle-arc-android-debug.apk` (Kotlin, minSdk 24) — see historical releases.

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

# version
python shuffle_arc.py --version

# unpack diagnostics (IO/decrypt/prefetch stats)
python shuffle_arc.py unpack -i out.far ... --debug
```

### Options

| Option | Default | Description |
|:---|---:|---|
| `-c, --chunk-size` | 4 MiB | chunk size = dedup granularity = encryption block |
| `-z, --zstd-level` | 1 | compression level (CLI). GUI offers 1/3/6/9/19 |
| `-I, --iter` | 300000 | PBKDF2 iterations |
| `-j, --jobs` | CPU count | parallel processes |
| `--version` | — | print version & disk format |
| `--debug` | — | unpack: print IO/decrypt/prefetch stats |

> Passwords are prompted if omitted. The two passwords **must be different**. Run with no arguments for the interactive wizard.

<br>

## 🏗️ Archive Format (v3, v5-compatible)

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

- **Disk format unchanged since v3**: v5 reads v3/v4, v4 reads v5 (both ways compatible).
- Permutation is derived from the shuffle password — **never stored**.
- v5's parallel unpack changes only read/prefetch strategy, not the byte format.

<br>

## 🔧 Build & Test

```bash
pyinstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
pyinstaller --onefile --name shuffle-arc-cli shuffle_arc.py

# regression suite (random roundtrip, dedup, streaming pack, v4↔v5 compat, password-free list)
python _test_v5.py
```

<br>

## ⚠️ Notes

- Custom format; v5 compatible with v3/v4; v1 legacy support removed.
- Plaintext manifest leaks filenames/sizes/chunk counts (trade-off for password-free listing).
- **Shuffle protects order, not content** — use strong random passwords.
- **Forgetting either password = permanent data loss.**

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