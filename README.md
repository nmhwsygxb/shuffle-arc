# shuffle-arc — 双密码「分块打乱加密压缩」归档工具

一个把**压缩加密**与**密钥化打乱**结合的归档工具：先压缩加密，再把密文块按「打乱密码」派生的置换乱序写入归档。即使归档和加密密码同时泄露，攻击者也看不出内容的原始顺序（顺序由独立的打乱密码保护）。

```
文件/目录 → 切块 → 逐块 zstd 压缩 → 逐块 AES-256-GCM 加密 → 按打乱密码置换乱序写入
```

- **两个完全独立的密码**：加密密码（内容）+ 打乱密码（顺序），必须不同
- **分块去重**：内容相同的块只存一份，相似文件只存差异
- **清单明文存储**：`list` 免密查看归档内容
- **随机访问**：`--chunk N` 只解密单个块
- **快速**：zstd + AES-GCM，打包速度约为 7z(LZMA2) 的 3 倍

> ⚠️ **安全提醒**：打乱保护的是【顺序】，不保护【内容】。两个密码必须各自足够强，「弱加密 + 打乱」并不能防暴力破解。忘记任意一个密码 = 数据永久不可恢复。

---

## 特性

| 特性 | 说明 |
|---|---|
| 双密码 | `-e` 加密密码、`-s` 打乱密码，独立派生两把密钥（PBKDF2-HMAC-SHA256，默认 300k 迭代，可并行派生） |
| 加密 | 每块独立 AES-256-GCM（随机 nonce，AAD 绑定存储槽位，防调包/换序） |
| 压缩 | 每块独立 zstd（默认 level 1，可用 `-z` 调整；对压缩比要求高可调高） |
| 打乱 | Fisher-Yates + HMAC-SHA256 伪随机置换，置换不入档，完全由打乱密码决定 |
| 去重 | 按块 sha256 去重：相同块只存一份；相似文件只存差异块（`-c` 控制块大小/去重粒度） |
| 明文清单 | v3 起清单明文存储，`list` 命令无需密码即可查看归档内文件 |
| 随机访问 | `unpack --chunk N` 只解出唯一块池中原始第 N 块 |
| 兼容 | 可解 v1 旧档（旧档清单加密于第 0 块） |
| 安全防覆盖 | 输出文件已存在时自动改名 `name (1).far`，绝不静默覆盖 |

## 性能（与 7z 对比实测，3.1GB 数据）

| 维度 | shuffle-arc | 7z (LZMA2 -mx=1) |
|---|---|---|
| 压缩 | **20.7s（150 MB/s）** | 67.8s（46 MB/s） |
| 解压 | 41.8s（74 MB/s） | **36.1s（86 MB/s）** |
| 压缩比 | 56.7% | **49.5%** |

定位：主打**压缩快 3 倍**（zstd level 1），压缩比略逊 LZMA2（设计取舍，可用 `-z` 调高级别）。解压 7z 略快（shuffle-arc 多付出 AES 解密 + 认证 + 置换还原）。功能上 7z 没有「打乱保护顺序 + 免密清单 + 分块去重」。

## 安装 / 运行

### 语言版本（中英共存）

- **英文版**：`shuffle_arc.py` / `shuffle_arc_gui.py`（英文注释与输出）、`shuffle-arc-gui.exe`、`shuffle-arc-cli.exe`
- **中文版**：`shuffle_arc_zh.py` / `shuffle_arc_gui_zh.py`（中文注释与输出）、`shuffle-arc-gui-zh.exe`、`shuffle-arc-cli-zh.exe`

功能完全一致，按语言喜好选用。

### 免安装 exe（Windows）

- **`shuffle-arc.exe`**（GUI 面板，双击使用，3 步流程：选文件 → 设双密码 → 进度条）
- **`dist/shuffle-arc-cli.exe`**（命令行）

### 从源码运行

```bash
pip install zstandard pycryptodome
python shuffle_arc.py ...   # 或 python shuffle_arc_gui.py 打开面板
```

需要 Python 3.9+（Windows 下用 `py -3.14` 亦可）。

## 用法

### CLI

```bash
# 打包（文件或目录 → .far 归档）
python shuffle-arc.py pack -i <文件或目录> -o out.far -e 加密密码 -s 打乱密码

# 解包（单文件归档 -o 为文件路径；多文件 -o 为输出目录）
python shuffle-arc.py unpack -i out.far -o <输出> -e 加密密码 -s 打乱密码

# 查看归档清单（无需密码，v3 明文清单）
python shuffle-arc.py list -i out.far

# 随机访问：只解出唯一块池中原始第 N 块
python shuffle-arc.py unpack -i out.far -o <输出> -e ... -s ... --chunk 3
```

可选参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-c, --chunk-size` | 4 MiB | 块大小 = 去重粒度 = 加密块大小 |
| `-z, --zstd-level` | 1 | zstd 压缩级别（越大压缩比越高、越慢） |
| `-I, --iter` | 300000 | PBKDF2 迭代次数 |
| `-j, --jobs` | CPU 数 | 并行进程数（中小规模数据多进程收益有限） |

> 密码不传则交互输入（`input()`，明文回显；getpass 在冻结 exe 中不可用）。两个密码必须不同。

### 向导模式

不带参数启动（含双击 exe）进入交互向导：`1=打包 2=解包 3=查看清单 q=退出`。

## 归档格式（v3）

```
┌─ 头部（明文，固定长度）──────────────────────────┐
│ magic "SFAR1" · version=3 · chunk_size · n(唯一块数) │
│ iterations · manifest_len · orig_len · salt1 · salt2 │
│ perm_check(HMAC) · table_offset                      │
├─ 明文清单（manifest）─────────────────────────────┤
│ 每行: {size}\t{relpath}\t{ref0},{ref1},...           │
├─ 加密区：唯一块池（按打乱置换乱序写入）───────────────┤
│ 每块: zstd 压缩 → AES-256-GCM（AAD 绑定槽位）          │
└─ 条目表：nonce/cipher_len/orig_len/payload_offset ──┘
```

- 置换（`perm`）完全由打乱密码派生，**不入档**；`perm[slot]` = 存储于该槽位的原始块下标
- v1 旧档：manifest 为加密的第 0 块（`unpack` 自动识别版本）

## 开发 / 构建 exe

```bash
# GUI（windowed，无控制台窗口）
py -3.14 -m PyInstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py

# CLI（console）
py -3.14 -m PyInstaller --onefile --name shuffle-arc-cli shuffle_arc.py
```

## 测试

```bash
python _test_v3.py        # v3 功能：去重/还原/list/随机访问/错误密码
python _test_v1_gui.py    # v1 兼容 + GUI prebuilt 路径
python _bench.py          # 性能基准（D 盘临时目录，结束自动清理）
```

## 已知限制

- 自定义格式，无跨版本兼容承诺（v3 可解 v1；将来新版本会保留向后兼容）
- 清单明文会泄露文件名/大小/块数（用户已知并接受）
- 大文件全量读入内存（打包/解包峰值内存 ≈ 源数据大小）
- 打乱保护顺序不保护内容——请使用强随机密码
