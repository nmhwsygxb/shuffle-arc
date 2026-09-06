#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shuffle-arc.py — 双密码「分块打乱加密压缩」归档工具  (v3)

设计（两个完全独立的密码）：
  1) -e / --enc-pass       加密密码  → PBKDF2-SHA256 派生 AES-256-GCM 密钥
  2) -s / --shuffle-pass   打乱密码  → PBKDF2-SHA256 派生打乱种子密钥，
                            用 Fisher-Yates + HMAC-SHA256 伪随机生成块置换

流程（符合“先压缩加密，再打乱”）：
  文件/目录 → 逻辑流(manifest + 内容) → 切成固定大小块
      → 每块独立 zstd 压缩
      → 每块独立 AES-256-GCM 加密（随机 nonce，AAD 绑定存储槽位，防调包/换序）
      → 按打乱密码派生的置换把密文块乱序写入归档

v3 变更（2026-08-16）：
  * 清单（manifest）明文存储：归档头之后、加密区之前直接写明文清单，
    不输密码即可用 `list` 子命令查看归档内容。
  * 分块去重：所有文件按固定大小切块，内容相同的块只存一份；
    相似文件只存差异块，相同部分不重复存储（明文清单记录每文件的块引用）。
  * 加密区只含「唯一块」；置换也只对唯一块做。

v4 流式解包（2026-08-28）：
  * 解包改为全流式：唯一块按需解密、边解边写文件，解密结果经由有上限的
    LRU 块缓存流转（默认 256 MiB 封顶），不再把全部明文块留在内存，
    任意大小的归档解包峰值内存都有界。
  * 已彻底移除 v1 旧档支持（LEGACY_V1 相关代码路径全部删除）。

特性：
  * 置换完全由打乱密码决定，文件头不含置换表 —— 即使拿到归档+加密密码，
    也看不出内容顺序（打乱密码独立保护顺序）。
  * 逐块独立加密 ⇒ 随机访问：unpack --chunk N 只解密/解压需要的块（快）。
  * 逐块可并行（-j）；压缩用 zstd（比 gzip/deflate 快数倍）。

安全提醒（重要）：
  * 打乱保护的是【顺序】，不保护【内容】。两个密码必须各自足够强，
    “弱加密 + 打乱”并不能防暴力破解 —— 请使用强随机密码。
  * v3 明文清单会泄露文件名、大小与块数（用户已知并接受）。
  * 忘记任意一个密码 = 数据永久不可恢复。
  * 自定义格式，无跨版本兼容承诺（仅 v3）。

用法：
  pack   : python shuffle-arc.py pack  -i <文件或目录> -o out.far -e 密码A -s 密码B [-c 1048576] [-I 300000] [-j 4]
  unpack : python shuffle-arc.py unpack -i out.far -o <输出>      -e 密码A -s 密码B [-j 4] [--chunk N]
            单文件归档时 -o 为输出文件路径；多文件时 -o 为输出目录。
            --chunk N：只解出唯一块池中原始第 N 块（随机访问），写入 <输出>.chunk<N>
  list   : python shuffle-arc.py list -i out.far
            查看明文清单（文件列表），无需密码（仅 v3 归档）。
"""

import argparse
import getpass
import hashlib
import hmac
import os
import struct
import sys
from pathlib import Path
from multiprocessing import Pool, cpu_count

import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

MAGIC = b"SFAR1"
VERSION = 3
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
DEFAULT_CHUNK = 4 << 20      # 4 MiB（去重粒度 = 加密块大小；基准：4MB 块比 1MB 快 ~29%）
DEFAULT_ITER = 300_000       # PBKDF2 迭代次数
ZSTD_LEVEL = 1               # zstd 压缩级别（基准：level1 比 level3 快 ~45%，压缩比几乎无损；可经 -z 覆盖）
STREAM_CACHE_BYTES = 256 << 20   # v4 流式解包：解密明文块的 LRU 缓存上限（256 MiB）

HEADER_FMT = ">5sBQIIQQ16s16s32sQ"   # magic, ver, chunk_size, n, iter, manifest_len, orig_len, salt1, salt2, perm_check, table_offset
HEADER_LEN = struct.calcsize(HEADER_FMT)
ENTRY_FMT = ">12sIIQ"             # nonce, cipher_len, orig_len, payload_offset
ENTRY_LEN = struct.calcsize(ENTRY_FMT)
AAD_PREFIX = MAGIC + b"slot"      # 认证数据前缀
PERM_CHECK_LABEL = b"shuffle-arc-perm-v1"


class AuthError(Exception):
    """GCM 认证失败：密码错误或归档损坏。"""


# ---------------------------------------------------------------- KDF / PRF

def kdf(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, length)


def derive_keys(enc_pass: str, shuffle_pass: str, salt1: bytes, salt2: bytes,
                iterations: int) -> tuple:
    """并行派生两个密钥：hashlib.pbkdf2_hmac 释放 GIL，双核并行可将
    PBKDF2 固定开销（默认 300K 迭代）减半。"""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(kdf, enc_pass, salt1, iterations, KEY_LEN)
        f2 = ex.submit(kdf, shuffle_pass, salt2, iterations, KEY_LEN)
        return f1.result(), f2.result()


def perm_rng(key: bytes):
    """HMAC-SHA256(key, 计数器) 作为确定性伪随机源（打乱密码派生）。"""
    c = 0
    while True:
        d = hmac.new(key, struct.pack(">Q", c), hashlib.sha256).digest()
        yield int.from_bytes(d[:8], "big")
        c += 1


def make_perm(n: int, key: bytes) -> list:
    """Fisher-Yates 洗牌：perm[slot] = 存储于该槽位的原始块下标。
    完全由打乱密码决定，归档中不存置换。"""
    perm = list(range(n))
    rng = perm_rng(key)
    for i in range(n - 1):
        bound = n - i
        while True:  # 拒绝采样消除模偏差
            v = next(rng)
            limit = (1 << 64) - ((1 << 64) % bound)
            if v < limit:
                break
        j = i + (v % bound)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


# ---------------------------------------------------------------- 分块

def chunk_data(data: bytes, cs: int) -> list:
    return [data[i:i + cs] for i in range(0, len(data), cs)]


# ---------------------------------------------------------------- 并行 worker（须为模块级函数）

def pack_chunk(args):
    slot, chunk = args
    cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    comp = cctx.compress(chunk)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD_PREFIX + struct.pack(">I", slot))
    ct, tag = cipher.encrypt_and_digest(comp)
    return slot, nonce, ct + tag, len(comp), len(chunk)


def unpack_chunk(args):
    slot, entry, payload = args
    nonce, cipher_len, orig_len, offset = entry
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD_PREFIX + struct.pack(">I", slot))
    try:
        comp = cipher.decrypt_and_verify(payload[:-TAG_LEN], payload[-TAG_LEN:])
    except ValueError:
        raise AuthError(slot) from None
    if orig_len == 0:
        return slot, b""
    dctx = zstd.ZstdDecompressor()
    return slot, dctx.decompress(comp, max_output_size=orig_len)


KEY = None  # 由进程初始化：pack/unpack 时设置，供 worker 使用


def _init_worker(key: bytes, level: int):
    global KEY, ZSTD_LEVEL
    KEY = key
    ZSTD_LEVEL = level   # -z 自定义级别在多进程 worker 中保持一致


# ---------------------------------------------------------------- 收集文件 / 分块去重 / manifest

def build_blocks(in_path: str, chunk_size: int) -> tuple:
    """读文件、按 chunk_size 切块、全局去重。
    返回 (manifest_bytes, unique_blocks, files, refs_list, orig_len)
    manifest 每行: {size}\t{relpath}\t{ref0},{ref1},...
    refs 为唯一块下标（首次出现顺序编号），明文可见。
    orig_len 为源文件总字节数（累计 len(data)，不依赖后续 stat）。"""
    p = Path(in_path)
    if p.is_dir():
        files = sorted([f for f in p.rglob("*") if f.is_file()])
        rels = [f.relative_to(p.parent).as_posix() for f in files]
    else:
        files = [p]
        rels = [p.name]
    lines = []
    unique = []          # 唯一块明文（去重后）
    index = {}           # sha256 -> 唯一块下标
    refs_list = []
    orig_len = 0
    for f, rel in zip(files, rels):
        data = f.read_bytes()
        orig_len += len(data)
        refs = []
        for c in chunk_data(data, chunk_size):
            h = hashlib.sha256(c).digest()
            u = index.get(h)
            if u is None:
                u = len(unique)
                index[h] = u
                unique.append(c)
            refs.append(u)
        refs_list.append(refs)
        lines.append(f"{len(data)}\t{rel}\t" + ",".join(map(str, refs)))
    manifest = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
    return manifest, unique, files, refs_list, orig_len


def parse_manifest_v3(manifest: bytes) -> list:
    """返回 [(relpath, size, refs), ...]（v3 明文清单）。"""
    out = []
    try:
        text = manifest.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("归档清单损坏（编码错误），归档可能被篡改！") from None
    for line in text.splitlines():
        if not line:
            continue
        try:
            size_s, rest = line.split("\t", 1)
            rel, _, refs_s = rest.partition("\t")
            size = int(size_s)
            if size < 0:
                raise ValueError
            refs = [int(x) for x in refs_s.split(",") if x] if refs_s else []
            out.append((rel, size, refs))
        except (ValueError, IndexError):
            raise ValueError("归档清单损坏（格式错误），归档可能被篡改！") from None
    return out


def _validate_relpath(relpath: str) -> str:
    """安全：拒绝归档清单中的路径穿越 / 绝对路径 / Windows 危险路径。
    v3 清单是明文，攻击者可构造恶意条目；解包绝不能写到输出目录之外。
    返回规范化后的 relpath（正斜杠，无空/'.'/'..' 段）。"""
    if not relpath:
        sys.exit("归档清单中的不安全路径：空 relpath")
    if relpath.startswith(("/", "\\")) or len(relpath) >= 2 and relpath[1] == ":":
        sys.exit(f"归档清单中的绝对路径不安全：{relpath!r}")
    norm = relpath.replace("\\", "/")
    parts = norm.split("/")
    if any(p in ("", ".", "..") for p in parts):
        sys.exit(f"归档清单中的路径穿越不安全：{relpath!r}")
    return norm


def unique_path(path: Path) -> Path:
    """目标已存在时自动改名：`name (1).ext`、`name (2).ext`… 绝不静默覆盖。"""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    n = 1
    while True:
        cand = path.with_name(f"{stem} ({n}){suffix}")
        if not cand.exists():
            return cand
        n += 1


# ---------------------------------------------------------------- 提前准备（GUI 后台预热）

def prep_pack(path: str, chunk_size: int = DEFAULT_CHUNK) -> tuple:
    """打包前准备：读源 + 切块去重 + 生成明文 manifest。
    结果可传给 pack(prebuilt=...)。"""
    return build_blocks(path, chunk_size)


def prep_unpack(path: str, enc_pass: str, shuffle_pass: str) -> tuple:
    """解包前准备：读归档头 + 派生两个密钥 + 校验打乱密码。
    返回 (meta, enc_key, shuf_key)；打乱密码错误抛 ValueError。"""
    meta = read_archive_meta(path)
    enc_key, shuf_key = derive_keys(enc_pass, shuffle_pass, meta["salt1"], meta["salt2"],
                                    meta["iterations"])
    if not hmac.compare_digest(hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest(),
                               meta["perm_check"]):
        raise ValueError("打乱密码错误，或归档已损坏！")
    return meta, enc_key, shuf_key


# ---------------------------------------------------------------- pack / unpack

def pack(args, progress=None, prebuilt=None):
    """progress(done, total, stage)：每处理完一块回调一次（GUI 进度条用）。
    prebuilt=(manifest, unique_blocks, files, refs_list, orig_len)：跳过源读取与去重（由 prep_pack 提前准备）。"""
    if prebuilt is not None:
        manifest, unique, files, refs_list, orig_len = prebuilt
    else:
        manifest, unique, files, refs_list, orig_len = build_blocks(args.input, args.chunk_size)
    # CLI -z 自定义 zstd 级别（GUI/向导的 ns 无此属性时保持全局默认）
    custom_level = getattr(args, "zstd_level", None)
    if custom_level is not None:
        global ZSTD_LEVEL
        ZSTD_LEVEL = int(custom_level)
    manifest_len = len(manifest)
    u = len(unique)              # 唯一块数（去重后）

    salt1 = get_random_bytes(SALT_LEN)
    salt2 = get_random_bytes(SALT_LEN)
    enc_key, shuf_key = derive_keys(args.enc_pass, args.shuffle_pass, salt1, salt2, args.iter)
    perm_check = hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest()

    global KEY
    KEY = enc_key
    perm = make_perm(u, shuf_key)

    # 输出已存在时自动改名（name (1).far…），绝不静默覆盖/销毁旧归档
    out_path = unique_path(Path(args.output))
    args.output = str(out_path)
    with open(out_path, "wb") as f:
        header = struct.pack(HEADER_FMT, MAGIC, VERSION, args.chunk_size, u,
                             args.iter, manifest_len, orig_len, salt1, salt2, perm_check, 0)
        f.write(header)
        f.write(manifest)        # v3：明文清单，加密区之前
        payload_start = HEADER_LEN + manifest_len

        entries = [None] * u
        payload_off = payload_start
        work = [(slot, unique[perm[slot]]) for slot in range(u)]
        done = 0

        def _store(slot, nonce, payload, comp_len, orig_chunk_len):
            nonlocal payload_off, done
            entries[slot] = (nonce, len(payload), orig_chunk_len, payload_off)
            f.write(payload)
            payload_off += len(payload)
            done += 1
            if progress:
                progress(done, u + 1, "压缩加密")      # 留 1 步给收尾

        if args.jobs > 1:
            with Pool(args.jobs, initializer=_init_worker, initargs=(enc_key, ZSTD_LEVEL)) as pool:
                for r in pool.imap_unordered(pack_chunk, work):
                    _store(*r)
        else:
            # 单进程路径（GUI 等不便多进程的场景）
            for item in work:
                _store(*pack_chunk(item))

        table_offset = payload_off
        for nonce, clen, olen, off in entries:
            f.write(struct.pack(ENTRY_FMT, nonce, clen, olen, off))
        f.seek(0)
        f.write(struct.pack(HEADER_FMT, MAGIC, VERSION, args.chunk_size, u,
                            args.iter, manifest_len, orig_len, salt1, salt2, perm_check, table_offset))
        if progress:
            progress(u + 1, u + 1, "收尾完成")

    total_refs = sum(len(r) for r in refs_list)
    print(f"pack 完成: {len(files)} 个文件, {u} 个唯一块（原始 {total_refs} 块引用, "
          f"去重比 {total_refs and (1 - u / total_refs):.1%}）, "
          f"原始 {orig_len + manifest_len} B → 归档 {os.path.getsize(args.output)} B")
    return str(out_path)   # 实际写入路径（可能已自动改名），GUI 用它显示结果


def read_archive_meta(path: str):
    with open(path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        if file_size < HEADER_LEN:
            sys.exit("不是 shuffle-arc 归档文件（文件过小）")
        f.seek(0)
        hdr = f.read(HEADER_LEN)
    magic, ver, chunk_size, n, iterations, manifest_len, orig_len, salt1, salt2, perm_check, table_offset = \
        struct.unpack(HEADER_FMT, hdr)
    if magic != MAGIC:
        sys.exit("不是 shuffle-arc 归档文件（magic 不匹配）")
    if ver != VERSION:
        sys.exit(f"不支持的版本: {ver}（仅支持 v3 归档）")
    # 对攻击者可控的头字段做合理性限制（恶意归档 → DoS / 荒谬分配）
    if n <= 0 or n > 50_000_000:
        sys.exit(f"归档头中的块数不合理: {n}")
    if iterations < 1000 or iterations > 50_000_000:
        sys.exit(f"归档头中的 PBKDF2 迭代次数不合理: {iterations}")
    if chunk_size <= 0 or chunk_size > (1 << 34):          # 16 GiB 上限
        sys.exit(f"归档头中的块大小不合理: {chunk_size}")
    if not (0 <= manifest_len <= file_size - HEADER_LEN) or orig_len > (1 << 46):  # 声明的总量上限 64 TiB
        sys.exit("归档头与文件大小不一致，已中止")
    if not (HEADER_LEN + manifest_len <= table_offset <= file_size):
        sys.exit("归档头条目表偏移越界，已中止")
    return dict(version=ver, chunk_size=chunk_size, n=n, iterations=iterations,
                manifest_len=manifest_len, orig_len=orig_len,
                salt1=salt1, salt2=salt2, perm_check=perm_check,
                table_offset=table_offset)


def read_entries(path: str, n: int, table_offset: int) -> list:
    with open(path, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        need = n * ENTRY_LEN
        if table_offset + need > fsize:
            sys.exit("归档条目表不完整 — 归档已损坏或遭篡改！")
        f.seek(table_offset)
        raw = f.read(need)
    return [struct.unpack(ENTRY_FMT, raw[i:i + ENTRY_LEN]) for i in range(0, len(raw), ENTRY_LEN)]


def _read_payload_of(path: str, entry):
    nonce, clen, olen, off = entry
    if clen <= 0 or off < 0:
        sys.exit("归档条目含无效的载荷偏移/长度 — 归档已损坏！")
    with open(path, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        if off + clen > fsize:
            sys.exit("归档条目指向文件末尾之外 — 归档已损坏！")
        f.seek(off)
        return f.read(clen)


def unpack(args, progress=None, precomputed=None):
    """progress(done, total, stage)：每处理完一块回调一次（GUI 进度条用）。
    precomputed=(meta, enc_key, shuf_key)：跳过读头与密钥派生（由 prep_unpack 提前准备）。"""
    if precomputed is not None:
        meta, enc_key, shuf_key = precomputed
    else:
        meta = read_archive_meta(args.input)
        enc_key, shuf_key = derive_keys(args.enc_pass, args.shuffle_pass,
                                        meta["salt1"], meta["salt2"], meta["iterations"])
    # 打乱密码校验（HMAC 极快，无论是否预计算都执行，防篡改）
    if not hmac.compare_digest(hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest(),
                               meta["perm_check"]):
        sys.exit("打乱密码错误，或归档已损坏！")
    return _unpack_v3(args, meta, enc_key, shuf_key, progress)


def _open_output_targets(files, out_arg):
    """解析输出布局、创建目录，返回 (targets, first_display, dir_mode)。
    files: [(relpath, size, refs)]。targets：每个文件一个已打开的可写句柄。
    安全：每个 relpath 都经校验（拒绝路径穿越/绝对路径），即使面对恶意构造的
    归档，解包也绝不能写到输出目录之外。"""
    dir_mode = any("/" in rel for rel, _, _ in files) or len(files) > 1
    targets = []
    first_display = None
    safe_files = []
    for relpath, size, refs in files:
        safe_files.append((_validate_relpath(relpath), size, refs))
    files = safe_files
    if dir_mode:
        out_dir = Path(out_arg)
        if out_dir.exists() and not out_dir.is_dir():
            sys.exit(f"输出路径 {out_arg} 已存在且不是目录！")
        top0 = files[0][0].split("/", 1)[0] if "/" in files[0][0] else files[0][0]
        if out_dir.exists() and out_dir.name == top0:
            out_dir = unique_path(out_dir)
        out_dir = out_dir.resolve()          # 规范化基准；所有目标都必须在其下
        out_dir.mkdir(parents=True, exist_ok=True)
        roots = {}
        for relpath, size, refs in files:
            if "/" in relpath:
                top, rel = relpath.split("/", 1)
            else:
                top, rel = relpath, ""
            if top not in roots:
                root = unique_path(out_dir / top)
                root.mkdir(parents=True, exist_ok=True)
                roots[top] = root
                if first_display is None:
                    first_display = root
            target = unique_path(roots[top] / rel) if rel else roots[top]
            target.parent.mkdir(parents=True, exist_ok=True)
            # 纵深防御：拒绝任何逃逸出输出根目录的路径（符号链接/竞态）
            if not (target.resolve().is_relative_to(out_dir.resolve())):
                sys.exit(f"输出路径解析到 {out_dir} 之外，不安全: {target}")
            targets.append(open(target, "wb"))          # 流式：句柄保持打开，由调用方关闭
    else:
        relpath, size, refs = files[0]
        if os.path.isdir(out_arg) or out_arg.endswith(("/", "\\")):
            out_dir = Path(out_arg).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            target = unique_path(out_dir / relpath)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not (target.resolve().is_relative_to(out_dir)):
                sys.exit(f"输出路径解析到 {out_dir} 之外，不安全: {target}")
        else:
            Path(out_arg).parent.mkdir(parents=True, exist_ok=True)
            target = unique_path(Path(out_arg))
        targets.append(open(target, "wb"))
        first_display = target
    return targets, first_display, dir_mode


class _LRUCache:
    """有上限内存的明文块 LRU 缓存，按「原始块下标」为键。
    字节预算约束：插入新块后逐出最久未用的条目，直到放得下为止。"""

    def __init__(self, budget):
        self.budget = budget
        self._data = {}          # ref -> bytes
        self._order = []         # 近期使用顺序（末尾 = 最近）
        self._bytes = 0

    def get(self, ref):
        if ref not in self._data:
            return None
        self._order.remove(ref)
        self._order.append(ref)
        return self._data[ref]

    def put(self, ref, chunk):
        if ref in self._data:
            self._order.remove(ref)
            self._bytes -= len(self._data[ref])
        self._data[ref] = chunk
        self._order.append(ref)
        self._bytes += len(chunk)
        while self._bytes > self.budget and len(self._data) > 1:
            old = self._order.pop(0)
            if old in self._data:
                self._bytes -= len(self._data.pop(old))

    def __len__(self):
        return len(self._data)


def _decrypt_slot_entry(path, entry, slot):
    """从归档读取一个槽位的密文并解密+解压，返回明文。"""
    try:
        _, plain = unpack_chunk((slot, entry, _read_payload_of(path, entry)))
        return plain
    except AuthError:
        sys.exit("解密失败：加密密码错误，或归档已损坏！")
    except zstd.ZstdError:
        sys.exit("解压失败：归档已损坏！")


def _unpack_v3(args, meta, enc_key, shuf_key, progress):
    """v3：明文清单 + 唯一块池 + 按引用重组。
    v4：全流式 — 解密块经由有上限的 LRU 缓存流转，写文件时逐块写出，
    任意大小的归档解包峰值内存都有界。"""
    n = meta["n"]                       # 唯一块数
    manifest_len = meta["manifest_len"]
    with open(args.input, "rb") as f:
        f.seek(HEADER_LEN)
        manifest_bytes = f.read(manifest_len)
    try:
        files = parse_manifest_v3(manifest_bytes)      # [(relpath, size, refs)]
    except ValueError as e:
        sys.exit(str(e))
    if not files:
        print("unpack 完成: 归档为空（无文件）")
        return str(args.output)
    # 安全：拒绝恶意清单中越界的块引用（会导致崩溃/错乱重组）
    for relpath, size, refs in files:
        bad = [r for r in refs if not (0 <= r < n)]
        if bad:
            sys.exit(f"归档清单引用了不存在的块 {bad[:8]} — 已损坏或遭篡改！")
    dir_mode = any("/" in rel for rel, _, _ in files) or len(files) > 1
    tail_steps = len(files) if dir_mode else 1
    total = 1 + n + tail_steps

    entries = read_entries(args.input, n, meta["table_offset"])
    global KEY
    KEY = enc_key
    perm = make_perm(n, shuf_key)
    inv = [0] * n
    for s, p in enumerate(perm):
        inv[p] = s                      # 原始下标 -> 存储槽位

    if args.chunk is not None:
        # 随机访问：唯一块池中原始第 N 块
        orig_idx = args.chunk
        if not (0 <= orig_idx < n):
            sys.exit(f"--chunk {args.chunk} 越界（唯一块数 {n}）")
        slot = inv[orig_idx]
        plain = _decrypt_slot_entry(args.input, entries[slot], slot)
        out_path = f"{args.output}.chunk{args.chunk}"
        with open(out_path, "wb") as f:
            f.write(plain)
        print(f"随机访问: 唯一块 #{args.chunk}（{len(plain)} B）已解出 → {out_path}")
        return str(out_path)

    # 策略选择：全部唯一块明文总量在流式预算内且请求了并行时，
    # 一次性并行解密整个块池（旧的快路径）；否则流式：按需经 LRU 缓存解密
    #（内存有界，任意大小都可用）。
    total_plain = sum(e[2] for e in entries)          # 每个唯一块的 orig_len
    use_parallel = args.jobs > 1 and total_plain <= STREAM_CACHE_BYTES

    done = 1
    if progress:
        progress(done, total, "解密解压")

    cache = _LRUCache(STREAM_CACHE_BYTES)

    def _block_of(ref):
        """原始块 `ref` 的明文（来自并行池或 LRU 缓存）。"""
        b = cache.get(ref)
        if b is not None:
            return b
        slot = inv[ref]
        b = _decrypt_slot_entry(args.input, entries[slot], slot)
        cache.put(ref, b)
        return b

    if use_parallel:
        blocks = {}
        try:
            with Pool(args.jobs, initializer=_init_worker, initargs=(enc_key, ZSTD_LEVEL)) as pool:
                work = [(s, entries[s], _read_payload_of(args.input, entries[s])) for s in range(n)]
                for slot, plain in pool.imap_unordered(unpack_chunk, work):
                    blocks[perm[slot]] = plain
                    done += 1
                    if progress:
                        progress(done, total, "解密解压")
        except AuthError:
            sys.exit("解密失败：加密密码错误，或归档已损坏！")

        def _block_of(ref):
            return blocks[ref]

    # 流式：逐个文件、逐块经 LRU 缓存写出
    targets, first_display, dir_mode = _open_output_targets(files, args.output)
    try:
        for (relpath, size, refs), fh in zip(files, targets):
            for r in refs:
                fh.write(_block_of(r))
            fh.flush()
            if not use_parallel:
                done += 1
                if progress:
                    progress(done, total, "写入文件")
    finally:
        for fh in targets:
            fh.close()

    if use_parallel:
        # 并行路径在上面已统计解密步数；此处补统计写文件尾段
        done += len(files) if dir_mode else 1
        if progress:
            progress(done, total, "写入文件")

    if dir_mode:
        print(f"unpack 完成: {len(files)} 个文件 → {first_display}/")
    else:
        print(f"unpack 完成: 1 个文件 → {first_display}（{files[0][1]} B）")
    return str(first_display)


# ---------------------------------------------------------------- 查看清单（无需密码）

def show_list(args):
    """list：读 v3 明文清单，无需密码即可查看归档内容。"""
    meta = read_archive_meta(args.input)
    with open(args.input, "rb") as f:
        f.seek(HEADER_LEN)
        manifest_bytes = f.read(meta["manifest_len"])
    try:
        files = parse_manifest_v3(manifest_bytes)
    except ValueError as e:
        sys.exit(str(e))
    print(f"归档: {args.input}")
    print(f"唯一块: {meta['n']}  原始总大小: {meta['orig_len']} B")
    print("-" * 60)
    for relpath, size, refs in files:
        print(f"{size:>12} B  {relpath}  [{len(refs)} 块]")
    print("-" * 60)
    print(f"共 {len(files)} 个文件")


# ---------------------------------------------------------------- 向导模式（双击直接用）

def wizard():
    """无参数启动（双击 exe）时进入的交互向导：引导打包/解包/查看，结束后停留等待回车。"""
    print("=" * 56)
    print(" shuffle-arc  双密码加密压缩工具  (v3)")
    print(" 打包: 文件/目录 → 加密压缩归档 (.far)（自动去重）")
    print(" 解包: 归档 → 还原文件")
    print(" 查看: 列出归档内文件（无需密码）")
    print("=" * 56)
    print("安全提醒：需要两个相互独立的密码")
    print("（加密密码 + 打乱密码），忘记任何一个，")
    print("数据将永久无法恢复，请务必牢记！")
    while True:
        choice = input("\n选择操作 [1=打包, 2=解包, 3=查看清单, q=退出]: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return
        if choice in ("1", "2", "3"):
            break
        print("输入无效，请输入 1、2 或 3")

    import types
    ns = types.SimpleNamespace()
    try:
        if choice == "1":
            ns.input = input("源文件或目录路径: ").strip().strip('"')
            ns.output = input("输出归档路径 (如 backup.far): ").strip().strip('"')
            ns.enc_pass = _ask("加密")
            ns.shuffle_pass = _ask("打乱")
            if ns.enc_pass == ns.shuffle_pass:
                sys.exit("两个密码必须不同且相互独立！")
            ns.chunk_size = DEFAULT_CHUNK
            ns.iter = DEFAULT_ITER
            ns.jobs = max(1, cpu_count())
            pack(ns)
        elif choice == "2":
            ns.input = input("归档路径: ").strip().strip('"')
            ns.output = input("输出路径（单文件归档=文件路径；多文件=目录）: ").strip().strip('"')
            ns.enc_pass = _ask("加密")
            ns.shuffle_pass = _ask("打乱")
            if ns.enc_pass == ns.shuffle_pass:
                sys.exit("两个密码必须不同且相互独立！")
            ns.jobs = max(1, cpu_count())
            ns.chunk = None
            unpack(ns)
        else:
            ns.input = input("归档路径: ").strip().strip('"')
            show_list(ns)
    except SystemExit as e:
        print(f"\n[错误] {e}")
    except Exception as e:
        print(f"\n[出错] {type(e).__name__}: {e}")
    input("\n按回车键退出...")


# ---------------------------------------------------------------- CLI

def _ask(which: str) -> str:
    """密码输入：用 input() 而非 getpass（getpass 在 PyInstaller 冻结 exe 中
    会因控制台读取失败而无法输入）。注意：此处输入会明文回显。"""
    return input(f"{which}密码: ").strip()


def main():
    # Windows 控制台编码修复（cp932 等无法输出中文时）
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # 无参数（双击 exe）→ 进入交互向导，避免窗口闪退
    if len(sys.argv) == 1:
        wizard()
        return

    ap = argparse.ArgumentParser(description="双密码分块打乱加密压缩归档工具（shuffle-arc v3）")
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("pack", help="打包加密（自动分块去重）")
    p.add_argument("-i", "--input", required=True, help="输入文件或目录")
    p.add_argument("-o", "--output", required=True, help="输出 .far 归档")
    p.add_argument("-e", "--enc-pass", help="加密密码（不传则交互输入）")
    p.add_argument("-s", "--shuffle-pass", help="打乱密码（不传则交互输入）")
    p.add_argument("-c", "--chunk-size", type=int, default=DEFAULT_CHUNK, help=f"块大小（去重粒度），默认 {DEFAULT_CHUNK}")
    p.add_argument("-z", "--zstd-level", type=int, default=None, help=f"zstd 压缩级别，默认 {ZSTD_LEVEL}（越大压缩比越高越慢）")
    p.add_argument("-I", "--iter", type=int, default=DEFAULT_ITER, help=f"PBKDF2 迭代次数，默认 {DEFAULT_ITER}")
    p.add_argument("-j", "--jobs", type=int, default=max(1, cpu_count()), help="并行进程数")
    p.set_defaults(func=pack)

    u = sub.add_parser("unpack", help="解包解密")
    u.add_argument("-i", "--input", required=True, help="输入 .far 归档")
    u.add_argument("-o", "--output", required=True, help="输出文件（单文件）或目录（多文件）")
    u.add_argument("-e", "--enc-pass", help="加密密码（不传则交互输入）")
    u.add_argument("-s", "--shuffle-pass", help="打乱密码（不传则交互输入）")
    u.add_argument("-j", "--jobs", type=int, default=max(1, cpu_count()), help="并行进程数")
    u.add_argument("--chunk", type=int, default=None, help="随机访问：只解出唯一块池中原始第 N 块")
    u.set_defaults(func=unpack)

    l = sub.add_parser("list", help="查看归档内文件清单（v3 明文，无需密码）")
    l.add_argument("-i", "--input", required=True, help="输入 .far 归档")
    l.set_defaults(func=show_list)

    args = ap.parse_args()
    if args.mode in ("pack", "unpack"):
        if not args.enc_pass:
            args.enc_pass = _ask("加密")
        if not args.shuffle_pass:
            args.shuffle_pass = _ask("打乱")
        if args.enc_pass == args.shuffle_pass:
            sys.exit("两个密码必须不同且相互独立！")
    args.func(args)


if __name__ == "__main__":
    from multiprocessing import freeze_support
    freeze_support()   # PyInstaller 冻结 exe 中 multiprocessing 的必需引导
    main()
