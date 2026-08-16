#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shuffle-arc.py — dual-password "chunked-shuffle encrypted compression" archive tool  (v3)

Design (two fully independent passwords):
  1) -e / --enc-pass       encryption password  → PBKDF2-SHA256 derives the AES-256-GCM key
  2) -s / --shuffle-pass   shuffle password  → PBKDF2-SHA256 derives the shuffle-seed key,
                           which generates the block permutation via Fisher-Yates + HMAC-SHA256 PRNG

Pipeline (compress-encrypt first, then shuffle):
  files/dirs → logical stream (manifest + content) → cut into fixed-size chunks
      → each chunk zstd-compressed independently
      → each chunk AES-256-GCM encrypted independently (random nonce, AAD bound to its storage slot, anti-tamper/reorder)
      → ciphertext chunks are written in the order of the permutation derived from the shuffle password

v3 changes (2026-08-16):
  * Plaintext manifest: written directly after the archive header and before the encrypted region,
    so `list` can show archive contents without any password.
  * Chunk-level dedup: all files are cut into fixed-size chunks and identical chunks are stored only once;
    similar files store only their differing chunks and shared parts are not duplicated (the plaintext manifest records each file's chunk references).
  * The encrypted region contains only the "unique chunks"; the permutation is applied to unique chunks only.
  * v1 archives can still be unpacked (their manifest is encrypted in chunk 0).

Features:
  * The permutation is fully determined by the shuffle password; the header holds no permutation table —
    even with the archive plus the encryption password, the content order stays hidden (the shuffle password independently protects order).
  * Per-chunk independent encryption ⇒ random access: unpack --chunk N decrypts/decompresses only the needed chunk (fast).
  * Chunks can be processed in parallel (-j); compression uses zstd (several times faster than gzip/deflate).

Security notes (important):
  * The shuffle protects ORDER, not CONTENT. Both passwords must each be strong on their own —
    "weak encryption + shuffle" does not resist brute force; use strong random passwords.
  * The v3 plaintext manifest reveals file names, sizes and chunk counts (known and accepted by the user).
  * Losing either password = data is permanently unrecoverable.
  * Custom format; no cross-version compatibility promise (v3 can unpack v1).

Usage:
  pack   : python shuffle-arc.py pack  -i <file-or-dir> -o out.far -e passA -s passB [-c 1048576] [-I 300000] [-j 4]
  unpack : python shuffle-arc.py unpack -i out.far -o <output>      -e passA -s passB [-j 4] [--chunk N]
            For a single-file archive, -o is the output file path; for multiple files, -o is the output directory.
            --chunk N: extract only original chunk N from the unique-chunk pool (random access), written to <output>.chunk<N>
  list   : python shuffle-arc.py list -i out.far
            Show the plaintext manifest (file list) without a password (v3 archives only).
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
LEGACY_V1 = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
DEFAULT_CHUNK = 4 << 20      # 4 MiB (dedup granularity = cipher block size; benchmark: 4MB chunks are ~29% faster than 1MB)
DEFAULT_ITER = 300_000       # PBKDF2 iteration count
ZSTD_LEVEL = 1               # zstd compression level (benchmark: level1 is ~45% faster than level3 with almost no ratio loss; overridable via -z)

HEADER_FMT = ">5sBQIIQQ16s16s32sQ"   # magic, ver, chunk_size, n, iter, manifest_len, orig_len, salt1, salt2, perm_check, table_offset
HEADER_LEN = struct.calcsize(HEADER_FMT)
ENTRY_FMT = ">12sIIQ"             # nonce, cipher_len, orig_len, payload_offset
ENTRY_LEN = struct.calcsize(ENTRY_FMT)
AAD_PREFIX = MAGIC + b"slot"      # authenticated data prefix
PERM_CHECK_LABEL = b"shuffle-arc-perm-v1"


class AuthError(Exception):
    """GCM authentication failed: wrong password or corrupted archive."""


# ---------------------------------------------------------------- KDF / PRF

def kdf(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, length)


def derive_keys(enc_pass: str, shuffle_pass: str, salt1: bytes, salt2: bytes,
                iterations: int) -> tuple:
    """Derive both keys in parallel: hashlib.pbkdf2_hmac releases the GIL, so two
    threads can halve the fixed PBKDF2 cost (300K iterations by default)."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(kdf, enc_pass, salt1, iterations, KEY_LEN)
        f2 = ex.submit(kdf, shuffle_pass, salt2, iterations, KEY_LEN)
        return f1.result(), f2.result()


def perm_rng(key: bytes):
    """HMAC-SHA256(key, counter) as a deterministic pseudo-random source (derived from the shuffle password)."""
    c = 0
    while True:
        d = hmac.new(key, struct.pack(">Q", c), hashlib.sha256).digest()
        yield int.from_bytes(d[:8], "big")
        c += 1


def make_perm(n: int, key: bytes) -> list:
    """Fisher-Yates shuffle: perm[slot] = original chunk index stored in that slot.
    Fully determined by the shuffle password; the permutation is not stored in the archive."""
    perm = list(range(n))
    rng = perm_rng(key)
    for i in range(n - 1):
        bound = n - i
        while True:  # rejection sampling to remove modulo bias
            v = next(rng)
            limit = (1 << 64) - ((1 << 64) % bound)
            if v < limit:
                break
        j = i + (v % bound)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


# ---------------------------------------------------------------- chunking

def chunk_data(data: bytes, cs: int) -> list:
    return [data[i:i + cs] for i in range(0, len(data), cs)]


# ---------------------------------------------------------------- parallel workers (must be module-level functions)

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


KEY = None  # process-wide: set during pack/unpack for use by workers


def _init_worker(key: bytes, level: int):
    global KEY, ZSTD_LEVEL
    KEY = key
    ZSTD_LEVEL = level   # keep a custom -z level consistent across multiprocessing workers


# ---------------------------------------------------------------- collect files / chunk dedup / manifest

def build_blocks(in_path: str, chunk_size: int) -> tuple:
    """Read files, split into chunk_size chunks, and deduplicate globally.
    Returns (manifest_bytes, unique_blocks, files, refs_list, orig_len).
    Each manifest line: {size}\t{relpath}\t{ref0},{ref1},...
    refs are unique-chunk indices (numbered in first-appearance order), visible in plaintext.
    orig_len is the total source bytes (accumulated len(data), not dependent on a later stat)."""
    p = Path(in_path)
    if p.is_dir():
        files = sorted([f for f in p.rglob("*") if f.is_file()])
        rels = [f.relative_to(p.parent).as_posix() for f in files]
    else:
        files = [p]
        rels = [p.name]
    lines = []
    unique = []          # plaintext of unique chunks (after dedup)
    index = {}           # sha256 -> unique chunk index
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
    """Returns [(relpath, size, refs), ...] (v3 plaintext manifest)."""
    out = []
    for line in manifest.decode("utf-8").splitlines():
        if not line:
            continue
        try:
            size_s, rest = line.split("\t", 1)
            rel, _, refs_s = rest.partition("\t")
            refs = [int(x) for x in refs_s.split(",") if x] if refs_s else []
            out.append((rel, int(size_s), refs))
        except (ValueError, IndexError):
            raise ValueError("Corrupted archive manifest (bad format) — the archive may have been tampered with!") from None
    return out


def parse_manifest_v1(manifest: bytes) -> list:
    """Returns [(relpath, length), ...] (v1 manifest, two columns only)."""
    out = []
    for line in manifest.decode("utf-8").splitlines():
        if not line:
            continue
        length_s, _, name = line.partition("\t")
        out.append((name, int(length_s)))
    return out


def unique_path(path: Path) -> Path:
    """Automatically rename when the target exists: `name (1).ext`, `name (2).ext`… never silently overwrite."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    n = 1
    while True:
        cand = path.with_name(f"{stem} ({n}){suffix}")
        if not cand.exists():
            return cand
        n += 1


# ---------------------------------------------------------------- advance preparation (GUI background warm-up)

def prep_pack(path: str, chunk_size: int = DEFAULT_CHUNK) -> tuple:
    """Pre-pack preparation: read the source + chunk dedup + build the plaintext manifest.
    The result can be passed to pack(prebuilt=...)."""
    return build_blocks(path, chunk_size)


def prep_unpack(path: str, enc_pass: str, shuffle_pass: str) -> tuple:
    """Pre-unpack preparation: read the archive header + derive both keys + verify the shuffle password.
    Returns (meta, enc_key, shuf_key); raises ValueError on a wrong shuffle password."""
    meta = read_archive_meta(path)
    enc_key, shuf_key = derive_keys(enc_pass, shuffle_pass, meta["salt1"], meta["salt2"],
                                    meta["iterations"])
    if not hmac.compare_digest(hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest(),
                               meta["perm_check"]):
        raise ValueError("Wrong shuffle password, or the archive is corrupted!")
    return meta, enc_key, shuf_key


# ---------------------------------------------------------------- pack / unpack

def pack(args, progress=None, prebuilt=None):
    """progress(done, total, stage): called back after each processed chunk (for the GUI progress bar).
    prebuilt=(manifest, unique_blocks, files, refs_list, orig_len): skips source reading and dedup (prepared by prep_pack)."""
    if prebuilt is not None:
        manifest, unique, files, refs_list, orig_len = prebuilt
    else:
        manifest, unique, files, refs_list, orig_len = build_blocks(args.input, args.chunk_size)
    # CLI -z custom zstd level (keep the global default when ns lacks this attribute, e.g. GUI/wizard)
    custom_level = getattr(args, "zstd_level", None)
    if custom_level is not None:
        global ZSTD_LEVEL
        ZSTD_LEVEL = int(custom_level)
    manifest_len = len(manifest)
    u = len(unique)              # number of unique chunks (after dedup)

    salt1 = get_random_bytes(SALT_LEN)
    salt2 = get_random_bytes(SALT_LEN)
    enc_key, shuf_key = derive_keys(args.enc_pass, args.shuffle_pass, salt1, salt2, args.iter)
    perm_check = hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest()

    global KEY
    KEY = enc_key
    perm = make_perm(u, shuf_key)

    # automatically rename when the output exists (name (1).far…), never silently overwrite/destroy an old archive
    out_path = unique_path(Path(args.output))
    args.output = str(out_path)
    with open(out_path, "wb") as f:
        header = struct.pack(HEADER_FMT, MAGIC, VERSION, args.chunk_size, u,
                             args.iter, manifest_len, orig_len, salt1, salt2, perm_check, 0)
        f.write(header)
        f.write(manifest)        # v3: plaintext manifest, before the encrypted region
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
                progress(done, u + 1, "Compress & encrypt")      # keep 1 step for the tail

        if args.jobs > 1:
            with Pool(args.jobs, initializer=_init_worker, initargs=(enc_key, ZSTD_LEVEL)) as pool:
                for r in pool.imap_unordered(pack_chunk, work):
                    _store(*r)
        else:
            # single-process path (scenarios where multiprocessing is inconvenient, e.g. GUI)
            for item in work:
                _store(*pack_chunk(item))

        table_offset = payload_off
        for nonce, clen, olen, off in entries:
            f.write(struct.pack(ENTRY_FMT, nonce, clen, olen, off))
        f.seek(0)
        f.write(struct.pack(HEADER_FMT, MAGIC, VERSION, args.chunk_size, u,
                            args.iter, manifest_len, orig_len, salt1, salt2, perm_check, table_offset))
        if progress:
            progress(u + 1, u + 1, "Finalizing")

    total_refs = sum(len(r) for r in refs_list)
    print(f"pack done: {len(files)} files, {u} unique chunks (out of {total_refs} original chunk refs, "
          f"dedup ratio {total_refs and (1 - u / total_refs):.1%}), "
          f"original {orig_len + manifest_len} B → archive {os.path.getsize(args.output)} B")
    return str(out_path)   # actual written path (possibly auto-renamed); the GUI uses it to show the result


def read_archive_meta(path: str):
    with open(path, "rb") as f:
        hdr = f.read(HEADER_LEN)
    magic, ver, chunk_size, n, iterations, manifest_len, orig_len, salt1, salt2, perm_check, table_offset = \
        struct.unpack(HEADER_FMT, hdr)
    if magic != MAGIC:
        sys.exit("Not a shuffle-arc archive file (magic mismatch)")
    if ver not in (LEGACY_V1, VERSION):
        sys.exit(f"Unsupported version: {ver}")
    return dict(version=ver, chunk_size=chunk_size, n=n, iterations=iterations,
                manifest_len=manifest_len, orig_len=orig_len,
                salt1=salt1, salt2=salt2, perm_check=perm_check,
                table_offset=table_offset)


def read_entries(path: str, n: int, table_offset: int) -> list:
    with open(path, "rb") as f:
        f.seek(table_offset)
        raw = f.read(n * ENTRY_LEN)
    return [struct.unpack(ENTRY_FMT, raw[i:i + ENTRY_LEN]) for i in range(0, len(raw), ENTRY_LEN)]


def _read_payload_of(path: str, entry):
    nonce, clen, olen, off = entry
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(clen)


def unpack(args, progress=None, precomputed=None):
    """progress(done, total, stage): called back after each processed chunk (for the GUI progress bar).
    precomputed=(meta, enc_key, shuf_key): skips header reading and key derivation (prepared by prep_unpack)."""
    if precomputed is not None:
        meta, enc_key, shuf_key = precomputed
    else:
        meta = read_archive_meta(args.input)
        enc_key, shuf_key = derive_keys(args.enc_pass, args.shuffle_pass,
                                        meta["salt1"], meta["salt2"], meta["iterations"])
    # verify the shuffle password (HMAC is fast; always run, even with precomputed values, to prevent tampering)
    if not hmac.compare_digest(hmac.new(shuf_key, PERM_CHECK_LABEL, hashlib.sha256).digest(),
                               meta["perm_check"]):
        sys.exit("Wrong shuffle password, or the archive is corrupted!")
    if meta["version"] == LEGACY_V1:
        return _unpack_v1(args, meta, enc_key, shuf_key, progress)
    return _unpack_v3(args, meta, enc_key, shuf_key, progress)


def _unpack_v3(args, meta, enc_key, shuf_key, progress):
    """v3: plaintext manifest + unique-chunk pool + reassembly by references."""
    n = meta["n"]                       # number of unique chunks
    manifest_len = meta["manifest_len"]
    with open(args.input, "rb") as f:
        f.seek(HEADER_LEN)
        manifest_bytes = f.read(manifest_len)
    try:
        files = parse_manifest_v3(manifest_bytes)      # [(relpath, size, refs)]
    except ValueError as e:
        sys.exit(str(e))
    if not files:
        print("unpack done: archive is empty (no files)")
        return str(args.output)
    dir_mode = any("/" in rel for rel, _, _ in files) or len(files) > 1
    tail_steps = len(files) if dir_mode else 1
    total = 1 + n + tail_steps

    entries = read_entries(args.input, n, meta["table_offset"])
    global KEY
    KEY = enc_key
    perm = make_perm(n, shuf_key)
    inv = [0] * n
    for s, p in enumerate(perm):
        inv[p] = s

    def _decrypt(slot):
        try:
            return unpack_chunk((slot, entries[slot], _read_payload_of(args.input, entries[slot])))
        except AuthError:
            sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")
        except zstd.ZstdError:
            sys.exit("Decompression failed: the archive is corrupted!")

    if args.chunk is not None:
        # random access: original chunk N in the unique-chunk pool
        orig_idx = args.chunk
        if not (0 <= orig_idx < n):
            sys.exit(f"--chunk {args.chunk} out of range (unique chunk count {n})")
        slot = inv[orig_idx]
        try:
            _, plain = unpack_chunk((slot, entries[slot], _read_payload_of(args.input, entries[slot])))
        except AuthError:
            sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")
        except zstd.ZstdError:
            sys.exit("Decompression failed: the archive is corrupted!")
        out_path = f"{args.output}.chunk{args.chunk}"
        with open(out_path, "wb") as f:
            f.write(plain)
        print(f"random access: unique chunk #{args.chunk} ({len(plain)} B) extracted → {out_path}")
        return str(out_path)

    # decrypt the unique-chunk pool
    blocks = [None] * n
    done = 1
    if progress:
        progress(done, total, "Decrypt & decompress")
    try:
        if args.jobs > 1:
            with Pool(args.jobs, initializer=_init_worker, initargs=(enc_key, ZSTD_LEVEL)) as pool:
                work = [(s, entries[s], _read_payload_of(args.input, entries[s])) for s in range(n)]
                for slot, plain in pool.imap_unordered(unpack_chunk, work):
                    blocks[perm[slot]] = plain
                    done += 1
                    if progress:
                        progress(done, total, "Decrypt & decompress")
        else:
            for s in range(n):                     # single-process: lazy per-chunk reads
                blocks[perm[s]] = _decrypt(s)[1]
                done += 1
                if progress:
                    progress(done, total, "Decrypt & decompress")
    except AuthError:
        sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")

    # reassemble by references and write files
    def _compose(refs):
        parts = []
        for r in refs:
            b = blocks[r]
            if b is None:
                sys.exit("Archive corrupted: a chunk reference points to a nonexistent unique chunk!")
            parts.append(b)
        return b"".join(parts)

    if dir_mode:
        out_dir = Path(args.output)
        if out_dir.exists() and not out_dir.is_dir():
            sys.exit(f"Output path {args.output} exists and is not a directory!")
        top0 = files[0][0].split("/", 1)[0] if "/" in files[0][0] else files[0][0]
        if out_dir.exists() and out_dir.name == top0:
            out_dir = unique_path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        roots = {}          # top-level folder → unique target directory
        first_root = None
        for relpath, size, refs in files:
            if "/" in relpath:
                top, rel = relpath.split("/", 1)
            else:
                top, rel = relpath, ""
            if top not in roots:
                root = unique_path(out_dir / top)
                root.mkdir(parents=True, exist_ok=True)
                roots[top] = root
                if first_root is None:
                    first_root = root
            target = unique_path(roots[top] / rel) if rel else roots[top]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_compose(refs))
            done += 1
            if progress:
                progress(done, total, "Writing files")
        print(f"unpack done: {len(files)} files → {first_root}/")
        return str(first_root)
    else:
        # single-file archive: output is a file path; if the output is a directory, write into it
        relpath, size, refs = files[0]
        if os.path.isdir(args.output) or args.output.endswith(("/", "\\")):
            out_dir = Path(args.output)
            out_dir.mkdir(parents=True, exist_ok=True)
            target = unique_path(out_dir / relpath)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_compose(refs))
            done += 1
            if progress:
                progress(done, total, "Writing files")
            print(f"unpack done: 1 file → {target} ({size} B)")
            return str(target)
        else:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            target = unique_path(Path(args.output))
            target.write_bytes(_compose(refs))
            done += 1
            if progress:
                progress(done, total, "Writing files")
            print(f"unpack done: 1 file → {target} ({size} B)")
            return str(target)


def _unpack_v1(args, meta, enc_key, shuf_key, progress):
    """v1 legacy archive: the manifest is the encrypted chunk 0; data chunks start at 1."""
    n = meta["n"]
    cs = meta["chunk_size"]
    manifest_len = meta["manifest_len"]
    entries = read_entries(args.input, n, meta["table_offset"])
    global KEY
    KEY = enc_key   # --chunk branch decrypts directly in the main process; full branch injects via the worker initializer
    perm = make_perm(n, shuf_key)
    inv = [0] * n
    for s, p in enumerate(perm):
        inv[p] = s

    if args.chunk is not None:
        # chunk 0 is the manifest; --chunk i maps to data chunk i (original index i+1)
        orig_idx = args.chunk + 1
        if not (0 <= orig_idx < n):
            sys.exit(f"--chunk {args.chunk} out of range (data chunk count {n - 1})")
        slot = inv[orig_idx]
        payload = _read_payload_of(args.input, entries[slot])
        try:
            slot_back, plain = unpack_chunk((slot, entries[slot], payload))
        except AuthError:
            sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")
        out_path = f"{args.output}.chunk{args.chunk}"
        with open(out_path, "wb") as f:
            f.write(plain)
        print(f"random access: original chunk {args.chunk} ({len(plain)} B) extracted → {out_path}")
        return str(out_path)

    def _decrypt(slot):
        try:
            return unpack_chunk((slot, entries[slot], _read_payload_of(args.input, entries[slot])))
        except AuthError:
            sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")
        except zstd.ZstdError:
            sys.exit("Decompression failed: the archive is corrupted!")

    # step 1: decrypt the manifest (chunk 0) to determine the file count and total progress steps
    slot0 = inv[0]
    _, manifest_bytes = _decrypt(slot0)
    if len(manifest_bytes) != manifest_len:
        sys.exit("Archive header and data are inconsistent (manifest length mismatch); the archive may be corrupted!")
    files = parse_manifest_v1(manifest_bytes)
    if not files:
        print("unpack done: archive is empty (no files)")
        return str(args.output)
    dir_mode = any("/" in rel for rel, _ in files) or len(files) > 1
    tail_steps = len(files) if dir_mode else 1
    total = n + tail_steps

    logical = bytearray(manifest_len + meta["orig_len"])
    logical[0:manifest_len] = manifest_bytes
    done = 1
    if progress:
        progress(done, total, "Decrypt & decompress")

    # step 2: decrypt the remaining data chunks (original indices 1..n-1)
    def _place_data(slot, plain):
        nonlocal done
        orig_idx = perm[slot]
        start = manifest_len + (orig_idx - 1) * cs
        logical[start:start + len(plain)] = plain
        done += 1
        if progress:
            progress(done, total, "Decrypt & decompress")

    data_slots = [s for s in range(n) if s != slot0]
    try:
        if args.jobs > 1:
            with Pool(args.jobs, initializer=_init_worker, initargs=(enc_key, ZSTD_LEVEL)) as pool:
                work = [(s, entries[s], _read_payload_of(args.input, entries[s])) for s in data_slots]
                for r in pool.imap_unordered(unpack_chunk, work):
                    _place_data(*r)
        else:
            for s in data_slots:                     # single-process: lazy per-chunk reads
                _place_data(*_decrypt(s))
    except AuthError:
        sys.exit("Decryption failed: wrong encryption password, or the archive is corrupted!")

    data = bytes(logical[manifest_len:])

    # step 3: write files (count each file into progress)
    if dir_mode:
        out_dir = Path(args.output)
        if out_dir.exists() and not out_dir.is_dir():
            sys.exit(f"Output path {args.output} exists and is not a directory!")
        top0 = files[0][0].split("/", 1)[0] if "/" in files[0][0] else files[0][0]
        if out_dir.exists() and out_dir.name == top0:
            out_dir = unique_path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        roots = {}          # top-level folder → unique target directory
        first_root = None
        off = 0
        for relpath, length in files:
            if "/" in relpath:
                top, rel = relpath.split("/", 1)
            else:
                top, rel = relpath, ""
            if top not in roots:
                root = unique_path(out_dir / top)
                root.mkdir(parents=True, exist_ok=True)
                roots[top] = root
                if first_root is None:
                    first_root = root
            target = unique_path(roots[top] / rel) if rel else roots[top]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data[off:off + length])
            off += length
            done += 1
            if progress:
                progress(done, total, "Writing files")
        print(f"unpack done: {len(files)} files → {first_root}/")
        return str(first_root)
    else:
        # single-file archive: output is a file path; if the output is a directory, write into it
        if os.path.isdir(args.output) or args.output.endswith(("/", "\\")):
            out_dir = Path(args.output)
            out_dir.mkdir(parents=True, exist_ok=True)
            target = unique_path(out_dir / files[0][0])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            done += 1
            if progress:
                progress(done, total, "Writing files")
            print(f"unpack done: 1 file → {target} ({len(data)} B)")
            return str(target)
        else:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            target = unique_path(Path(args.output))
            target.write_bytes(data)
            done += 1
            if progress:
                progress(done, total, "Writing files")
            print(f"unpack done: 1 file → {target} ({len(data)} B)")
            return str(target)


# ---------------------------------------------------------------- view manifest (no password needed)

def show_list(args):
    """list: read the v3 plaintext manifest; view archive contents without a password."""
    meta = read_archive_meta(args.input)
    if meta["version"] == LEGACY_V1:
        sys.exit("Legacy v1 archive: the manifest is encrypted and cannot be listed without a password; use unpack instead.")
    with open(args.input, "rb") as f:
        f.seek(HEADER_LEN)
        manifest_bytes = f.read(meta["manifest_len"])
    try:
        files = parse_manifest_v3(manifest_bytes)
    except ValueError as e:
        sys.exit(str(e))
    print(f"archive: {args.input}")
    print(f"unique chunks: {meta['n']}  total original size: {meta['orig_len']} B")
    print("-" * 60)
    for relpath, size, refs in files:
        print(f"{size:>12} B  {relpath}  [{len(refs)} chunks]")
    print("-" * 60)
    print(f"{len(files)} file(s) total")


# ---------------------------------------------------------------- wizard mode (for direct use by double-click)

def wizard():
    """Interactive wizard entered when started without arguments (e.g. double-clicking the exe):
    guides pack/unpack/list, then waits for Enter before exiting."""
    print("=" * 56)
    print(" shuffle-arc  dual-password encrypted archive tool  (v3)")
    print(" pack:   file/dir → encrypted compressed archive (.far) (auto dedup)")
    print(" unpack: archive → restore files")
    print(" list:   show files inside the archive (no password needed)")
    print("=" * 56)
    print("Security reminder: two mutually independent passwords are required")
    print("(encryption password + shuffle password); if you forget either one,")
    print("the data will be permanently unrecoverable — keep them safe!")
    while True:
        choice = input("\nChoose an operation [1=pack, 2=unpack, 3=list, q=quit]: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return
        if choice in ("1", "2", "3"):
            break
        print("Invalid input; please enter 1, 2 or 3")

    import types
    ns = types.SimpleNamespace()
    try:
        if choice == "1":
            ns.input = input("Source file or directory path: ").strip().strip('"')
            ns.output = input("Output archive path (e.g. backup.far): ").strip().strip('"')
            ns.enc_pass = _ask("Encryption")
            ns.shuffle_pass = _ask("Shuffle")
            if ns.enc_pass == ns.shuffle_pass:
                sys.exit("The two passwords must be different and mutually independent!")
            ns.chunk_size = DEFAULT_CHUNK
            ns.iter = DEFAULT_ITER
            ns.jobs = max(1, cpu_count())
            pack(ns)
        elif choice == "2":
            ns.input = input("Archive path: ").strip().strip('"')
            ns.output = input("Output path (single-file archive = file path; multiple files = directory): ").strip().strip('"')
            ns.enc_pass = _ask("Encryption")
            ns.shuffle_pass = _ask("Shuffle")
            if ns.enc_pass == ns.shuffle_pass:
                sys.exit("The two passwords must be different and mutually independent!")
            ns.jobs = max(1, cpu_count())
            ns.chunk = None
            unpack(ns)
        else:
            ns.input = input("Archive path: ").strip().strip('"')
            show_list(ns)
    except SystemExit as e:
        print(f"\n[error] {e}")
    except Exception as e:
        print(f"\n[failed] {type(e).__name__}: {e}")
    input("\nPress Enter to exit...")


# ---------------------------------------------------------------- CLI

def _ask(which: str) -> str:
    """Password prompt: use input() instead of getpass (getpass fails to read the console
    inside a PyInstaller-frozen exe). Note: the input is echoed in plaintext here."""
    return input(f"{which} password: ").strip()


def main():
    # fix the Windows console encoding (for code pages like cp932 that cannot print non-ASCII)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # no arguments (double-clicked exe) → enter the interactive wizard to avoid a flashing, instantly-closing window
    if len(sys.argv) == 1:
        wizard()
        return

    ap = argparse.ArgumentParser(description="Dual-password chunked-shuffle encrypted compression archive tool (shuffle-arc v3)")
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("pack", help="pack and encrypt (auto chunk-level dedup)")
    p.add_argument("-i", "--input", required=True, help="input file or directory")
    p.add_argument("-o", "--output", required=True, help="output .far archive")
    p.add_argument("-e", "--enc-pass", help="encryption password (prompted interactively if omitted)")
    p.add_argument("-s", "--shuffle-pass", help="shuffle password (prompted interactively if omitted)")
    p.add_argument("-c", "--chunk-size", type=int, default=DEFAULT_CHUNK, help=f"chunk size (dedup granularity), default {DEFAULT_CHUNK}")
    p.add_argument("-z", "--zstd-level", type=int, default=None, help=f"zstd compression level, default {ZSTD_LEVEL} (higher = better ratio, slower)")
    p.add_argument("-I", "--iter", type=int, default=DEFAULT_ITER, help=f"PBKDF2 iteration count, default {DEFAULT_ITER}")
    p.add_argument("-j", "--jobs", type=int, default=max(1, cpu_count()), help="number of parallel processes")
    p.set_defaults(func=pack)

    u = sub.add_parser("unpack", help="unpack and decrypt")
    u.add_argument("-i", "--input", required=True, help="input .far archive")
    u.add_argument("-o", "--output", required=True, help="output file (single-file archive) or directory (multiple files)")
    u.add_argument("-e", "--enc-pass", help="encryption password (prompted interactively if omitted)")
    u.add_argument("-s", "--shuffle-pass", help="shuffle password (prompted interactively if omitted)")
    u.add_argument("-j", "--jobs", type=int, default=max(1, cpu_count()), help="number of parallel processes")
    u.add_argument("--chunk", type=int, default=None, help="random access: extract only original chunk N from the unique-chunk pool")
    u.set_defaults(func=unpack)

    l = sub.add_parser("list", help="list files in the archive (v3 plaintext manifest, no password needed)")
    l.add_argument("-i", "--input", required=True, help="input .far archive")
    l.set_defaults(func=show_list)

    args = ap.parse_args()
    if args.mode in ("pack", "unpack"):
        if not args.enc_pass:
            args.enc_pass = _ask("Encryption")
        if not args.shuffle_pass:
            args.shuffle_pass = _ask("Shuffle")
        if args.enc_pass == args.shuffle_pass:
            sys.exit("The two passwords must be different and mutually independent!")
    args.func(args)


if __name__ == "__main__":
    from multiprocessing import freeze_support
    freeze_support()   # required bootstrap for multiprocessing in a PyInstaller-frozen exe
    main()
