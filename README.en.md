# shuffle-arc

A CLI/GUI archiver that compresses and encrypts files, then **shuffles the ciphertext blocks** using a permutation derived from a second, independent password.

```
files/dir → split into chunks → zstd-compress each → AES-256-GCM encrypt each → write in permuted order
```

Even if someone gets the archive *and* the encryption password, they cannot reconstruct the original data order — the order is protected by the separate shuffle password. The permutation is never stored; it is derived from the shuffle password every time.

**Two independent passwords, always different:**
- **encryption password** (`-e`) — protects content
- **shuffle password** (`-s`) — protects order

> **Warning:** shuffling protects *order*, not *content*. Both passwords must be strong; "weak encryption + shuffle" is not unbreakable. Forgetting either password means permanent data loss.

## What it does differently

| | shuffle-arc | typical archive tools (7z/zip) |
|---|---|---|
| Encryption | AES-256-GCM per chunk | yes |
| Order protection | keyed permutation, not stored | no |
| Dedup | identical chunks stored once | no |
| Listing | plaintext manifest, `list` without password | depends |
| Random access | `unpack --chunk N` | partial |

It is not a 7z replacement. It is for the case where you want the *layout of the data inside the archive* to be secret too — e.g. which files are big, how many chunks, or that a "file" is actually a stream of repeated blocks.

## Install

**Windows exe (no install):** grab `shuffle-arc-gui.exe` (GUI) or `shuffle-arc-cli.exe` (CLI) from the [Releases](https://github.com/nmhwsygxb/shuffle-arc/releases) page.

**From source (Python 3.9+):**

```bash
pip install -r requirements.txt   # zstandard, pycryptodome
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

If you omit `-e`/`-s`, they are prompted interactively. The two passwords must be different.

Options:

| Option | Default | Meaning |
|---|---|---|
| `-c, --chunk-size` | 4 MiB | chunk size = dedup granularity = encryption block |
| `-z, --zstd-level` | 1 | zstd level (higher = smaller but slower) |
| `-I, --iter` | 300000 | PBKDF2 iterations |
| `-j, --jobs` | CPU count | parallel processes (only helps with many chunks) |

Run with no arguments to get the interactive wizard (`1=pack 2=unpack 3=list`).

The GUI (`shuffle_arc_gui.py` or `shuffle-arc-gui.exe`) is a single window: pick source → set the two passwords → progress bar.

## Performance

Measured on a 3.1 GB folder (Unity assets, mostly incompressible):

| | shuffle-arc | 7z (LZMA2, -mx=1) |
|---|---|---|
| pack | **20.7 s** (150 MB/s) | 67.8 s (46 MB/s) |
| unpack | 41.8 s (74 MB/s) | **36.1 s** (86 MB/s) |
| size | 56.7% | **49.5%** |

Packing is about 3× faster than 7z at the default zstd level 1; 7z compresses somewhat better (LZMA2). Raise `-z` if you want a better ratio — it stays faster than 7z at comparable settings.

## Archive format (v3)

```
┌ header (plaintext, fixed length): magic "SFAR1", version=3, chunk_size,
│ n (unique chunks), iterations, manifest_len, orig_len, salt1, salt2,
│ perm_check (HMAC), table_offset
├ plaintext manifest: one line per file
│   {size}\t{relpath}\t{ref0},{ref1},...
├ encrypted unique-chunk pool, written in permuted order:
│   each chunk = zstd → AES-256-GCM (random nonce, AAD binds the slot)
└ entry table: nonce / cipher_len / orig_len / payload_offset
```

- The permutation is derived from the shuffle password and is **never stored**; `perm[slot]` = original chunk index stored in that slot.
- v1 archives (manifest encrypted as chunk 0) are detected and unpacked automatically.

## Limitations

- Custom format; no forward-compatibility promise (v3 reads v1; future versions will keep reading old ones).
- The plaintext manifest leaks filenames / sizes / chunk counts (a deliberate trade-off for password-free listing).
- Files are read fully into memory; peak memory ≈ source size.
- Use strong random passwords. Order protection ≠ content protection.

## Build & test

```bash
# GUI (windowed, no console window)
py -3.14 -m PyInstaller --onefile --noconsole --name shuffle-arc-gui shuffle_arc_gui.py
# CLI
py -3.14 -m PyInstaller --onefile --name shuffle-arc-cli shuffle_arc.py

python _test_v3.py        # dedup / round-trip / list / random access / wrong password
python _test_v1_gui.py    # v1 compat + GUI prebuilt path
```

## Files

- `shuffle_arc.py` — core (CLI + library)
- `shuffle_arc_gui.py` — GUI
- `shuffle-arc-gui.exe` / `shuffle-arc-cli.exe` — Windows builds (Releases)
- `_test_v3.py`, `_test_v1_gui.py` — regression tests
