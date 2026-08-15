# -*- coding: utf-8 -*-
"""
shuffle-arc GUI panel (single-window, three-step flow)
  Step 1: browse and select a file/directory → Step 2: set the two passwords → Step 3: progress bar
  Returns to step 1 automatically when finished.
  Key point: one window and one container panel throughout; switching steps refreshes the
  content in place — no new windows, no new pages.
"""

import os
import queue
import sys
import threading
import traceback
import types

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox

import shuffle_arc as core


def _log_path():
    try:
        base = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
    except Exception:
        base = os.getcwd()
    return os.path.join(base, "shuffle-arc-error.log")


def _log_crash():
    try:
        with open(_log_path(), "a", encoding="utf-8") as f:
            f.write(traceback.format_exc())
            f.write("\n" + "=" * 40 + "\n")
    except Exception:
        pass


class TreePicker(tk.Toplevel):
    """Self-drawn picker (replaces all native dialogs):
    mode="folder" → shows a folder-only directory tree; picks a folder;
    mode="file"   → shows a directory+file tree; picks a file (filetypes filter the display, e.g. [".far"]).
    Lazy loading + placeholders: any node with subdirectories always shows a "+", expandable to any depth."""

    def __init__(self, parent, title="Select", initial=None, mode="folder", filetypes=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("620x500")
        self.minsize(520, 380)
        self.result = None
        self.mode = mode
        self.filetypes = filetypes or []
        self.show_all = tk.BooleanVar(value=False)
        self.selected = tk.StringVar()
        self._ph = {}          # node_iid -> [placeholder iid list]
        self._ph_seq = 0       # placeholder iids increase monotonically and are never reused

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Current selection:").pack(side="left")
        ttk.Entry(top, textvariable=self.selected).pack(side="left", fill="x", expand=True, padx=6)

        self.tree = ttk.Treeview(self, show="tree", selectmode="browse")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tree.tag_configure("dir", foreground="#1a1a1a")
        self.tree.tag_configure("file", foreground="#8a8a8a")
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_double)

        btns = ttk.Frame(self, padding=8)
        btns.pack(fill="x")
        if self.mode == "file" and self.filetypes:
            ttk.Checkbutton(btns, text="Show all files", variable=self.show_all,
                            command=self._refresh).pack(side="left")
        ttk.Button(btns, text="New folder", command=self._new_folder).pack(side="left", padx=6)
        ttk.Button(btns, text="Refresh", command=self._refresh).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="Choose this folder" if mode == "folder" else "Choose this file",
                   command=self._ok).pack(side="right")

        self._populate_drives()
        self._try_select(initial)
        self.transient(parent)
        self.grab_set()

    # ---------- tree operations ----------
    def _entry_ok(self, node, name):
        full = os.path.join(node, name)
        if self.mode == "file":
            if not os.path.isfile(full):
                return None
            if self.show_all.get() or not self.filetypes:
                return "file"
            if os.path.splitext(name)[1].lower() in self.filetypes:
                return "file"
            return None
        return "dir" if os.path.isdir(full) else None

    def _has_children(self, full):
        """Whether the directory has expandable content: subdirectories, or (in file mode) visible files."""
        try:
            entries = os.listdir(full)
        except OSError:
            return False
        for n in entries:
            p = os.path.join(full, n)
            if os.path.isdir(p):
                return True
            if self.mode == "file" and self._entry_ok(full, n) == "file":
                return True
        return False

    def _fill(self, node):
        """Fill the tree with node's subdirectories (and files); add a placeholder to nodes with expandable content so the "+" shows."""
        try:
            names = os.listdir(node)
        except OSError:
            return
        dirs = sorted([n for n in names if os.path.isdir(os.path.join(node, n))], key=str.lower)
        files = sorted([n for n in names if self._entry_ok(node, n) == "file"], key=str.lower)
        existing = set(self.tree.get_children(node))
        for name in dirs:
            full = os.path.join(node, name)
            if full not in existing:
                self.tree.insert(node, "end", iid=full, text=name, tags=("dir",))
            if full not in self._ph:
                if self._has_children(full):
                    if self.tree.item(full, "open"):
                        # already-open directories get real content directly; never leave a visible placeholder
                        self._open_node(full)
                    else:
                        # a placeholder child makes Treeview show "+" (iids increase monotonically, never reused)
                        self._ph_seq += 1
                        ph = f"@ph{self._ph_seq}"
                        self.tree.insert(full, "end", iid=ph, text="")
                        self._ph.setdefault(full, []).append(ph)
        for name in files:
            full = os.path.join(node, name)
            if full not in existing:
                self.tree.insert(node, "end", iid=full, text=name, tags=("file",))

    def _open_node(self, node):
        """Expand a node: remove placeholders and fill in real children (ensures no visible blank rows remain)."""
        for ph in self._ph.pop(node, []):
            try:
                self.tree.delete(ph)
            except tk.TclError:
                pass
        self._fill(node)

    def _on_open(self, event):
        node = self.tree.focus()
        if node:
            self._open_node(node)

    def _on_select(self, event):
        sel = self.tree.selection()
        if sel:
            self.selected.set(sel[0])

    def _on_double(self, event):
        node = self.tree.identify_row(event.y)
        if not node:
            return
        self.tree.selection_set(node)
        self.selected.set(node)
        if os.path.isdir(node):
            if self.tree.item(node, "open"):
                self.tree.item(node, open=False)
            else:
                self.tree.item(node, open=True)
                self._on_open(event)
        else:
            # file: double-click confirms directly
            self._ok()

    def _populate_drives(self):
        for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{d}:\\"):
                self.tree.insert("", "end", iid=f"{d}:\\", text=f"{d}:\\")

    def _try_select(self, path):
        """Expand to the initial path and select it (in file mode, locates the file's directory and selects the file)."""
        if not path:
            return
        path = os.path.abspath(path)
        target = None
        if os.path.isfile(path):
            target = path
            path = os.path.dirname(path)
        elif not os.path.isdir(path):
            path = os.path.dirname(path)
        self.selected.set(target or path)
        drive, rest = os.path.splitdrive(path)
        if not drive:
            return
        drive = drive + "\\"
        cur = drive
        if self.tree.exists(cur):
            self.tree.item(cur, open=True)
            self._open_node(cur)
        segs = [s for s in rest.replace("/", "\\").split("\\") if s]
        for seg in segs:
            nxt = os.path.join(cur, seg)
            if self.tree.exists(nxt):
                self.tree.item(nxt, open=True)
                self._open_node(nxt)
                cur = nxt
            else:
                break
        if target and self.tree.exists(target):
            self.tree.selection_set(target)
            self.tree.see(target)
        elif self.tree.exists(path):
            self.tree.selection_set(path)
            self.tree.see(path)

    # ---------- helper buttons ----------
    def _refresh(self):
        for item in self.tree.get_children(""):
            self.tree.delete(item)
        self._ph.clear()
        self._populate_drives()
        self._try_select(self.selected.get())

    def _new_folder(self):
        sel = self.tree.selection()
        base = sel[0] if sel else self.selected.get().strip()
        if not base or not os.path.isdir(base):
            messagebox.showwarning("Notice", "Please select a folder above as the location for the new folder", parent=self)
            return
        name = simpledialog.askstring("New folder", "Folder name:", parent=self)
        if not name:
            return
        path = os.path.join(base, name)
        try:
            os.makedirs(path)
        except OSError as e:
            messagebox.showerror("Error", str(e), parent=self)
            return
        self._fill(base)
        self.tree.selection_set(path)
        self.selected.set(path)
        self.tree.see(path)

    def _ok(self):
        sel = self.tree.selection()
        chosen = sel[0] if sel else self.selected.get().strip()
        if not chosen:
            return
        if self.mode == "folder":
            if not os.path.isdir(chosen):
                messagebox.showwarning("Notice", "Please choose a folder", parent=self)
                return
        else:
            if not os.path.isfile(chosen):
                messagebox.showwarning("Notice", "Please choose a file", parent=self)
                return
        self.result = chosen
        self.destroy()


class App:
    def __init__(self, root):
        self.root = root
        root.title("shuffle-arc dual-password encrypted archive")
        root.geometry("560x430")
        root.minsize(500, 400)
        root.resizable(True, True)

        self.q = queue.Queue()
        self.step = 0
        self.busy = False

        self.mode = tk.StringVar(value="pack")
        self.src = tk.StringVar()
        self.out = tk.StringVar()
        self.enc = tk.StringVar()
        self.shuf = tk.StringVar()
        self.show_enc = tk.BooleanVar(value=False)
        self.show_shuf = tk.BooleanVar(value=False)

        self.pbar = None
        self.status = None
        self._prep = None
        self._prep_error = None
        self._prep_params = None

        self.container = ttk.Frame(root, padding=16)
        self.container.pack(fill="both", expand=True)
        self.show_step(1)
        self.root.after(120, self._poll)

    # ---------------- in-place panel refresh (no new pages) ----------------
    def show_step(self, n):
        for w in self.container.winfo_children():
            w.destroy()
        self.step = n
        if n == 1:
            self._step1()
        elif n == 2:
            self._step2()
        elif n == 3:
            self._step3()

    # ---------------- step 1: browse and select files ----------------
    def _step1(self):
        ttk.Label(self.container, text="Step 1: select the file/directory to process",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 8))

        # group 1: operation mode
        g1 = ttk.LabelFrame(self.container, text=" Operation mode ", padding=8)
        g1.pack(fill="x", pady=(0, 6))
        row = ttk.Frame(g1)
        row.pack(anchor="w")
        ttk.Radiobutton(row, text="Pack & encrypt", variable=self.mode, value="pack",
                        command=self._on_mode).pack(side="left")
        ttk.Radiobutton(row, text="Unpack & decrypt", variable=self.mode, value="unpack",
                        command=self._on_mode).pack(side="left", padx=14)
        ttk.Label(g1, text="(pack = file/folder → .far archive; unpack = .far → restore)",
                  foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # group 2: source path
        g2 = ttk.LabelFrame(self.container, text=" Source file/directory ", padding=8)
        g2.pack(fill="x")
        row = ttk.Frame(g2)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.src).pack(side="left", fill="x", expand=True)
        self.btn_file = ttk.Button(row, text="Select file", command=self._browse_file)
        self.btn_dir = ttk.Button(row, text="Select folder", command=self._browse_dir)
        self.btn_file.pack(side="left", padx=2)
        self.btn_dir.pack(side="left", padx=2)
        ttk.Label(g2,
                  text="Tip: click \"Select folder / Browse\" to open the directory tree (folders only); click a folder, then click \"Choose this folder\".",
                  foreground="#7f8c8d", font=("", 9), wraplength=480).pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # group 3: output path
        g3 = ttk.LabelFrame(self.container, text=" Output path ", padding=8)
        g3.pack(fill="x")
        row = ttk.Frame(g3)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.out).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=self._browse_out).pack(side="left", padx=2)

        ttk.Button(self.container, text="Next", command=self._step1_next).pack(anchor="e", pady=(14, 0))
        self._on_mode()

    def _on_mode(self):
        if not hasattr(self, "btn_file"):
            return
        self.btn_file.pack_forget()
        self.btn_dir.pack_forget()
        if self.mode.get() == "pack":
            self.btn_file.configure(text="Select file")
            self.btn_file.pack(side="left", padx=2)
            self.btn_dir.pack(side="left", padx=2)
        else:
            self.btn_file.configure(text="Select .far archive")
            self.btn_file.pack(side="left", padx=2)

    def _browse_file(self):
        if self.mode.get() == "pack":
            p = self._pick_file("Select the file to pack")
        else:
            p = self._pick_file("Select the .far archive", filetypes=[".far"])
        if p:
            self.src.set(p)
            self._auto_out()

    def _pick_folder(self, title, initial=None):
        if not initial:
            initial = self.src.get().strip() or os.getcwd()
        picker = TreePicker(self.root, title=title, initial=initial, mode="folder")
        self.root.wait_window(picker)
        return picker.result

    def _pick_file(self, title, initial=None, filetypes=None):
        if not initial:
            initial = self.src.get().strip() or os.getcwd()
        picker = TreePicker(self.root, title=title, initial=initial, mode="file",
                            filetypes=filetypes)
        self.root.wait_window(picker)
        return picker.result

    def _browse_dir(self):
        p = self._pick_folder("Select the folder to pack", self.src.get().strip() or os.getcwd())
        if p:
            self.src.set(p)
            self._auto_out()

    def _browse_out(self):
        if self.mode.get() == "pack":
            p = self._pick_folder("Select the folder to save the archive", os.path.dirname(self.out.get()) or os.getcwd())
            if p:
                base = os.path.basename(self.out.get()) or "backup.far"
                if not base.lower().endswith(".far"):
                    base = os.path.splitext(base)[0] + ".far"
                self.out.set(os.path.join(p, base))
        else:
            p = self._pick_folder("Select the unpack output directory", os.path.dirname(self.out.get()) or os.getcwd())
            if p:
                self.out.set(p)

    def _auto_out(self):
        src = self.src.get().strip().strip('"').rstrip("/\\")
        if not src:
            return
        if self.mode.get() == "pack":
            if os.path.isdir(src):
                # directory names may contain dots (e.g. my.data); do not splitext
                self.out.set(src + ".far")
            else:
                self.out.set(os.path.splitext(src)[0] + ".far")
        else:
            # unpack default output = the archive's directory (restore next to the archive, no same-named folder created)
            d = os.path.dirname(src)
            self.out.set(d if d else os.getcwd())

    def _step1_next(self):
        if not self.src.get().strip():
            messagebox.showwarning("Notice", "Please select a source file/directory or a .far archive first")
            return
        if not self.out.get().strip():
            messagebox.showwarning("Notice", "Please fill in the output path")
            return
        self.show_step(2)

    # ---------------- step 2: set the two passwords ----------------
    def _step2(self):
        ttk.Label(self.container, text="Step 2: set two independent passwords",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 8))

        # group 1: encryption password
        g1 = ttk.LabelFrame(self.container, text=" Encryption password ", padding=8)
        g1.pack(fill="x")
        row = ttk.Frame(g1)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.enc,
                  show="" if self.show_enc.get() else "•").pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(row, text="Show", variable=self.show_enc,
                        command=self._refresh_step2).pack(side="left", padx=4)
        ttk.Label(g1, text="Protects the file contents (AES-256-GCM)", foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # group 2: shuffle password
        g2 = ttk.LabelFrame(self.container, text=" Shuffle password ", padding=8)
        g2.pack(fill="x")
        row = ttk.Frame(g2)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.shuf,
                  show="" if self.show_shuf.get() else "•").pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(row, text="Show", variable=self.show_shuf,
                        command=self._refresh_step2).pack(side="left", padx=4)
        ttk.Label(g2, text="Protects the chunk order (keyed shuffling; the permutation is not stored in the archive)", foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        ttk.Label(self.container,
                  text="⚠ The two passwords are independent; if you forget either one, the data will be permanently unrecoverable!",
                  foreground="#c0392b", wraplength=480).pack(anchor="w", pady=(4, 4))

        row = ttk.Frame(self.container)
        row.pack(anchor="e", pady=(10, 0))
        ttk.Button(row, text="Back", command=lambda: self.show_step(1)).pack(side="left", padx=4)
        ttk.Button(row, text="Next", command=self._step2_next).pack(side="left")

    def _refresh_step2(self):
        if self.step == 2:
            self.show_step(2)

    def _step2_next(self):
        e, s = self.enc.get().strip(), self.shuf.get().strip()
        if not e or not s:
            messagebox.showwarning("Notice", "Both passwords are required")
            return
        if e == s:
            messagebox.showwarning("Notice", "The two passwords must be different and mutually independent!")
            return
        # prepare in advance (background): pack → pre-read the source; unpack → pre-derive keys + verify the shuffle password
        # so the progress bar starts immediately on step 3 instead of hanging on "preparing"
        self._prep = None
        self._prep_error = None
        self._prep_params = dict(
            mode=self.mode.get(),
            src=self.src.get().strip().strip('"'),
            out=self.out.get().strip().strip('"'),
            enc=e,
            shuf=s,
        )
        t = threading.Thread(target=self._prepare, args=(self._prep_params,), daemon=True)
        t.start()
        self.show_step(3)

    def _prepare(self, params):
        try:
            if params["mode"] == "pack":
                prebuilt = core.prep_pack(params["src"])
                self.q.put(("prep_done", {"kind": "pack", "prebuilt": prebuilt}))
            else:
                precomputed = core.prep_unpack(params["src"], params["enc"], params["shuf"])
                self.q.put(("prep_done", {"kind": "unpack", "precomputed": precomputed}))
        except SystemExit as e:
            self.q.put(("prep_error", str(e)))
        except Exception as e:
            self.q.put(("prep_error", f"{type(e).__name__}: {e}"))
            _log_crash()

    # ---------------- step 3: progress bar ----------------
    def _step3(self):
        ttk.Label(self.container, text="Step 3: processing, please wait…",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 12))
        self.pbar = ttk.Progressbar(self.container, mode="indeterminate")
        self.pbar.pack(fill="x", pady=8)
        self.pbar.start(20)
        self.status = ttk.Label(self.container, text="Preparing…")
        self.status.pack(anchor="w", pady=4)

        self.busy = True
        self._start_worker_when_ready()

    def _start_worker_when_ready(self):
        if self._prep_error is not None:
            return                      # preparation failed: _poll already showed the error and reset
        if self._prep is not None:
            t = threading.Thread(target=self._worker, args=(self._prep_params, self._prep), daemon=True)
            t.start()
        else:
            self.root.after(80, self._start_worker_when_ready)

    def _worker(self, params, prep):
        try:
            ns = types.SimpleNamespace(
                input=params["src"],
                output=params["out"],
                enc_pass=params["enc"],
                shuffle_pass=params["shuf"],
                jobs=1,                 # single-process inside the GUI to avoid multiprocessing issues in a frozen exe
                chunk=None,
            )
            if params["mode"] == "pack":
                ns.chunk_size = core.DEFAULT_CHUNK
                ns.iter = core.DEFAULT_ITER
                prebuilt = prep.get("prebuilt") if prep else None
                result_path = core.pack(ns, progress=self._progress, prebuilt=prebuilt)
            else:
                precomputed = prep.get("precomputed") if prep else None
                result_path = core.unpack(ns, progress=self._progress, precomputed=precomputed)
            self.q.put(("done", result_path))
        except SystemExit as e:
            self.q.put(("error", str(e)))
        except Exception as e:
            self.q.put(("error", f"{type(e).__name__}: {e}"))
            _log_crash()

    def _progress(self, done, total, stage):
        self.q.put(("prog", (done, total, stage)))

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "prog":
                    done, total, stage = payload
                    if self.pbar is not None and total:
                        if str(self.pbar.cget("mode")) != "determinate":
                            self.pbar.stop()
                            self.pbar.configure(mode="determinate")
                        self.pbar.configure(maximum=total, value=done)
                        self.status.configure(text=f"{stage} {done}/{total}")
                elif kind == "prep_done":
                    self._prep = payload
                elif kind == "prep_error":
                    self._prep_error = payload
                    self.busy = False
                    messagebox.showerror("Error", f"Preparation failed:\n{payload}")
                    self._reset()
                elif kind == "done":
                    self.busy = False
                    verb = "Pack" if self.mode.get() == "pack" else "Unpack"
                    shown = payload if payload else self.out.get()
                    messagebox.showinfo("Done", f"{verb} complete!\nResult saved to:\n{shown}")
                    self._reset()
                elif kind == "error":
                    self.busy = False
                    verb = "Pack" if self.mode.get() == "pack" else "Unpack"
                    messagebox.showerror("Error", f"{verb} failed:\n{payload}")
                    self._reset()
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _reset(self):
        # after finishing/erroring, return to step 1 and clear all inputs and preparation state
        self.src.set("")
        self.out.set("")
        self.enc.set("")
        self.shuf.set("")
        self.show_enc.set(False)
        self.show_shuf.set(False)
        self.pbar = None
        self.status = None
        self._prep = None
        self._prep_error = None
        self._prep_params = None
        self.show_step(1)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    from multiprocessing import freeze_support
    freeze_support()
    try:
        main()
    except Exception:
        _log_crash()
        try:
            messagebox.showerror("shuffle-arc", "Startup failed; see shuffle-arc-error.log for details")
        except Exception:
            pass
        raise
