# -*- coding: utf-8 -*-
"""
shuffle-arc 图形面板（单窗口三步流程）
  第一步：浏览选择文件/目录 → 第二步：设置两个密码 → 第三步：进度条
  完成后自动返回第一步。
  要点：全程同一个窗口、同一个容器面板，切换步骤时“原地刷新”内容，
  不新建窗口、不新建页面。
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
    """自绘选择器（替换全部原生对话框）：
    mode="folder" → 只显示文件夹目录树，选文件夹；
    mode="file"   → 目录+文件树，选文件（filetypes 过滤显示，如 [".far"]）。
    懒加载 + 占位符：有子目录的节点必然出现“+”号，可逐级展开到任意深度。"""

    def __init__(self, parent, title="选择", initial=None, mode="folder", filetypes=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("620x500")
        self.minsize(520, 380)
        self.result = None
        self.mode = mode
        self.filetypes = filetypes or []
        self.show_all = tk.BooleanVar(value=False)
        self.selected = tk.StringVar()
        self._ph = {}          # node_iid -> [占位符 iid 列表]
        self._ph_seq = 0       # 占位符 iid 单调递增，永不复用

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="当前选择:").pack(side="left")
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
            ttk.Checkbutton(btns, text="显示所有文件", variable=self.show_all,
                            command=self._refresh).pack(side="left")
        ttk.Button(btns, text="新建文件夹", command=self._new_folder).pack(side="left", padx=6)
        ttk.Button(btns, text="刷新", command=self._refresh).pack(side="left", padx=4)
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="选择此文件夹" if mode == "folder" else "选择此文件",
                   command=self._ok).pack(side="right")

        self._populate_drives()
        self._try_select(initial)
        self.transient(parent)
        self.grab_set()

    # ---------- 树操作 ----------
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
        """该目录是否有可展开的内容：子目录，或（文件模式下）可见文件。"""
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
        """把 node 下的子目录（及文件）填入树；有可展开内容的节点补占位符以显示“+”。"""
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
                        # 已展开的目录直接填真实内容，绝不留可见占位符
                        self._open_node(full)
                    else:
                        # 占位符子节点让 Treeview 显示“+”（iid 单调递增，绝不复用）
                        self._ph_seq += 1
                        ph = f"@ph{self._ph_seq}"
                        self.tree.insert(full, "end", iid=ph, text="")
                        self._ph.setdefault(full, []).append(ph)
        for name in files:
            full = os.path.join(node, name)
            if full not in existing:
                self.tree.insert(node, "end", iid=full, text=name, tags=("file",))

    def _open_node(self, node):
        """展开节点：移除占位符并填入真实子内容（保证不留可见空行）。"""
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
            # 文件：双击直接确认
            self._ok()

    def _populate_drives(self):
        for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{d}:\\"):
                self.tree.insert("", "end", iid=f"{d}:\\", text=f"{d}:\\")

    def _try_select(self, path):
        """展开到 initial 路径并选中它（文件模式会定位到文件所在目录并选中文件）。"""
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

    # ---------- 辅助按钮 ----------
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
            messagebox.showwarning("提示", "请先在上方选择一个文件夹作为新建位置", parent=self)
            return
        name = simpledialog.askstring("新建文件夹", "文件夹名称:", parent=self)
        if not name:
            return
        path = os.path.join(base, name)
        try:
            os.makedirs(path)
        except OSError as e:
            messagebox.showerror("出错", str(e), parent=self)
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
                messagebox.showwarning("提示", "请选择一个文件夹", parent=self)
                return
        else:
            if not os.path.isfile(chosen):
                messagebox.showwarning("提示", "请选择一个文件", parent=self)
                return
        self.result = chosen
        self.destroy()


class App:
    def __init__(self, root):
        self.root = root
        root.title("shuffle-arc 双密码加密压缩")
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

    # ---------------- 原地刷新面板（不新建页面） ----------------
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

    # ---------------- 第一步：浏览选择文件 ----------------
    def _step1(self):
        ttk.Label(self.container, text="第一步：选择要处理的文件/目录",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 8))

        # 分组 1：操作模式
        g1 = ttk.LabelFrame(self.container, text=" 操作模式 ", padding=8)
        g1.pack(fill="x", pady=(0, 6))
        row = ttk.Frame(g1)
        row.pack(anchor="w")
        ttk.Radiobutton(row, text="打包加密", variable=self.mode, value="pack",
                        command=self._on_mode).pack(side="left")
        ttk.Radiobutton(row, text="解包解密", variable=self.mode, value="unpack",
                        command=self._on_mode).pack(side="left", padx=14)
        ttk.Label(g1, text="（打包=文件/文件夹→.far 归档；解包=.far→还原）",
                  foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # 分组 2：源路径
        g2 = ttk.LabelFrame(self.container, text=" 源文件/目录 ", padding=8)
        g2.pack(fill="x")
        row = ttk.Frame(g2)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.src).pack(side="left", fill="x", expand=True)
        self.btn_file = ttk.Button(row, text="选文件", command=self._browse_file)
        self.btn_dir = ttk.Button(row, text="选文件夹", command=self._browse_dir)
        self.btn_file.pack(side="left", padx=2)
        self.btn_dir.pack(side="left", padx=2)
        ttk.Label(g2,
                  text="提示：点“选文件夹/浏览”打开目录树（只显示文件夹），单击选中后点“选择此文件夹”。",
                  foreground="#7f8c8d", font=("", 9), wraplength=480).pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # 分组 3：输出路径
        g3 = ttk.LabelFrame(self.container, text=" 输出路径 ", padding=8)
        g3.pack(fill="x")
        row = ttk.Frame(g3)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.out).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览", command=self._browse_out).pack(side="left", padx=2)

        ttk.Button(self.container, text="下一步", command=self._step1_next).pack(anchor="e", pady=(14, 0))
        self._on_mode()

    def _on_mode(self):
        if not hasattr(self, "btn_file"):
            return
        self.btn_file.pack_forget()
        self.btn_dir.pack_forget()
        if self.mode.get() == "pack":
            self.btn_file.configure(text="选文件")
            self.btn_file.pack(side="left", padx=2)
            self.btn_dir.pack(side="left", padx=2)
        else:
            self.btn_file.configure(text="选 .far 归档")
            self.btn_file.pack(side="left", padx=2)

    def _browse_file(self):
        if self.mode.get() == "pack":
            p = self._pick_file("选择要打包的文件")
        else:
            p = self._pick_file("选择 .far 归档", filetypes=[".far"])
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
        p = self._pick_folder("选择要打包的文件夹", self.src.get().strip() or os.getcwd())
        if p:
            self.src.set(p)
            self._auto_out()

    def _browse_out(self):
        if self.mode.get() == "pack":
            p = self._pick_folder("选择归档保存的文件夹", os.path.dirname(self.out.get()) or os.getcwd())
            if p:
                base = os.path.basename(self.out.get()) or "backup.far"
                if not base.lower().endswith(".far"):
                    base = os.path.splitext(base)[0] + ".far"
                self.out.set(os.path.join(p, base))
        else:
            p = self._pick_folder("选择解包输出目录", os.path.dirname(self.out.get()) or os.getcwd())
            if p:
                self.out.set(p)

    def _auto_out(self):
        src = self.src.get().strip().strip('"').rstrip("/\\")
        if not src:
            return
        if self.mode.get() == "pack":
            if os.path.isdir(src):
                # 目录名可能含点（如 my.data），不能 splitext
                self.out.set(src + ".far")
            else:
                self.out.set(os.path.splitext(src)[0] + ".far")
        else:
            # 解包默认输出 = 归档所在目录（还原到归档旁边，不生成同名文件夹）
            d = os.path.dirname(src)
            self.out.set(d if d else os.getcwd())

    def _step1_next(self):
        if not self.src.get().strip():
            messagebox.showwarning("提示", "请先选择源文件/目录或 .far 归档")
            return
        if not self.out.get().strip():
            messagebox.showwarning("提示", "请填写输出路径")
            return
        self.show_step(2)

    # ---------------- 第二步：设置两个密码 ----------------
    def _step2(self):
        ttk.Label(self.container, text="第二步：设置两个独立密码",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 8))

        # 分组 1：加密密码
        g1 = ttk.LabelFrame(self.container, text=" 加密密码 ", padding=8)
        g1.pack(fill="x")
        row = ttk.Frame(g1)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.enc,
                  show="" if self.show_enc.get() else "•").pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(row, text="显示", variable=self.show_enc,
                        command=self._refresh_step2).pack(side="left", padx=4)
        ttk.Label(g1, text="保护文件内容（AES-256-GCM）", foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        # 分组 2：打乱密码
        g2 = ttk.LabelFrame(self.container, text=" 打乱密码 ", padding=8)
        g2.pack(fill="x")
        row = ttk.Frame(g2)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.shuf,
                  show="" if self.show_shuf.get() else "•").pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(row, text="显示", variable=self.show_shuf,
                        command=self._refresh_step2).pack(side="left", padx=4)
        ttk.Label(g2, text="保护块顺序（密钥化乱序，置换不入档）", foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        ttk.Separator(self.container).pack(fill="x", pady=8)

        ttk.Label(self.container,
                  text="⚠ 两个密码相互独立，忘记任何一个，数据将永久无法恢复！",
                  foreground="#c0392b", wraplength=480).pack(anchor="w", pady=(4, 4))

        row = ttk.Frame(self.container)
        row.pack(anchor="e", pady=(10, 0))
        ttk.Button(row, text="上一步", command=lambda: self.show_step(1)).pack(side="left", padx=4)
        ttk.Button(row, text="下一步", command=self._step2_next).pack(side="left")

    def _refresh_step2(self):
        if self.step == 2:
            self.show_step(2)

    def _step2_next(self):
        e, s = self.enc.get().strip(), self.shuf.get().strip()
        if not e or not s:
            messagebox.showwarning("提示", "两个密码都不能为空")
            return
        if e == s:
            messagebox.showwarning("提示", "两个密码必须不同且相互独立！")
            return
        # 提前准备（后台）：打包→预读源；解包→预派生密钥+校验打乱密码
        # 这样进入第三步时进度条直接开始走，不再卡在“准备中”
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

    # ---------------- 第三步：进度条 ----------------
    def _step3(self):
        ttk.Label(self.container, text="第三步：处理中，请稍候…",
                  font=("", 11, "bold")).pack(anchor="w", pady=(0, 12))
        self.pbar = ttk.Progressbar(self.container, mode="indeterminate")
        self.pbar.pack(fill="x", pady=8)
        self.pbar.start(20)
        self.status = ttk.Label(self.container, text="正在准备…")
        self.status.pack(anchor="w", pady=4)

        self.busy = True
        self._start_worker_when_ready()

    def _start_worker_when_ready(self):
        if self._prep_error is not None:
            return                      # 准备失败：_poll 已弹错并重置
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
                jobs=1,                 # GUI 内单进程执行，避免冻结 exe 的多进程问题
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
                    messagebox.showerror("出错", f"准备失败：\n{payload}")
                    self._reset()
                elif kind == "done":
                    self.busy = False
                    verb = "打包" if self.mode.get() == "pack" else "解包"
                    shown = payload if payload else self.out.get()
                    messagebox.showinfo("完成", f"{verb}完成！\n结果已保存到：\n{shown}")
                    self._reset()
                elif kind == "error":
                    self.busy = False
                    verb = "打包" if self.mode.get() == "pack" else "解包"
                    messagebox.showerror("出错", f"{verb}失败：\n{payload}")
                    self._reset()
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _reset(self):
        # 完成/出错后返回第一步，清空所有输入与准备状态
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
            messagebox.showerror("shuffle-arc", "程序启动失败，详情见 shuffle-arc-error.log")
        except Exception:
            pass
        raise
