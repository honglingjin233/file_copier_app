import os
import shutil
import hashlib
import threading
import base64
import logging
from datetime import datetime, timedelta
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from logging.handlers import RotatingFileHandler

# 配置日志记录
log_file = 'file_copier.log'
# 设置日志文件最大大小为 10MB，保留 3 个备份文件
max_bytes = 10 * 1024 * 1024
backup_count = 3

# 创建 RotatingFileHandler
handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# 获取根日志记录器
root_logger = logging.getLogger()
root_logger.addHandler(handler)
root_logger.setLevel(logging.INFO)


class FileCopierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("定时复制工具 v1.1")
        self.scheduled_job = None
        self.decrypt_thread = None
        self.copy_thread = None
        self.total_files = 0
        self.copied_files = 0
        self.stop_event = threading.Event()
        self.copied_files_list = []
        self.setup_ui()

    def setup_ui(self):
        # 时间设置框架
        time_frame = ttk.LabelFrame(self.root, text="时间设置")
        time_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        ttk.Label(time_frame, text="执行模式:").grid(row=0, column=0)
        self.mode = ttk.Combobox(time_frame, values=["立即执行", "每日", "每小时", "每N小时"])
        self.mode.grid(row=0, column=1)
        self.mode.set("立即执行")
        self.mode.bind("<<ComboboxSelected>>", self.update_ui)

        self.custom_hours_label = ttk.Label(time_frame, text="每N小时:")
        self.custom_hours_label.grid(row=0, column=2, padx=5)
        self.custom_hours = ttk.Spinbox(time_frame, from_=1, to=24, width=5)
        self.custom_hours.grid(row=0, column=3)
        self.custom_hours_label.grid_remove()
        self.custom_hours.grid_remove()

        ttk.Label(time_frame, text="首次执行时间:").grid(row=1, column=0)
        self.start_time = ttk.Entry(time_frame)
        self.start_time.grid(row=1, column=1, sticky="ew")
        self.start_time.insert(0, datetime.now().strftime("%Y-%m-%d %H:%M"))

        # 文件选择框架
        file_frame = ttk.LabelFrame(self.root, text="文件操作")
        file_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        ttk.Button(file_frame, text="选择源文件夹", command=self.select_source).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="选择目标文件夹", command=self.select_dest).grid(row=0, column=1, padx=5)
        self.source_path = ttk.Entry(file_frame)
        self.source_path.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.dest_path = ttk.Entry(file_frame)
        self.dest_path.grid(row=2, column=0, columnspan=2, sticky="ew")

        # 加密设置框架
        crypto_frame = ttk.LabelFrame(self.root, text="加密设置")
        crypto_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.encrypt_var = BooleanVar()
        self.encrypt_cb = ttk.Checkbutton(crypto_frame, text="加密文件",
                                          variable=self.encrypt_var,
                                          command=self.update_password_state)
        self.encrypt_cb.grid(row=0, column=0)
        ttk.Label(crypto_frame, text="加密密码:").grid(row=0, column=1)
        self.encrypt_pwd = ttk.Entry(crypto_frame, show="*", state=DISABLED)
        self.encrypt_pwd.grid(row=0, column=2)

        # 解密设置框架
        decrypt_frame = ttk.LabelFrame(self.root, text="解密设置")
        decrypt_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        ttk.Button(decrypt_frame, text="选择加密文件", command=self.select_encrypted_files).grid(row=0, column=0)
        ttk.Button(decrypt_frame, text="选择输出目录", command=self.select_output_dir).grid(row=0, column=1)

        # 多选文件列表
        self.file_listbox = Listbox(decrypt_frame, height=4, selectmode=MULTIPLE)
        self.file_listbox.grid(row=1, column=0, columnspan=2, sticky="ew")

        # 滚动条
        scrollbar = ttk.Scrollbar(decrypt_frame)
        scrollbar.grid(row=1, column=2, sticky="ns")
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.file_listbox.yview)

        self.output_dir = ttk.Entry(decrypt_frame)
        self.output_dir.grid(row=2, column=0, columnspan=2, sticky="ew")

        ttk.Label(decrypt_frame, text="解密密码:").grid(row=3, column=0)
        self.decrypt_pwd = ttk.Entry(decrypt_frame, show="*")
        self.decrypt_pwd.grid(row=3, column=1, sticky="ew")

        # 进度显示
        self.progress_frame = ttk.Frame(self.root)
        self.progress_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        self.progress = ttk.Progressbar(self.progress_frame, orient=HORIZONTAL, mode='determinate')
        self.progress.pack(fill=X, expand=True)

        self.file_counter = ttk.Label(self.progress_frame, text="0/0 文件")
        self.file_counter.pack()

        # 状态栏
        self.status_var = StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=SUNKEN)
        self.status_bar.grid(row=5, column=0, padx=10, pady=5, sticky="ew")

        # 操作按钮
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=6, column=0, pady=10)
        ttk.Button(button_frame, text="开始计划", command=self.start_copy_job).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="取消任务", command=self.cancel_job).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="解密文件", command=self.start_decrypt_job).grid(row=0, column=2, padx=5)

        # 初始化布局
        self.root.columnconfigure(0, weight=1)
        for frame in [time_frame, file_frame, crypto_frame, decrypt_frame]:
            frame.columnconfigure(1, weight=1)
        self.update_ui()

    def update_password_state(self):
        if self.encrypt_var.get():
            self.encrypt_pwd.config(state=NORMAL)
        else:
            self.encrypt_pwd.delete(0, END)
            self.encrypt_pwd.config(state=DISABLED)

    def generate_key(self, password):
        """从密码生成加密密钥"""
        try:
            password = password.encode()
            salt = b'salt_'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            return base64.urlsafe_b64encode(kdf.derive(password))
        except Exception as e:
            logging.error(f"生成加密密钥时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "生成加密密钥时出错，请检查密码")
            return None

    def update_ui(self, event=None):
        if self.mode.get() == "立即执行":
            self.start_time.config(state=DISABLED)
        else:
            self.start_time.config(state=NORMAL)

        if self.mode.get() == "每N小时":
            self.custom_hours_label.grid()
            self.custom_hours.grid()
        else:
            self.custom_hours_label.grid_remove()
            self.custom_hours.grid_remove()

    def select_source(self):
        try:
            path = filedialog.askdirectory()
            if path:
                self.source_path.delete(0, END)
                self.source_path.insert(0, path)
                logging.info(f"选择源文件夹: {path}")
        except Exception as e:
            logging.error(f"选择源文件夹时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "选择源文件夹时出错，请重试")

    def select_dest(self):
        try:
            path = filedialog.askdirectory()
            if path:
                self.dest_path.delete(0, END)
                self.dest_path.insert(0, path)
                logging.info(f"选择目标文件夹: {path}")
        except Exception as e:
            logging.error(f"选择目标文件夹时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "选择目标文件夹时出错，请重试")

    def select_encrypted_files(self):
        try:
            files = filedialog.askopenfilenames(filetypes=[("加密文件", "*.aes")])
            if files:
                self.file_listbox.delete(0, END)
                for f in files:
                    self.file_listbox.insert(END, f)
                logging.info(f"选择加密文件: {files}")
        except Exception as e:
            logging.error(f"选择加密文件时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "选择加密文件时出错，请重试")

    def select_output_dir(self):
        try:
            path = filedialog.askdirectory()
            if path:
                self.output_dir.delete(0, END)
                self.output_dir.insert(0, path)
                logging.info(f"选择输出目录: {path}")
        except Exception as e:
            logging.error(f"选择输出目录时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "选择输出目录时出错，请重试")

    def safe_update(self, func, *args):
        """线程安全的UI更新"""
        self.root.after(0, func, *args)

    def update_progress(self, value=None, max_value=None):
        if max_value:
            self.progress["maximum"] = max_value
            self.file_counter.config(text=f"0/{max_value} 文件")
        if value is not None:
            self.progress["value"] = value
            self.file_counter.config(text=f"{value}/{self.progress['maximum']} 文件")

    def update_status(self, message):
        self.status_var.set(f"{datetime.now().strftime('%H:%M:%S')} - {message}")
        logging.info(message)

    def count_files(self, path):
        try:
            count = 0
            for root, _, files in os.walk(path):
                count += len(files)
            return count
        except Exception as e:
            logging.error(f"统计文件数量时出错: {str(e)}")
            self.safe_update(messagebox.showerror, "错误", "统计文件数量时出错，请检查路径")
            return 0

    def start_copy_job(self):
        if self.copy_thread and self.copy_thread.is_alive():
            messagebox.showerror("错误", "已有复制任务在进行中")
            logging.error("已有复制任务在进行中")
            return

        self.copy_thread = threading.Thread(target=self.copy_worker)
        self.copy_thread.start()
        logging.info("开始复制任务")

    def copy_worker(self):
        try:
            self.stop_event.clear()
            src = self.source_path.get()
            dest = self.dest_path.get()

            if not all([src, dest]):
                self.safe_update(messagebox.showerror, "错误", "请选择源目录和目标目录")
                logging.error("请选择源目录和目标目录")
                return

            self.safe_update(self.update_status, "正在准备操作...")
            self.total_files = self.count_files(src)
            self.safe_update(self.update_progress, 0, self.total_files)

            key = None
            if self.encrypt_var.get():
                if not self.encrypt_pwd.get():
                    self.safe_update(messagebox.showerror, "错误", "请输入加密密码")
                    logging.error("请输入加密密码")
                    return
                key = self.generate_key(self.encrypt_pwd.get())
                if key is None:
                    return

            self.realtime_copy(src, dest, key)
            self.safe_update(messagebox.showinfo, "成功", "操作完成")
            self.safe_update(self.update_status, "操作成功")
            logging.info("复制任务完成")
        except FileNotFoundError as e:
            self.safe_update(messagebox.showerror, "错误", f"文件未找到: {str(e)}")
            logging.error(f"复制任务中文件未找到: {str(e)}")
        except PermissionError as e:
            self.safe_update(messagebox.showerror, "错误", f"权限不足: {str(e)}")
            logging.error(f"复制任务中权限不足: {str(e)}")
        except Exception as e:
            if str(e) != "用户取消操作":
                self.safe_update(messagebox.showerror, "错误", str(e))
                logging.error(f"复制任务出错: {str(e)}")
            self.safe_update(self.update_status, "已取消" if self.stop_event.is_set() else "失败")
            self.clean_interrupted_files()

    def realtime_copy(self, src, dest, key):
        self.copied_files_list = []
        fernet = Fernet(key) if key else None
        self.copied_files = 0

        for root, _, files in os.walk(src):
            if self.stop_event.is_set():
                raise Exception("用户取消操作")

            rel_path = os.path.relpath(root, src)
            dest_dir = os.path.join(dest, rel_path)
            try:
                os.makedirs(dest_dir, exist_ok=True)
            except PermissionError as e:
                logging.error(f"创建目录 {dest_dir} 时权限不足: {str(e)}")
                self.safe_update(messagebox.showerror, "错误", f"创建目录 {dest_dir} 时权限不足，请检查权限")
                return

            for file in files:
                if self.stop_event.is_set():
                    raise Exception("用户取消操作")

                src_path = os.path.join(root, file)
                dest_file = os.path.join(dest_dir, file)

                try:
                    if fernet:
                        logging.info(f"开始加密文件: {src_path}")
                        start_time = datetime.now()
                        dest_file += ".aes"
                        with open(src_path, "rb") as f:
                            data = fernet.encrypt(f.read())
                        end_time = datetime.now()
                        elapsed_time = (end_time - start_time).total_seconds()
                        logging.info(f"完成加密文件: {src_path} 到 {dest_file}, 耗时: {elapsed_time} 秒")
                    else:
                        with open(src_path, "rb") as f:
                            data = f.read()

                    with open(dest_file, "wb") as f:
                        f.write(data)

                    self.copied_files += 1
                    self.copied_files_list.append(dest_file)
                    self.safe_update(self.update_progress, self.copied_files)
                    logging.info(f"复制文件: {src_path} 到 {dest_file}")

                    if not fernet:
                        if hashlib.sha256(open(src_path, 'rb').read()).hexdigest() != \
                                hashlib.sha256(open(dest_file, 'rb').read()).hexdigest():
                            raise Exception("文件验证失败")
                except FileNotFoundError as e:
                    self._handle_file_error(src_path, "复制", e)
                except PermissionError as e:
                    self._handle_file_error(src_path, "复制", e)
                except IOError as e:  # 新增捕获 IOError
                    self._handle_file_error(src_path, "复制", e)
                except ValueError as e:  # 新增捕获 ValueError
                    self._handle_file_error(src_path, "复制", e)
                except Exception as e:
                    self._handle_file_error(src_path, "复制", e)

    def start_decrypt_job(self):
        if self.decrypt_thread and self.decrypt_thread.is_alive():
            messagebox.showerror("错误", "已有解密任务在进行中")
            logging.error("已有解密任务在进行中")
            return

        file_paths = self.file_listbox.get(0, END)
        output_dir = self.output_dir.get()
        password = self.decrypt_pwd.get()

        if not all([file_paths, output_dir, password]):
            messagebox.showerror("错误", "请填写所有参数")
            logging.error("请填写所有解密参数")
            return

        self.decrypt_thread = threading.Thread(
            target=self.decrypt_worker,
            args=(file_paths, output_dir, password)
        )
        self.decrypt_thread.start()
        logging.info("开始解密任务")

    def decrypt_worker(self, file_paths, output_dir, password):
        try:
            self.stop_event.clear()
            key = self.generate_key(password)
            fernet = Fernet(key)
            total = len(file_paths)
            success = 0
            output_paths = [
                os.path.join(output_dir, os.path.splitext(os.path.basename(f))[0])
                for f in file_paths
            ]

            self.safe_update(self.update_progress, 0, total)

            for index, (src_file, output_path) in enumerate(zip(file_paths, output_paths)):
                if self.stop_event.is_set():
                    self._clean_partial_files(output_paths, index)
                    raise Exception("用户取消操作")

                temp_path = None
                try:
                    logging.info(f"开始解密文件: {src_file}")
                    start_time = datetime.now()
                    temp_path = output_path + ".tmp"
                    if os.path.exists(output_path):
                        raise Exception(f"文件已存在: {os.path.basename(output_path)}")

                    with open(src_file, "rb") as f:
                        data = f.read()

                    decrypted = fernet.decrypt(data)

                    with open(temp_path, "wb") as f:
                        f.write(decrypted)

                    os.replace(temp_path, output_path)
                    end_time = datetime.now()
                    elapsed_time = (end_time - start_time).total_seconds()
                    logging.info(f"完成解密文件: {src_file} 到 {output_path}, 耗时: {elapsed_time} 秒")
                    success += 1
                    self.safe_update(self.update_progress, success)
                    logging.info(f"解密文件: {src_file} 到 {output_path}")
                except FileNotFoundError as e:
                    self._handle_file_error(src_file, "解密", e)
                    self._safe_delete(temp_path)
                    self._safe_delete(output_path)
                    self._clean_partial_files(output_paths, index + 1)
                    return
                except PermissionError as e:
                    self._handle_file_error(src_file, "解密", e)
                    self._safe_delete(temp_path)
                    self._safe_delete(output_path)
                    self._clean_partial_files(output_paths, index + 1)
                    return
                except IOError as e:  # 新增捕获 IOError
                    self._handle_file_error(src_file, "解密", e)
                    self._safe_delete(temp_path)
                    self._safe_delete(output_path)
                    self._clean_partial_files(output_paths, index + 1)
                    return
                except ValueError as e:  # 新增捕获 ValueError
                    self._handle_file_error(src_file, "解密", e)
                    self._safe_delete(temp_path)
                    self._safe_delete(output_path)
                    self._clean_partial_files(output_paths, index + 1)
                    return
                except Exception as e:
                    self._handle_file_error(src_file, "解密", e)
                    self._safe_delete(temp_path)
                    self._safe_delete(output_path)
                    self._clean_partial_files(output_paths, index + 1)
                    return

            self.safe_update(messagebox.showinfo, "完成", f"成功解密 {success}/{total} 个文件")
            self.safe_update(self.update_status, f"解密完成 {success}/{total}")
            logging.info(f"解密任务完成，成功解密 {success}/{total} 个文件")
        except Exception as e:
            if str(e) == "用户取消操作":
                self.safe_update(self.update_status, "解密已取消")
                logging.info("解密任务被用户取消")
            else:
                self.safe_update(self.update_status, "解密失败")
                logging.error(f"解密任务出错: {str(e)}")

    def _clean_partial_files(self, output_paths, index):
        for path in output_paths[index:]:
            self._safe_delete(path)
            self._safe_delete(path + ".tmp")

    def _safe_delete(self, path):
        if path and os.path.exists(path):
            try:
                os.remove(path)
                logging.info(f"删除临时文件: {path}")
            except Exception as e:
                logging.error(f"删除临时文件 {path} 出错: {str(e)}")

    def _handle_file_error(self, file_path, operation, error):
        """封装异常处理逻辑"""
        error_message = f"{operation} 文件 {file_path} 时出错: {str(error)}"
        logging.error(error_message)
        self.safe_update(messagebox.showerror, "错误", error_message)

    def cancel_job(self):
        self.stop_event.set()
        if self.decrypt_thread and self.decrypt_thread.is_alive():
            self.decrypt_thread.join(timeout=0.5)
        if self.copy_thread and self.copy_thread.is_alive():
            self.copy_thread.join(timeout=0.5)
        self.safe_update(self.update_status, "操作已取消")
        logging.info("任务被用户取消")


if __name__ == "__main__":
    root = Tk()
    app = FileCopierApp(root)
    root.mainloop()    