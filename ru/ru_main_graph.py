import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import hashlib
import os
import json
from datetime import datetime
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import random
import string

BLOCK_SIZE = 16
CONFIG_FILE = "app_config.json"
HISTORY_FILE = "operation_history.json"

class CryptoApp(ttk.Window):
    def __init__(self):
        self.config_data = self.load_config()
        self.theme_mode = self.config_data.get('theme', 'light')
        bootstrap_theme = "cosmo" if self.theme_mode == 'light' else "darkly"
        super().__init__(themename=bootstrap_theme)
        self.title("Encoder")
        self.geometry("1200x800")
        self.iconbitmap("путь к вашей иконке")
        self.history = self.load_history()
        self.themes = {
            'light': {
                'bootstrap_theme': 'cosmo',
                'text': '#333333',
                'input_bg': '#ffffff',
                'accent': '#007bff'
            },
            'dark': {
                'bootstrap_theme': 'darkly',
                'text': '#ffffff',
                'input_bg': '#343a40',
                'accent': '#00bc8c'
            }
        }
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        settings_menu.add_command(label="Светлая тема", 
                                  command=lambda: self.change_theme('light'))
        settings_menu.add_command(label="Темная тема", 
                                  command=lambda: self.change_theme('dark'))
        settings_menu.add_command(label="О программе", 
                                  command=lambda: messagebox.showinfo("О программе", "Encoder v1.0\nПриложение для шифрования и дешифрования текста"))
        self.menu_bar.add_cascade(label="Настройки", menu=settings_menu)
        self.notebook = ttk.Notebook(self)
        self.encrypt_frame = self.create_encrypt_tab()
        self.decrypt_frame = self.create_decrypt_tab()
        self.history_frame = self.create_history_tab()
        self.notebook.add(self.encrypt_frame, text="Зашифровать")
        self.notebook.add(self.decrypt_frame, text="Расшифровать")
        self.notebook.add(self.history_frame, text="История")
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def create_encrypt_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        ttk.Label(frame, text="Текст для шифрования:", font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=(10, 5))
        self.encrypt_input = tk.Text(frame, height=10, font=('Segoe UI', 10),
                                     wrap=tk.WORD)
        self.encrypt_input.pack(fill=tk.X, padx=10, pady=10)
        self.encrypt_input.insert(tk.END, "Введите текст для шифрования...")
        self.encrypt_input.bind("<FocusIn>", lambda e: self.clear_placeholder(self.encrypt_input, "Введите текст для шифрования..."))
        self.encrypt_input.bind("<FocusOut>", lambda e: self.restore_placeholder(self.encrypt_input, "Введите текст для шифрования..."))
        encrypt_input_scroll = ttk.Scrollbar(frame, command=self.encrypt_input.yview, bootstyle="round")
        self.encrypt_input.config(yscrollcommand=encrypt_input_scroll.set)
        encrypt_input_scroll.pack_forget()
        self.encrypt_input.bind("<MouseWheel>", lambda e: self.encrypt_input.yview_scroll(-1 * int(e.delta / 120), "units"))
        key_frame = ttk.Frame(frame)
        ttk.Label(key_frame, text="Ключ:", font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.key_entry = ttk.Entry(key_frame, width=50, font=('Segoe UI', 10))
        self.key_entry.pack(side=tk.LEFT, padx=5)
        self.key_entry.insert(0, "Введите или сгенерируйте ключ...")
        self.key_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.key_entry, "Введите или сгенерируйте ключ..."))
        self.key_entry.bind("<FocusOut>", lambda e: self.restore_placeholder(self.key_entry, "Введите или сгенерируйте ключ..."))
        self.generate_key_btn = ttk.Button(key_frame, 
                                          text="Сгенерировать ключ",
                                          command=self.generate_random_key,
                                          bootstyle="info")
        self.generate_key_btn.pack(side=tk.LEFT, padx=5)
        key_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(frame, 
                   text="Зашифровать",
                   command=self.perform_encryption,
                   bootstyle="success",
                   width=20).pack(pady=15)
        
        ttk.Label(frame, text="Результат:", font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=(10, 5))
        self.encrypt_output = tk.Text(frame, height=10, font=('Segoe UI', 10),
                                      wrap=tk.WORD)
        self.encrypt_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.encrypt_output.configure(state='disabled')
        
        encrypt_output_scroll = ttk.Scrollbar(frame, command=self.encrypt_output.yview, bootstyle="round")
        self.encrypt_output.config(yscrollcommand=encrypt_output_scroll.set)
        encrypt_output_scroll.pack_forget()
        self.encrypt_output.bind("<MouseWheel>", lambda e: self.encrypt_output.yview_scroll(-1 * int(e.delta / 120), "units"))
        return frame

    def create_decrypt_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        ttk.Label(frame, text="Зашифрованный текст:", font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=(10, 5))
        self.decrypt_input = tk.Text(frame, height=10, font=('Segoe UI', 10),
                                     wrap=tk.WORD)
        self.decrypt_input.pack(fill=tk.X, padx=10, pady=10)
        self.decrypt_input.insert(tk.END, "Введите зашифрованный текст...")
        self.decrypt_input.bind("<FocusIn>", lambda e: self.clear_placeholder(self.decrypt_input, "Введите зашифрованный текст..."))
        self.decrypt_input.bind("<FocusOut>", lambda e: self.restore_placeholder(self.decrypt_input, "Введите зашифрованный текст..."))
        decrypt_input_scroll = ttk.Scrollbar(frame, command=self.decrypt_input.yview, bootstyle="round")
        self.decrypt_input.config(yscrollcommand=decrypt_input_scroll.set)
        decrypt_input_scroll.pack_forget()
        self.decrypt_input.bind("<MouseWheel>", lambda e: self.decrypt_input.yview_scroll(-1 * int(e.delta / 120), "units"))
        ttk.Label(frame, text="Ключ:", font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=(10, 5))
        self.decrypt_key_entry = ttk.Entry(frame, width=60, font=('Segoe UI', 10))
        self.decrypt_key_entry.pack(fill=tk.X, padx=10, pady=10)
        self.decrypt_key_entry.insert(0, "Введите ключ...")
        self.decrypt_key_entry.bind("<FocusIn>", lambda e: self.clear_placeholder(self.decrypt_key_entry, "Введите ключ..."))
        self.decrypt_key_entry.bind("<FocusOut>", lambda e: self.restore_placeholder(self.decrypt_key_entry, "Введите ключ..."))
        ttk.Button(frame, 
                   text="Расшифровать",
                   command=self.perform_decryption,
                   bootstyle="success",
                   width=20).pack(pady=15)
        
        ttk.Label(frame, text="Результат:", font=('Segoe UI', 10)).pack(anchor='w', padx=10, pady=(10, 5))
        self.decrypt_output = tk.Text(frame, height=10, font=('Segoe UI', 10),
                                      wrap=tk.WORD)
        self.decrypt_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.decrypt_output.configure(state='disabled')
        decrypt_output_scroll = ttk.Scrollbar(frame, command=self.decrypt_output.yview, bootstyle="round")
        self.decrypt_output.config(yscrollcommand=decrypt_output_scroll.set)
        decrypt_output_scroll.pack_forget()
        self.decrypt_output.bind("<MouseWheel>", lambda e: self.decrypt_output.yview_scroll(-1 * int(e.delta / 120), "units")) 
        return frame

    def create_history_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)   
        columns = ('datetime', 'operation', 'text', 'result')
        self.history_tree = ttk.Treeview(frame, 
                                         columns=columns,
                                         show='headings',
                                         selectmode='browse',
                                         bootstyle="info")
        self.history_tree.heading('datetime', text='Дата и время')
        self.history_tree.heading('operation', text='Операция')
        self.history_tree.heading('text', text='Исходный текст')
        self.history_tree.heading('result', text='Результат')
        self.history_tree.column('datetime', width=150)
        self.history_tree.column('operation', width=100)
        self.history_tree.column('text', width=300)
        self.history_tree.column('result', width=300)
        scrollbar = ttk.Scrollbar(frame, 
                                  orient=tk.VERTICAL,
                                  command=self.history_tree.yview,
                                  bootstyle="round")
        self.history_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Button(frame,
                   text="Очистить историю",
                   command=self.clear_history,
                   bootstyle="danger",
                   width=20).pack(pady=15)
        
        self.update_history_view()
        return frame

    def add_history_record(self, operation, text, result):
        record = {
            'datetime': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'operation': operation,
            'text': text,
            'result': result
        }
        self.history.append(record)
        self.update_history_view()

    def update_history_view(self):
        self.history_tree.delete(*self.history_tree.get_children())
        for record in reversed(self.history):
            self.history_tree.insert('', 'end', values=(
                record['datetime'],
                record['operation'],
                record['text'][:50] + '...' if len(record['text']) > 50 else record['text'],
                record['result'][:50] + '...' if len(record['result']) > 50 else record['result']
            ))

    def clear_history(self):
        self.history = []
        self.update_history_view()

    def change_theme(self, theme_name):
        self.theme_mode = theme_name
        self.config_data['theme'] = theme_name
        bootstrap_theme = self.themes[theme_name]['bootstrap_theme']
        self.style.theme_use(bootstrap_theme)
        self.update_widget_colors()

    def update_widget_colors(self):
        pass

    def generate_random_key(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        key = ''.join(random.choices(chars, k=32))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def perform_encryption(self):
        text = self.encrypt_input.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        if not text or not key or text == "Введите текст для шифрования..." or key == "Введите или сгенерируйте ключ...":
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        try:
            encrypted = self.encrypt(text, key)
            self.encrypt_output.configure(state='normal')
            self.encrypt_output.delete("1.0", tk.END)
            self.encrypt_output.insert(tk.END, encrypted)
            self.encrypt_output.configure(state='disabled')
            self.add_history_record('Шифрование', text, encrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def perform_decryption(self):
        text = self.decrypt_input.get("1.0", tk.END).strip()
        key = self.decrypt_key_entry.get().strip()
        if not text or not key or text == "Введите зашифрованный текст..." or key == "Введите ключ...":
            messagebox.showerror("Ошибка", "Заполните все поля")
            return
        try:
            decrypted = self.decrypt(text, key)
            self.decrypt_output.configure(state='normal')
            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert(tk.END, decrypted)
            self.decrypt_output.configure(state='disabled')
            self.add_history_record('Дешифрование', text, decrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", "Неверный ключ или данные")

    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {'theme': 'light'}

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config_data, f)

    def load_history(self):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except:
            return []

    def save_history(self):
        with open(HISTORY_FILE, 'w') as f:
            json.dump(self.history, f)

    def on_close(self):
        self.save_config()
        self.save_history()
        self.destroy()

    def clear_placeholder(self, widget, placeholder):
        if isinstance(widget, ttk.Entry):
            if widget.get() == placeholder:
                widget.delete(0, tk.END)
        else:
            if widget.get("1.0", tk.END).strip() == placeholder:
                widget.delete("1.0", tk.END)

    def restore_placeholder(self, widget, placeholder):
        if isinstance(widget, ttk.Entry):
            if not widget.get().strip():
                widget.insert(0, placeholder)
        else:
            if not widget.get("1.0", tk.END).strip():
                widget.insert(tk.END, placeholder)

    def derive_key(self, key):
        return hashlib.sha256(key.encode()).digest()

    def pad_text(self, text):
        padder = padding.PKCS7(128).padder()
        return padder.update(text.encode()) + padder.finalize()

    def unpad_text(self, data):
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(data) + unpadder.finalize()).decode()

    def encrypt(self, text, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.derive_key(key)), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(self.pad_text(text)) + encryptor.finalize()
        return urlsafe_b64encode(iv + ct).decode()

    def decrypt(self, data, key):
        data = urlsafe_b64decode(data)
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(self.derive_key(key)), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return self.unpad_text(decryptor.update(ct) + decryptor.finalize())

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
