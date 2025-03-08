import os
import csv
import base64
import tkinter as tk
import platform
import subprocess
import webbrowser
import secrets
import string
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def detect_system_theme():
    """
    Detects the system's preferred theme.
    On Windows, reads the registry key 'AppsUseLightTheme'.
    On macOS, uses 'defaults read -g AppleInterfaceStyle'.
    Defaults to light mode ('flatly') if detection fails.
    """
    try:
        if platform.system() == "Windows":
            import winreg
            registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            use_light_theme, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return "darkly" if use_light_theme == 0 else "flatly"
        elif platform.system() == "Darwin":
            try:
                result = subprocess.check_output(
                    ["defaults", "read", "-g", "AppleInterfaceStyle"],
                    stderr=subprocess.STDOUT
                ).strip().decode()
                return "darkly" if result.lower() == "dark" else "flatly"
            except subprocess.CalledProcessError:
                return "flatly"
        else:
            return "flatly"
    except Exception:
        return "flatly"

    if theme == "darkly":
        style.configure("Custom.TFrame",
                       background="#2b2b2b",
                       bordercolor="#3a3a3a")
        style.configure("Custom.TButton",
                       background="#3a3a3a",
                       foreground="#ffffff")
        style.configure("Custom.TEntry",
                       fieldbackground="#2b2b2b",
                       foreground="#ffffff")
    else:
        style.configure("Custom.TFrame",
                       background="#ffffff",
                       bordercolor="#e0e0e0")
        style.configure("Custom.TButton",
                       background="#f0f0f0",
                       foreground="#000000")
        style.configure("Custom.TEntry",
                       fieldbackground="#ffffff",
                       foreground="#000000")

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Manager")
        self.root.geometry("900x700")
        self.entries = []
        self.key = None
        self.salt = None
        # For auto-lock overlay (in-window notification)
        self.lock_frame = None

        self.style = ttk.Style()
        self.current_theme = self.style.theme.name
        self.theme_var = tk.StringVar(value=self.current_theme)
        self.matched_fields_dict = {}

        # Variables for drag selection
        self.dragging = False
        self.rect = None

        self.style.configure("Treeview",
                             rowheight=30,
                             bordercolor="gray",
                             borderwidth=1,
                             relief="flat",
                             background="#ffffff",
                             fieldbackground="#ffffff",
                             foreground="#000000")
        self.style.configure("Treeview.Heading",
                             background="#e0e0e0",
                             foreground="#000000",
                             font=("Segoe UI", 10, "bold"))

        # Configure modern styling
        self.style.configure("Custom.TButton",
                            padding=10,
                            borderwidth=0,
                            relief="flat",
                            borderradius=10)
        
        self.style.configure("Custom.TEntry",
                            padding=5,
                            relief="flat",
                            borderwidth=0,
                            fieldbackground="#f0f0f0")
        
        self.style.configure("Custom.TFrame",
                            borderwidth=1,
                            relief="solid",
                            borderradius=15)
        
        self.style.configure("Custom.Treeview",
                            rowheight=40,
                            padding=5,
                            borderwidth=0,
                            relief="flat",
                            borderradius=10)
        
        self.style.configure("Custom.Treeview.Heading",
                            padding=10,
                            font=("Segoe UI", 10, "bold"))
        
        # Apply rounded corners to all buttons
        self.style.configure("TButton", 
                            borderradius=10,
                            padding=10)
        
        # Make entry fields look modern
        self.style.configure("TEntry",
                            padding=8,
                            relief="flat",
                            borderwidth=0)
        
        # Add shadow effect to frames
        self.style.configure("Card.TFrame",
                            borderwidth=0,
                            relief="solid",
                            padding=15,
                            borderradius=15)

        if os.path.exists("secret.key"):
            self.load_key()
        else:
            self.create_master_password()

        self.create_menubar()
        self.create_widgets()
        self.create_context_menu()
        self.update_treeview_style(self.current_theme)
        self.load_data()

        # --- Auto-Lock Setup ---
        self.auto_lock_delay = 600000  # 10 minutes in milliseconds
        self.auto_lock_id = None
        self.bind_auto_lock_events()
        self.reset_auto_lock_timer()

    def set_window_icon(self, window):
        """Sets the favicon for any window or popup"""
        try:
            window.iconbitmap("favicon.ico")
        except Exception as e:
            print(f"Could not set window icon: {e}")

    # ---------------- Helper to Center Popups -------------------
    def center_popup(self, popup):
        self.root.update_idletasks()
        popup_width = popup.winfo_reqwidth()
        popup_height = popup.winfo_reqheight()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        x = root_x + (root_width // 2) - (popup_width // 2)
        y = root_y + (root_height // 2) - (popup_height // 2)
        popup.geometry(f"+{x}+{y}")

    # ---------------- Custom Password Dialog -------------------
    def ask_master_password(self, prompt, title):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        d.grab_set()
        self.center_popup(d)
        label = ttk.Label(d, text=prompt)
        label.pack(padx=10, pady=5)
        pass_var = tk.StringVar()
        entry = ttk.Entry(d, textvariable=pass_var, show="*")
        entry.pack(padx=10, pady=5)
        entry.focus_set()

        def toggle():
            if entry.cget("show") == "*":
                entry.config(show="")
                toggle_btn.config(text="Hide")
            else:
                entry.config(show="*")
                toggle_btn.config(text="Show")
        toggle_btn = ttk.Button(d, text="Show", command=toggle)
        toggle_btn.pack(padx=10, pady=5)

        def on_ok():
            d.destroy()
        ok_btn = ttk.Button(d, text="OK", command=on_ok)
        ok_btn.pack(padx=10, pady=5)
        self.root.wait_window(d)
        return pass_var.get()

    # ---------------- Auto-Lock Methods -------------------
    def bind_auto_lock_events(self):
        self.root.bind_all("<Any-KeyPress>", lambda event: self.reset_auto_lock_timer())
        self.root.bind_all("<Motion>", lambda event: self.reset_auto_lock_timer())
        self.root.bind_all("<Button>", lambda event: self.reset_auto_lock_timer())

    def reset_auto_lock_timer(self):
        if self.auto_lock_id is not None:
            self.root.after_cancel(self.auto_lock_id)
        self.auto_lock_id = self.root.after(self.auto_lock_delay, self.auto_lock)

    def auto_lock(self):
        if self.lock_frame is not None:
            return  # Prevent multiple overlays

        self.lock_frame = ttk.Frame(self.root)
        self.lock_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        if self.current_theme in ["darkly", "cyborg", "vapor"]:
            bg_color = "black"
            fg_color = "white"
        else:
            bg_color = "white"
            fg_color = "black"
        self.style.configure("Lock.TFrame", background=bg_color)
        self.style.configure("Lock.TLabel", background=bg_color, foreground=fg_color)
        self.lock_frame.configure(style="Lock.TFrame")

        prompt_frame = ttk.Frame(self.lock_frame, padding=20, style="Lock.TFrame")
        prompt_frame.place(relx=0.5, rely=0.5, anchor="center")

        prompt_label = ttk.Label(prompt_frame,
                                 text="You have been logged out due to inactivity.\nPlease re-enter master password.",
                                 style="Lock.TLabel", font=("Segoe UI", 12))
        prompt_label.pack(pady=(0, 10))

        password_var = tk.StringVar()
        password_entry = ttk.Entry(prompt_frame, textvariable=password_var, show="*")
        password_entry.pack(pady=(0, 10))
        password_entry.focus_set()

        def toggle_master():
            if password_entry.cget("show") == "*":
                password_entry.config(show="")
                master_toggle.config(text="Hide")
            else:
                password_entry.config(show="*")
                master_toggle.config(text="Show")
        master_toggle = ttk.Button(prompt_frame, text="Show", command=toggle_master)
        master_toggle.pack(pady=(0, 10))

        def check_password():
            pwd = password_var.get()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt, iterations=480000)
            derived_key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
            if derived_key == self.key:
                self.lock_frame.destroy()
                self.lock_frame = None
                self.reset_auto_lock_timer()
            else:
                messagebox.showerror("Auto Lock", "Incorrect master password! Try again.")
                password_var.set("")
                password_entry.focus_set()

        unlock_button = ttk.Button(prompt_frame, text="Unlock", command=check_password)
        unlock_button.pack(pady=(0, 10))

        def close_app():
            self.root.destroy()
        close_button = ttk.Button(prompt_frame, text="Close Application", command=close_app)
        close_button.pack()

        self.lock_frame.tkraise()
        self.lock_frame.grab_set()
        self.root.wait_window(self.lock_frame)

    # ---------------- Menubar and Theme -------------------
    def create_menubar(self):
        menubar = ttk.Menu(self.root)
        
        file_menu = ttk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Import CSV", command=self.import_csv)
        file_menu.add_command(label="Export as CSV", command=self.export_csv)
        file_menu.add_command(label="App Lock", command=self.auto_lock)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        
        theme_menu = ttk.Menu(menubar, tearoff=0)
        themes = ["flatly", "darkly", "minty", "cyborg", "vapor"]
        for t in themes:
            theme_menu.add_radiobutton(label=t.capitalize(),
                                       variable=self.theme_var,
                                       value=t,
                                       command=lambda theme=t: self.change_theme(theme))
        menubar.add_cascade(label="Themes", menu=theme_menu)
        
        settings_menu = ttk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Change Master Password", command=self.change_master_password)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        edit_menu = ttk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Delete All Duplicates", command=self.delete_all_duplicates)
        edit_menu.add_command(label="Delete All Entries", command=self.delete_all_entries)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        
        help_menu = ttk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="How to Use", command=self.show_how_to_use)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def show_how_to_use(self):
        instructions = (
            "General Information:\n"
            " - Use 'Add Entry' to create new entries and 'Edit Entry' to modify them.\n"
            " - 'Delete Entry' removes the selected entry.\n"
            " - 'View Password' (or press Space when a row is selected) displays the decrypted password.\n"
            " - 'Copy Password' (or press Ctrl+C when a row is selected) copies the password to the clipboard.\n"
            " - Use the 'App Lock' button (or wait for auto-lock) to secure the application.\n\n"
            "Shortcuts:\n"
            " - Space: View the password for the selected row.\n"
            " - Ctrl+C: Copy the password of the selected row to the clipboard.\n"
            " - The search box filters entries in real-time.\n"
            " - Click the 'Filters' button to show/hide filter options.\n\n"
            "NOTE: Uncheck a Box to Remove All Rows which contain Data in that Column."
        )
        messagebox.showinfo("How to Use", instructions)

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)
        self.current_theme = theme_name
        self.theme_var.set(theme_name)
        self.update_treeview_style(theme_name)
        self.status.config(text=f"Theme changed to {theme_name.capitalize()}")

    def update_treeview_style(self, theme_name):
        if theme_name in ["darkly", "cyborg", "vapor"]:
            self.style.configure("Treeview",
                                 rowheight=30,
                                 bordercolor="gray",
                                 borderwidth=1,
                                 relief="flat",
                                 background="#2e2e2e",
                                 fieldbackground="#2e2e2e",
                                 foreground="#ffffff")
            self.style.configure("Treeview.Heading",
                                 background="#3a3a3a",
                                 foreground="#ffffff",
                                 font=("Segoe UI", 10, "bold"))
            self.tree.tag_configure('even', background='#2e2e2e')
            self.tree.tag_configure('odd', background='#323232')
        else:
            self.style.configure("Treeview",
                                 rowheight=30,
                                 bordercolor="gray",
                                 borderwidth=1,
                                 relief="flat",
                                 background="#ffffff",
                                 fieldbackground="#ffffff",
                                 foreground="#000000")
            self.style.configure("Treeview.Heading",
                                 background="#e0e0e0",
                                 foreground="#000000",
                                 font=("Segoe UI", 10, "bold"))
            self.tree.tag_configure('even', background='#ffffff')
            self.tree.tag_configure('odd', background='#f0f0f0')

    def show_about(self):
        messagebox.showinfo("About", "SecurePass Manager\nVersion 1.0\nA secure password manager built with ttkbootstrap.")

    # ---------------- Master Password and Data Encryption -------------------
    def create_master_password(self):
        password = self.ask_master_password("Create master password:", "Master Password")
        if password:
            self.salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32,
                             salt=self.salt,
                             iterations=480000)
            self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            with open("secret.key", "wb") as key_file:
                key_file.write(self.salt + self.key)

    def load_key(self):
        with open("secret.key", "rb") as key_file:
            data = key_file.read()
            self.salt = data[:16]
            stored_key = data[16:]
        password = self.ask_master_password("Enter master password:", "Master Password")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=self.salt,
                         iterations=480000)
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        if self.key != stored_key:
            messagebox.showerror("Error", "Incorrect master password!")
            self.root.destroy()

    def verify_master_password(self):
        password = self.ask_master_password("Enter master password:", "Verify Master Password")
        if not password:
            return False
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=self.salt,
                         iterations=480000)
        derived_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        if derived_key != self.key:
            messagebox.showerror("Error", "Incorrect master password!")
            return False
        return True

    def change_master_password(self):
        if not self.verify_master_password():
            return
        new_password = self.ask_master_password("Enter your new master password:", "New Master Password")
        if not new_password:
            return
        confirm_password = self.ask_master_password("Confirm your new master password:", "Confirm New Master Password")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        old_key = self.key
        new_salt = os.urandom(16)
        new_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32,
                             salt=new_salt,
                             iterations=480000)
        new_key = base64.urlsafe_b64encode(new_kdf.derive(new_password.encode()))

        for entry in self.entries:
            try:
                plaintext = Fernet(old_key).decrypt(entry['password'].encode()).decode()
            except Exception:
                plaintext = entry['password']
            entry['password'] = Fernet(new_key).encrypt(plaintext.encode()).decode()

        with open("secret.key", "wb") as key_file:
            key_file.write(new_salt + new_key)
        self.salt = new_salt
        self.key = new_key
        self.save_data()
        self.load_data()
        messagebox.showinfo("Success", "Master password has been changed successfully!")

    # ---------------- Encryption Helpers -------------------
    def encrypt(self, data):
        return Fernet(self.key).encrypt(data.encode()).decode()

    def decrypt(self, data):
        return Fernet(self.key).decrypt(data.encode()).decode()

    # ---------------- Widget Creation -------------------
    def create_widgets(self):
        top_frame = ttk.Frame(self.root, padding=10, style="Card.TFrame")
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Container for search entry, filter toggle, clear search, and "Generate a Pass" button.
        search_container = ttk.Frame(top_frame, style="Card.TFrame")
        search_container.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(search_container, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_container, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<KeyRelease>", self.search_entries)
        self.search_var.trace_add('write', lambda *args: self.update_clear_search_button())
        
        toggle_button = ttk.Button(search_container, text="Filters", command=self.toggle_filter_box)
        toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Clear Search button (initially not packed)
        self.clear_search_button = ttk.Button(search_container, text="Clear Search", command=self.clear_search)
        
        # "Generate a Pass" button on the right.
        gen_pass_button = ttk.Button(search_container, text="Generate a Pass", command=self.open_password_generator)
        gen_pass_button.pack(side=tk.RIGHT, padx=5)
        
        # Filter box (initially hidden)
        self.filter_frame = ttk.Frame(top_frame)
        note_label = ttk.Label(self.filter_frame, text="NOTE: Uncheck a Box to Remove All Rows which contain Data in that Column.", font=("Segoe UI", 8))
        note_label.pack(side=tk.TOP, anchor="w", padx=5, pady=2)
        self.search_name_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_frame, text="Name", variable=self.search_name_var, command=self.search_entries).pack(side=tk.LEFT, padx=2)
        self.search_url_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_frame, text="URL", variable=self.search_url_var, command=self.search_entries).pack(side=tk.LEFT, padx=2)
        self.search_username_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_frame, text="Username", variable=self.search_username_var, command=self.search_entries).pack(side=tk.LEFT, padx=2)
        self.search_password_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_frame, text="Password", variable=self.search_password_var, command=self.search_entries).pack(side=tk.LEFT, padx=2)
        self.search_note_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_frame, text="Note", variable=self.search_note_var, command=self.search_entries).pack(side=tk.LEFT, padx=2)
        # Initially, the filter_frame is not packed.
        
        self.status = ttk.Label(self.root, text="Ready", bootstyle="secondary", anchor="w")
        self.status.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

        tree_frame = ttk.Frame(self.root, padding=10)
        tree_frame.pack(expand=True, fill=tk.BOTH)
        # Treeview with a "S.No." column.
        self.tree = ttk.Treeview(tree_frame, columns=("S.No.", "Name", "URL", "Username", "Password", "Note"),
                                 show="headings", style="Custom.Treeview", bootstyle="info-rounded")
        for col in ["S.No.", "Name", "URL", "Username", "Password", "Note"]:
            self.tree.heading(col, text=col)
            if col == "S.No.":
                self.tree.column(col, anchor=tk.CENTER, width=62, stretch=False)
            else:
                self.tree.column(col, anchor=tk.W, width=150, stretch=True)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<Delete>", lambda event: self.delete_entry())
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<space>", lambda event: self.view_password())
        self.tree.bind("<Control-c>", lambda event: self.copy_to_clipboard())
        self.tree.tag_configure('even', background='#ffffff')
        self.tree.tag_configure('odd', background='#f0f0f0')
        
        # Canvas overlay for drag selection.
        self.drag_canvas = tk.Canvas(tree_frame, highlightthickness=0, cursor='crosshair')
        self.drag_canvas.place(in_=self.tree, x=0, y=0, relwidth=1, relheight=1)
        self.drag_canvas.place_forget()
        self.tree.bind('<ButtonPress-1>', self.on_drag_start)
        self.tree.bind('<B1-Motion>', self.on_drag_motion)
        self.tree.bind('<ButtonRelease-1>', self.on_drag_release)

        btn_frame = ttk.Frame(self.root, padding=10)
        btn_frame.pack(fill=tk.X)
        btn_specs = [
            ("Add Entry", self.add_entry),
            ("Edit Entry", self.edit_entry),
            ("Delete Entry", self.delete_entry),
            ("View Password", self.view_password),
            ("Copy Password", self.copy_to_clipboard),
            ("Copy Username", self.copy_username)  # Added Copy Username button
        ]
        for text, command in btn_specs:
            ttk.Button(btn_frame, 
                      text=text, 
                      command=command, 
                      style="Custom.TButton",
                      bootstyle=(PRIMARY, "rounded")).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Details section below the button frame.
        self.details_frame = ttk.Frame(self.root, 
                                     padding=15,
                                     style="Card.TFrame")
        self.details_frame.pack(fill=tk.X, padx=15, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self.update_details)

    def update_clear_search_button(self, *args):
        if self.search_var.get().strip():
            if not self.clear_search_button.winfo_ismapped():
                self.clear_search_button.pack(side=tk.LEFT, padx=5)
        else:
            if self.clear_search_button.winfo_ismapped():
                self.clear_search_button.pack_forget()

    def clear_search(self):
        self.search_var.set("")
        self.search_entries()

    def toggle_filter_box(self):
        if self.filter_frame.winfo_ismapped():
            self.filter_frame.pack_forget()
        else:
            self.filter_frame.pack(fill=tk.X, padx=5, pady=5)

    def update_details(self, event=None):
        for widget in self.details_frame.winfo_children():
            widget.destroy()
        selected = self.tree.selection()
        if selected:
            header = ttk.Frame(self.details_frame)
            header.pack(fill=tk.X)
            close_btn = ttk.Button(header, text="X", command=self.close_details, width=3)
            close_btn.pack(side=tk.RIGHT)
            index = int(selected[0])
            entry = self.entries[index]
            ttk.Label(self.details_frame, text="Name: " + entry.get("name", ""), font=("Segoe UI", 10, "bold")).pack(anchor="w")
            url = entry.get("url", "")
            if url:
                url_label = ttk.Label(self.details_frame, text="URL: " + url, font=("Segoe UI", 10, "bold"), foreground="blue", cursor="hand2")
                url_label.pack(anchor="w")
                url_label.bind("<Button-1>", lambda e, url=url: webbrowser.open(url))
            else:
                ttk.Label(self.details_frame, text="URL: ", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Label(self.details_frame, text="Username: " + entry.get("username", ""), font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Label(self.details_frame, text="Note: " + entry.get("note", ""), font=("Segoe UI", 10, "bold")).pack(anchor="w")
        else:
            ttk.Label(self.details_frame, text="No row selected.", font=("Segoe UI", 10, "bold")).pack(anchor="w")

    def close_details(self):
        for widget in self.details_frame.winfo_children():
            widget.destroy()
        self.tree.selection_remove(self.tree.selection())

    def create_context_menu(self):
        self.context_menu = ttk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Edit Entry", command=self.edit_entry)
        self.context_menu.add_command(label="Delete Entry", command=self.delete_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="View Password", command=self.view_password)
        self.context_menu.add_command(label="Copy Password", command=self.copy_to_clipboard)

    def show_context_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.context_menu.post(event.x_root, event.y_root)

    def on_drag_start(self, event):
        self.drag_start_x = event.x
        self.drag_start_y = event.y
        self.dragging = False
        self.initial_selection = self.tree.selection()

    def on_drag_motion(self, event):
        if not self.dragging:
            delta_x = abs(event.x - self.drag_start_x)
            delta_y = abs(event.y - self.drag_start_y)
            if delta_x < 3 and delta_y < 3:
                return
            self.dragging = True
            self.tree.selection_remove(self.initial_selection)
            self.drag_canvas.place(in_=self.tree, x=0, y=0, relwidth=1, relheight=1)
            self.rect = self.drag_canvas.create_rectangle(
                self.drag_start_x, self.drag_start_y, event.x, event.y,
                outline='#4a9cff', dash=(2, 2), fill='#4a9cff', stipple='gray50', tags='selection_rect'
            )
        else:
            current_x, current_y = event.x, event.y
            self.drag_canvas.coords(self.rect, self.drag_start_x, self.drag_start_y, current_x, current_y)
            x1, y1 = sorted([self.drag_start_x, current_x])[0], sorted([self.drag_start_y, current_y])[0]
            x2, y2 = sorted([self.drag_start_x, current_x])[1], sorted([self.drag_start_y, current_y])[1]
            selected = []
            for item in self.tree.get_children():
                bbox = self.tree.bbox(item)
                if bbox:
                    iy, ih = bbox[1], bbox[3]
                    if (iy < y2) and (iy + ih > y1):
                        selected.append(item)
            self.tree.selection_set(selected)

    def on_drag_release(self, event):
        if self.dragging:
            self.drag_canvas.place_forget()
            self.drag_canvas.delete('selection_rect')
            self.dragging = False

    def load_data(self):
        if os.path.exists("passwords.enc"):
            with open("passwords.enc", "r") as f:
                encrypted_data = f.read()
            try:
                decrypted_data = self.decrypt(encrypted_data)
                self.entries = eval(decrypted_data)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load data: {e}")
                self.entries = []
            self.entries = sorted(self.entries, key=lambda x: x['name'].lower())
        if self.search_var.get():
            self.search_entries()
        else:
            indices = list(range(len(self.entries)))
            self.update_treeview(self.entries, indices)
        self.status.config(text="Data loaded.")

    def save_data(self):
        encrypted_data = self.encrypt(str(self.entries))
        with open("passwords.enc", "w") as f:
            f.write(encrypted_data)
        self.status.config(text="Data saved.")

    def update_treeview(self, entries_list, indices=None):
        self.tree.delete(*self.tree.get_children())
        if indices is None:
            indices = list(range(len(entries_list)))
        for i, (idx, entry) in enumerate(zip(indices, entries_list)):
            tag = 'even' if i % 2 == 0 else 'odd'
            self.tree.insert("", tk.END, iid=str(idx), values=(
                i + 1,
                entry['name'],
                entry['url'],
                entry['username'],
                "••••••••",
                entry['note']
            ), tags=(tag,))
    
    def search_entries(self, event=None):
        search_term = self.search_var.get().lower().strip()
        filtered_entries = []
        indices = []
        for idx, entry in enumerate(self.entries):
            if not self.search_name_var.get() and entry['name'].strip() != "":
                continue
            if not self.search_url_var.get() and entry['url'].strip() != "":
                continue
            if not self.search_username_var.get() and entry['username'].strip() != "":
                continue
            if not self.search_note_var.get() and entry['note'].strip() != "":
                continue
            if not self.search_password_var.get():
                try:
                    decrypted_pwd = self.decrypt(entry['password']).strip()
                except Exception:
                    decrypted_pwd = ""
                if decrypted_pwd != "":
                    continue

            if search_term:
                matched = False
                if self.search_name_var.get() and search_term in entry['name'].lower():
                    matched = True
                if self.search_url_var.get() and search_term in entry['url'].lower():
                    matched = True
                if self.search_username_var.get() and search_term in entry['username'].lower():
                    matched = True
                if self.search_note_var.get() and search_term in entry['note'].lower():
                    matched = True
                if self.search_password_var.get():
                    try:
                        decrypted_pwd = self.decrypt(entry['password']).lower()
                        if search_term in decrypted_pwd:
                            matched = True
                    except Exception:
                        pass
                if not matched:
                    continue

            filtered_entries.append(entry)
            indices.append(idx)
        self.update_treeview(filtered_entries, indices)
        self.status.config(text=f"Found {len(filtered_entries)} matching entries.")

    def add_entry(self):
        self.entry_dialog("Add New Entry")

    def edit_entry(self):
        selected = self.tree.selection()
        if selected:
            if not self.verify_master_password():
                return
            index = int(selected[0])
            self.entry_dialog("Edit Entry", index)
        else:
            messagebox.showerror("Error", "No entry selected!")

    def delete_entry(self):
        selected = self.tree.selection()
        if selected:
            index = int(selected[0])
            del self.entries[index]
            self.save_data()
            self.load_data()
            self.status.config(text="Entry deleted.")
        else:
            messagebox.showerror("Error", "No entry selected!")

    # --------------- Password Generator Toplevel ---------------
    def open_password_generator(self, apply_target=None):
        pg_window = ttk.Toplevel(self.root)
        self.set_window_icon(pg_window)
        pg_window.geometry("700x700")
        
        notebook = ttk.Notebook(pg_window)
        notebook.pack(expand=True, fill="both")
        
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="Basic")
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="Advanced")
        
        # --- Basic Tab ---
        length_var = tk.IntVar(value=8)
        ttk.Label(basic_frame, text="Password Length:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        length_spin = ttk.Spinbox(basic_frame, from_=4, to=64, textvariable=length_var, width=5)
        length_spin.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        include_upper = tk.BooleanVar(value=True)
        include_lower = tk.BooleanVar(value=True)
        include_digits = tk.BooleanVar(value=True)
        include_symbols = tk.BooleanVar(value=False)
        include_spaces = tk.BooleanVar(value=False)
        include_minus = tk.BooleanVar(value=False)
        include_underscore = tk.BooleanVar(value=False)
        include_latin1 = tk.BooleanVar(value=False)
        forced_custom_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(basic_frame, text="Include Uppercase (A-Z)", variable=include_upper) \
            .grid(row=1, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Lowercase (a-z)", variable=include_lower) \
            .grid(row=2, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Digits (0-9)", variable=include_digits) \
            .grid(row=3, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Symbols (e.g. !@#$)", variable=include_symbols) \
            .grid(row=4, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Spaces", variable=include_spaces) \
            .grid(row=5, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Minus (-)", variable=include_minus) \
            .grid(row=6, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Underscore (_)", variable=include_underscore) \
            .grid(row=7, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        ttk.Checkbutton(basic_frame, text="Include Latin-1 Supplement", variable=include_latin1) \
            .grid(row=8, column=0, sticky="w", padx=5, pady=5, columnspan=2)
        
        difficulty_var = tk.StringVar(value="Easy")
        ttk.Label(basic_frame, text="Set Difficulty:").grid(row=9, column=0, sticky="w", padx=5, pady=5)
        difficulty_options = ["Easy", "Medium", "Hard", "Super Hard", "Uncrackable"]
        difficulty_menu = ttk.OptionMenu(basic_frame, difficulty_var, difficulty_options[0], *difficulty_options)
        difficulty_menu.grid(row=9, column=1, sticky="w", padx=5, pady=5)
        
        custom_chars_var = tk.StringVar(value="")
        ttk.Label(basic_frame, text="Custom Character (optional):") \
            .grid(row=10, column=0, sticky="w", padx=5, pady=5)
        custom_entry = ttk.Entry(basic_frame, textvariable=custom_chars_var)
        custom_entry.grid(row=10, column=1, sticky="w", padx=5, pady=5)
        
        ttk.Checkbutton(basic_frame, text="Forced include custom characters", variable=forced_custom_var) \
            .grid(row=11, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        # --- Advanced Tab ---
        exclude_ambiguous = tk.BooleanVar(value=False)
        no_repeats = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(advanced_frame, text="Exclude Ambiguous Characters (I, l, 1, O, 0)",
                        variable=exclude_ambiguous).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Checkbutton(advanced_frame, text="Each Character Must Occur at Most Once",
                        variable=no_repeats).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        note_text = ("Note: Enabling these options can reduce the overall security of the generated password. "
                     "They should only be used if the target system requires such restrictions.")
        ttk.Label(advanced_frame, text=note_text, wraplength=400, foreground="red") \
            .grid(row=2, column=0, sticky="w", padx=5, pady=5)
        
        # --- Bottom Section in Generator Window ---
        bottom_frame = ttk.Frame(pg_window)
        bottom_frame.pack(fill="x", padx=5, pady=5)
        
        result_var_local = tk.StringVar()
        result_entry = ttk.Entry(bottom_frame, textvariable=result_var_local, font=("Courier", 12), width=40)
        result_entry.grid(row=0, column=0, columnspan=4, pady=5)
        
        def generate_password_local():
            LATIN1_SUPPLEMENT = ''.join(chr(i) for i in range(0x00A1, 0x0100))
            AMBIGUOUS = "Il1O0"
            
            length = length_var.get()
            pool = ""
            active_groups = []
            
            if include_upper.get():
                group = string.ascii_uppercase
                pool += group
                active_groups.append(("Uppercase", group))
            if include_lower.get():
                group = string.ascii_lowercase
                pool += group
                active_groups.append(("Lowercase", group))
            if include_digits.get():
                group = string.digits
                pool += group
                active_groups.append(("Digits", group))
            if include_symbols.get():
                group = string.punctuation
                pool += group
                active_groups.append(("Symbols", group))
            if include_spaces.get():
                group = " "
                pool += group
                active_groups.append(("Spaces", group))
            if include_minus.get():
                group = "-"
                pool += group
                active_groups.append(("Minus", group))
            if include_underscore.get():
                group = "_"
                pool += group
                active_groups.append(("Underscore", group))
            if include_latin1.get():
                group = LATIN1_SUPPLEMENT
                pool += group
                active_groups.append(("Latin-1", group))
            custom = custom_chars_var.get()
            if custom:
                pool += custom
                active_groups.append(("Custom", custom))
            
            if exclude_ambiguous.get():
                pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
                new_groups = []
                for name, chars in active_groups:
                    filtered = "".join(ch for ch in chars if ch not in AMBIGUOUS)
                    if filtered:
                        new_groups.append((name, filtered))
                active_groups = new_groups
            
            if not pool:
                result_var_local.set("Error: No character sets selected!")
                return
            
            unique_pool = set(pool)
            if no_repeats.get() and length > len(unique_pool):
                result_var_local.set("Error: Length too high for no repeats!")
                return
            
            diff = difficulty_var.get()
            if diff == "Easy":
                required_count = 0
            elif diff == "Medium":
                required_count = 2
            elif diff == "Hard":
                required_count = 3
            elif diff == "Super Hard":
                required_count = 4
            elif diff == "Uncrackable":
                required_count = len(active_groups)
            else:
                required_count = 0
            
            required_count = min(required_count, len(active_groups))
            
            forced_chars = []
            for i in range(required_count):
                group_chars = active_groups[i][1]
                forced_chars.append(secrets.choice(group_chars))
            
            # Handle forced custom characters if selected.
            if forced_custom_var.get():
                if not custom:
                    result_var_local.set("Error: Custom characters required but none provided!")
                    return
                forced_chars.append(secrets.choice(custom))
            
            total_forced = len(forced_chars)
            if total_forced > length:
                result_var_local.set(f"Error: Length too short for {total_forced} forced characters!")
                return
            
            remaining_length = length - total_forced
            
            if no_repeats.get():
                available_pool = list(set(pool) - set(forced_chars))
                if remaining_length > len(available_pool):
                    result_var_local.set("Error: Not enough unique characters!")
                    return
                random_chars = secrets.SystemRandom().sample(available_pool, remaining_length)
            else:
                random_chars = [secrets.choice(pool) for _ in range(remaining_length)]
            
            password_chars = forced_chars + random_chars
            secrets.SystemRandom().shuffle(password_chars)
            candidate = ''.join(password_chars)
            result_var_local.set(candidate)
        
        generate_btn_local = ttk.Button(bottom_frame, text="Generate", command=generate_password_local)
        generate_btn_local.grid(row=1, column=0, padx=5, pady=5)
        
        def copy_local():
            pg_window.clipboard_clear()
            pg_window.clipboard_append(result_var_local.get())
            messagebox.showinfo("Copied", "Password copied to clipboard! It will be cleared after 10 minutes.")
        copy_btn_local = ttk.Button(bottom_frame, text="Copy", command=copy_local)
        copy_btn_local.grid(row=1, column=1, padx=5, pady=5)
        
        close_btn_local = ttk.Button(bottom_frame, text="Close", command=pg_window.destroy)
        close_btn_local.grid(row=1, column=2, padx=5, pady=5)
        
        if apply_target is not None:
            def apply_password():
                apply_target.delete(0, tk.END)
                apply_target.insert(0, result_var_local.get())
                pg_window.destroy()
            apply_btn_local = ttk.Button(bottom_frame, text="Apply", command=apply_password)
            apply_btn_local.grid(row=1, column=3, padx=5, pady=5)
        
        self.center_popup(pg_window)
        # Make the generator window modal.
        pg_window.grab_set()
        pg_window.wait_window()
    
    def generate_password_from_dialog(self, parent_dialog, target_entry):
        # Release the grab from the parent dialog before opening the generator.
        parent_dialog.grab_release()
        self.open_password_generator(apply_target=target_entry)
        parent_dialog.grab_set()

    def entry_dialog(self, title, index=None):
        dialog = ttk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.grab_set()
        self.center_popup(dialog)
        frm = ttk.Frame(dialog, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        fields = ["Name", "URL", "Username", "Password", "Note"]
        entries_widgets = {}
        row = 0
        for field in fields:
            ttk.Label(frm, text=f"{field}:").grid(row=row, column=0, padx=5, pady=5, sticky=tk.E)
            if field.lower() == "password":
                pwd_entry = ttk.Entry(frm, width=30, show="*")
                pwd_entry.grid(row=row, column=1, padx=5, pady=5)
                entries_widgets["password"] = pwd_entry
                show_pwd_var = tk.BooleanVar(value=False)
                def toggle_password():
                    if show_pwd_var.get():
                        pwd_entry.config(show="")
                    else:
                        pwd_entry.config(show="*")
                ttk.Checkbutton(frm, text="Show Password", variable=show_pwd_var,
                                command=toggle_password).grid(row=row, column=2, padx=5, pady=5)
                # Add "Generate Password" button below the password field.
                generate_btn = ttk.Button(frm, text="Generate Password",
                                          command=lambda: self.generate_password_from_dialog(dialog, pwd_entry))
                generate_btn.grid(row=row+1, column=1, columnspan=4, padx=5, pady=5, sticky=tk.W)
                row += 2
            else:
                ent = ttk.Entry(frm, width=30)
                ent.grid(row=row, column=1, padx=5, pady=5)
                entries_widgets[field.lower()] = ent
                row += 1

        if index is not None:
            entry_data = self.entries[index]
            for field in fields:
                if field.lower() == "password":
                    try:
                        decrypted_password = self.decrypt(entry_data['password'])
                    except Exception:
                        decrypted_password = ""
                    entries_widgets["password"].insert(0, decrypted_password)
                else:
                    entries_widgets[field.lower()].insert(0, entry_data[field.lower()])

        def save_entry():
            new_entry = {field.lower(): entries_widgets[field.lower()].get() for field in fields}
            new_entry['password'] = self.encrypt(new_entry['password'])
            if index is not None:
                self.entries[index] = new_entry
            else:
                self.entries.append(new_entry)
            self.save_data()
            self.load_data()
            dialog.destroy()

        ttk.Button(frm, text="Save", command=save_entry, bootstyle=SUCCESS).grid(row=row, column=1, pady=10, sticky=tk.E)
        dialog.wait_window()

    def view_password(self):
        selected = self.tree.selection()
        if selected:
            index = int(selected[0])
            try:
                decrypted_password = self.decrypt(self.entries[index]['password'])
                messagebox.showinfo("Decrypted Password", f"Password: {decrypted_password}")
            except Exception:
                messagebox.showerror("Error", "Failed to decrypt password!")
        else:
            messagebox.showerror("Error", "No entry selected!")

    def copy_to_clipboard(self):
        selected = self.tree.selection()
        if selected:
            index = int(selected[0])
            try:
                decrypted_password = self.decrypt(self.entries[index]['password'])
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted_password)
                self.root.update()
                messagebox.showinfo("Copied", "Password copied to clipboard!")
            except Exception:
                messagebox.showerror("Error", "Failed to decrypt password!")
        else:
            messagebox.showerror("Error", "No entry selected!")

    def copy_username(self):
        selected = self.tree.selection()
        if selected:
            index = int(selected[0])
            username = self.entries[index]['username']
            self.root.clipboard_clear()
            self.root.clipboard_append(username)
            self.root.update()
            messagebox.showinfo("Copied", "Username copied to clipboard!")
        else:
            messagebox.showerror("Error", "No entry selected!")

    def import_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")], parent=self.root)
        if file_path:
            with open(file_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    entry = {k: row.get(k, '') for k in ["name", "url", "username", "note"]}
                    plaintext_password = row.get("password", "")
                    entry["password"] = self.encrypt(plaintext_password)
                    self.entries.append(entry)
            self.save_data()
            self.load_data()
            self.status.config(text="CSV imported successfully!")

    def export_csv(self):
        print("Exporting", len(self.entries), "entries")
        if not self.verify_master_password():
            return
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialdir=desktop,
            initialfile="passwords.csv",
            parent=self.root
        )
        if not file_path:
            return
        export_data = []
        for entry in self.entries:
            new_entry = entry.copy()
            try:
                new_entry['password'] = self.decrypt(entry['password'])
            except Exception:
                new_entry['password'] = entry['password']
            export_data.append(new_entry)
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["name", "url", "username", "password", "note"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in export_data:
                writer.writerow(row)
        messagebox.showinfo("Export CSV", "Data exported successfully!")

    def calculate_strength(self, password):
        score = 0
        if len(password) >= 8:
            score += 30
        else:
            score += 10
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 20
        if any(c.isdigit() for c in password):
            score += 20
        if any(not c.isalnum() for c in password):
            score += 30
        if score < 30:
            strength_text = "Very Weak"
        elif score < 50:
            strength_text = "Weak"
        elif score < 70:
            strength_text = "Medium"
        else:
            strength_text = "Strong"
        if score > 100:
            score = 100
        return score, strength_text

    def delete_all_entries(self):
        if not self.verify_master_password():
            return
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete all entries?"):
            self.entries = []
            self.save_data()
            self.load_data()
            self.status.config(text="All entries have been deleted.")

    def delete_all_duplicates(self):
        duplicate_dict = {}
        for entry in self.entries:
            key_name = entry['name'].strip().lower()
            duplicate_dict.setdefault(key_name, []).append(entry)
        duplicates = {name: items for name, items in duplicate_dict.items() if len(items) > 1}
        if not duplicates:
            messagebox.showinfo("No Duplicates", "No duplicate entries found.")
            return

        msg = "The following duplicate groups were found:\n\n"
        for name, items in duplicates.items():
            count = len(items)
            msg += f"Name: {name} — {count} entries (will delete {count - 1} extra copy/copies)\n"
        msg += "\nDo you want to delete all duplicate entries, keeping only one per name?"

        if messagebox.askyesno("Delete Duplicates", msg):
            seen = set()
            new_entries = []
            for entry in self.entries:
                key_name = entry['name'].strip().lower()
                if key_name not in seen:
                    seen.add(key_name)
                    new_entries.append(entry)
            self.entries = new_entries
            self.save_data()
            self.load_data()
            self.status.config(text="Duplicate entries have been removed.")

if __name__ == "__main__":
    default_theme = detect_system_theme()
    root = ttk.Window(themename=default_theme)
    app = PasswordManager(root)
    root.mainloop()
