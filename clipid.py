## ClipId ##


import win32clipboard
import time
import threading
import subprocess
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
from queue import Queue, Empty
from ttkthemes import ThemedTk, THEMES
import os
from tkinter import messagebox
import configparser

def center_window(window, window_width, window_height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)

    window.geometry(f"{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}")

class ClipboardMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Clipboard Monitor -- Program Grant Cole (COLEuk) -- Credits Paul Spencer -- Ver 4.0.8")
        self.root.geometry("800x425")

        # Get the window size
        window_width = 800
        window_height = 425

        # Center the window on the screen
        center_window(self.root, window_width, window_height)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Rest of your code remains unchanged...


        # Create a themed style
        self.style = ttk.Style()
        self.load_theme_from_config()  # Load the theme from config.ini or use "itft1" as default

        self.label = tk.Label(root, text="Clipboard Content:")
        self.label.pack()

        self.content_label = scrolledtext.ScrolledText(root, wrap="word", height=8)
        self.content_label.pack(fill="both", expand=True)

        self.clear_button = ttk.Button(root, text="Clear Clipboard", command=self.clear_clipboard)
        self.clear_button.pack(side="left", padx=10, pady=5)

        self.always_on_top = tk.BooleanVar(value=False)
        self.always_on_top_button = ttk.Checkbutton(root, text="Always On Top", variable=self.always_on_top, command=self.toggle_always_on_top)
        self.always_on_top_button.pack(side="left", padx=10, pady=5)

        self.monitor_thread = None
        self.monitoring = False
        self.dummy_widget = tk.Frame(root)
        self.dummy_widget.pack(side="left", expand=True)

        self.start_button = ttk.Button(root, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_button.pack(side="left", padx=10, pady=5)

        self.theme_button = ttk.Button(root, text="Change Theme", command=self.change_theme)  #cycle button creation
        self.theme_button.pack(side="left", padx=10, pady=5)


        self.close_program_button = ttk.Button(root, text="Close Program", command=self.on_closing)
        self.close_program_button.pack(side="left", padx=15, pady=5)

        self.root.bind("<Configure>", self.update_label_wraplength)
        clipboard_data = get_clipboard_data()

        if clipboard_data is not None:
            self.content_label.insert("end", clipboard_data)
            self.toggle_monitoring()

        self.queue = Queue()

        # Create a list of available themes
        self.available_themes = THEMES
        self.current_theme_index = 0


    def toggle_monitoring(self):
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def clear_clipboard(self):
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
            self.content_label.delete("1.0", "end")
        except win32clipboard.error:
            pass

    def start_monitoring(self):
        self.monitoring = True
        self.start_button.config(text="Stop Monitoring")
        self.monitor_thread = threading.Thread(target=self.monitor_clipboard)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(text="Start Monitoring")

    def monitor_clipboard(self):
        while self.monitoring:
            clipboard_data = get_clipboard_data()

            if clipboard_data is not None:
                self.queue.put(clipboard_data)
            else:
                self.stop_monitoring()

            time.sleep(1)

    def update_label_wraplength(self, event):
        self.content_label.config(wrap="word", width=event.width - 40)

    def toggle_always_on_top(self):
        self.root.attributes("-topmost", self.always_on_top.get())

    def change_theme(self):
        # Get the next theme name from the list
        next_theme = self.available_themes[self.current_theme_index]

        # Apply the next theme
        self.style.theme_use(next_theme)

        # Calculate the next theme index
        self.current_theme_index = (self.current_theme_index + 1) % len(self.available_themes)

        # Save the new theme to config.ini
        self.save_theme_to_config(next_theme)

        # Apply next theme in line
    def process_queue(self):
        try:
            clipboard_data = self.queue.get_nowait()
            self.update_content_label(clipboard_data)
        except Empty:
            pass
        self.root.after(100, self.process_queue)

    def update_content_label(self, clipboard_data):
        self.content_label.delete("1.0", "end")
        self.content_label.insert("end", clipboard_data)

    def on_closing(self):
        if self.monitor_thread:
            self.stop_monitoring()
            self.monitor_thread.join()
        self.root.destroy()

    def load_theme_from_config(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if 'Settings' in config and 'theme' in config['Settings']:
            theme = config['Settings']['theme']
            if theme in THEMES:
                self.style.theme_use(theme)

    def save_theme_to_config(self, theme_name):
        config = configparser.ConfigParser()
        config['Settings'] = {'theme': theme_name}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

def get_clipboard_data():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        return data
    except (win32clipboard.error, TypeError):
        return None

if __name__ == "__main__":
    root = ThemedTk()
    root.attributes("-topmost", True)
    monitor = ClipboardMonitor(root)
    root.after(100, monitor.process_queue)
    root.mainloop()
