## SecretCodeGeneratorApp: ##

import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import pyperclip
import random
import string
import time
import subprocess
import logging
import os
import datetime
from ttkthemes import ThemedStyle
from tkinter import ttk
import configparser
from complex_caesar_cipher import ComplexCaesarCipher
from complex_caesar_cipher_hash import ComplexCaesarCipherHash
import json
import base64
import hashlib


class SecretCodeGeneratorApp:

    authorization_results = {}

    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secret Code Generator -- COLEuk, Inc. -- Coded By: Grant Cole -- Credit Ideas: Paul R Spencer -- Version 4.1.1")

        # Set the window size
        window_width = 1080
        window_height = 700

        # Get the screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate the position for the window to be centered
        x_coordinate = (screen_width / 2) - (window_width / 2)
        y_coordinate = (screen_height / 2) - (window_height / 2)

        # Set the window geometry to be centered while keeping the size the same
        self.root.geometry(f"{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}")

        # Define a new column configuration for the grid
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.columnconfigure(2, weight=1)
        self.root.columnconfigure(3, weight=1)

        # Set the row weights

        self.root.rowconfigure(0, weight=0)  # Row 0 will resize equally
        self.root.rowconfigure(1, weight=0)  # Row 1 will resize equally
        self.root.rowconfigure(2, weight=0)  # Row 2 will resize equally
        self.root.rowconfigure(3, weight=0)  # Row 3 will resize equally
        self.root.rowconfigure(4, weight=1)  # Row 4 will remain fixed
        self.root.rowconfigure(5, weight=0)  # Row 5 will resize equally
        self.root.rowconfigure(6, weight=0)  # Row 6 will resize equally
        self.root.rowconfigure(7, weight=1)  # Row 7 will resize equally
        self.root.rowconfigure(8, weight=0)  # Row 8 will resize equally
        self.root.rowconfigure(9, weight=0)  # Row 9 will resize equally
        self.root.rowconfigure(10, weight=0)  # Row 10 will resize equally

        
        # Create GUI components
        input_output_width = 40  # Adjust this value to control input/output width
        min_height = 12
        input_output_height = max(min_height, int((screen_height - window_height) / 20))  # Adjust the divisor to control the height dynamically

        self.cipher = ComplexCaesarCipher()
        self.caesar_cipher_hash = ComplexCaesarCipherHash()
        
        self.current_action = None
        self.always_on_top = tk.BooleanVar(value=False)  # Always on top Defaults to On

        # Configure Logging to write "SCG.log" with the desired format.
        self.configure_logging()


        # Create a ThemedStyle instance
        self.style = ThemedStyle(self.root)        

        # Load theme configuration from config.ini
        self.load_theme_config()  # Call this method to load the theme configuration

        # Define a style that centers the text
        self.style.configure("Centered.TButton", anchor="center", justify="center")


        # Labels for input and output fields
        self.input_label = ttk.Label(self.root, text="Input Message")
        self.output_label = ttk.Label(self.root, text="Output Message")


        # Create and place labels and entry fields for username and user group
        username_label = tk.Label(self.root, text="Username:")
        username_label.grid(row=0, column=0, padx=2, pady=2, sticky=tk.W)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.grid(row=0, column=0, columnspan=1, padx=90, pady=2, sticky=tk.W+tk.E)

        usergroup_label = tk.Label(self.root, text="User Group:")
        usergroup_label.grid(row=1, column=0, padx=2, pady=2, sticky=tk.W)
        self.usergroup_entry = tk.Entry(self.root, show="*")
        self.usergroup_entry.grid(row=1, column=0, columnspan=1, padx=90, pady=2, sticky=tk.W+tk.E)

        
        # Define a style for buttons
        self.button_style = "TButton"


        # Create a button for generating the hash
        self.gen_hash_button = ttk.Button(self.root, text="Generate Hash", command=self.generate_hash, style=self.button_style)
        self.gen_hash_button.grid(row=1, column=1, padx=0, pady=5, sticky="w")

        # Create a button for clearing hash contents
        self.clear_hash_button = ttk.Button(self.root, text="Clear Hash", command=self.clear_hash, style=self.button_style)
        self.clear_hash_button.grid(row=0, column=1, padx=0, pady=5, sticky="w")


        # Create an entry field for displaying the hash code
        self.hash_entry = tk.Entry(self.root, state="readonly")  # Set the state to "readonly"
        self.hash_entry.grid(row=1, column=2, columnspan=2, padx=20, pady=5, sticky="we")

        # Create a "Chat" button
        self.chat_button = ttk.Button(self.root, text="Messenger Chat", command=self.open_chat_program, style=self.button_style)
        self.chat_button.grid(row=8, column=3, columnspan=1, padx=25, pady=5, sticky="we")


        # Create the scrolledtext widgets
        self.text_entry = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=input_output_width, height=input_output_height)
        self.output_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=input_output_width, height=input_output_height)

        # Create buttons using ttk style
        button_style = "TButton"
        self.encrypt_button = ttk.Button(self.root, text="Encrypt", command=self.encrypt_text, style=button_style)
        self.paste_button = ttk.Button(self.root, text="Get from Clipboard", command=self.paste_from_clipboard, style=button_style)
        self.decrypt_button = ttk.Button(self.root, text="Decrypt", command=self.decrypt_text, style=button_style)
        self.copy_button = ttk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard, style=button_style)
        self.clipid_button = ttk.Button(self.root, text="Clip Monitor", command=self.run_clipid, style=button_style)
        self.quit_button = ttk.Button(self.root, text="Quit", command=self.root.quit, style=button_style)     
        self.open_log_button = ttk.Button(self.root, text="Open Log", command=self.open_log_file, style=button_style)
        self.clear_button = ttk.Button(self.root, text="Clear I/O ", command=self.clear_message_windows, style=button_style)
        self.delete_log_button = ttk.Button(self.root, text="Clear Log", command=self.confirm_clear_log_file, style=button_style)

        # Create a button to run UserBase.py
        self.run_user_base_button = ttk.Button(self.root, text="Run UserBase", command=self.run_user_base_program, style=button_style)
        self.run_user_base_button.grid(row=3, column=3, columnspan=1, padx=25, pady=5, sticky="we")

        # Create a "Check Encrypted" button
        self.check_encrypted_button = ttk.Button(self.root, text="Check Encrypted", command=self.check_encrypted, style=button_style)
        self.check_encrypted_button.grid(row=8, column=0, padx=2, pady=2, sticky="e")

        # Create a clear input button
        self.clear_input_button = ttk.Button(self.root, text="Clear Input Window", command=self.clear_input_window, style=button_style)
        self.clear_input_button.grid(row=3, column=0, columnspan=1, padx=120, pady=5, sticky="w")
     
        # Place GUI components using grid
        self.input_label.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky="w")
        self.text_entry.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky="we")
        self.encrypt_button.grid(row=5, column=0, columnspan=1, padx=2, pady=2, sticky="e")
        self.paste_button.grid(row=5, column=1, columnspan=1, padx=3, pady=2, sticky="we")
        self.decrypt_button.grid(row=5, column=2, columnspan=1, padx=2, pady=2, sticky="w")
        self.output_label.grid(row=5, column=0, columnspan=4, padx=5, pady=5, sticky="w")
        self.output_text.grid(row=7, column=0, columnspan=4, padx=5, pady=5, sticky="we")
        self.copy_button.grid(row=8, column=1, columnspan=1, padx=5, pady=5, sticky="we") 
        self.clipid_button.grid(row=8, column=2, padx=3, pady=5, sticky="w")  
        self.quit_button.grid(row=10, column=3, columnspan=1, padx=25, pady=5, sticky="we")
        self.toggle_top_button = ttk.Checkbutton(self.root, text="Always on Top", variable=self.always_on_top, command=self.toggle_always_on_top, style="TCheckbutton")
        self.toggle_top_button.grid(row=10, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        self.open_log_button.grid(row=0, column=3, padx=25, pady=5, sticky="e")
        self.delete_log_button.grid(row=0, column=2, padx=60, pady=5, sticky="w")


        # Create and place labels and entry fields for username and user group
        senderusername_label = tk.Label(self.root, text="Sender Username:")
        senderusername_label.grid(row=2, column=1, columnspan=1, padx=10, pady=2, sticky=tk.W+tk.E)
        self.senderusername_entry = tk.Entry(self.root, state="readonly")
        self.senderusername_entry.grid(row=3, column=1, columnspan=1, padx=0, pady=2, sticky=tk.W+tk.E)

        senderusergroup_label = tk.Label(self.root, text="Sender User Group:")
        senderusergroup_label.grid(row=2, column=2, columnspan=1, padx=25, pady=2, sticky=tk.W+tk.E)
        self.senderusergroup_entry = tk.Entry(self.root, state="readonly")
        self.senderusergroup_entry.grid(row=3, column=2, columnspan=1, padx=25, pady=2, sticky=tk.W+tk.E)

        # Add two entry widgets for sender name and group name

        self.theme_label = ttk.Label(self.root, text="Select Theme")
        self.theme_var = tk.StringVar()
        self.theme_selector = ttk.Combobox(
        self.root, textvariable=self.theme_var, values=self.style.get_themes())
        self.theme_selector.bind("<<ComboboxSelected>>", self.change_theme)
        self.theme_selector.set(self.current_theme)  # Set the theme from the loaded configuration
        self.theme_label.grid(row=9, column=0, padx=10, pady=5, sticky="w")
        self.theme_selector.grid(row=10, column=0, padx=10, pady=5, sticky="w")
        self.clear_button.grid(row=5, column=0, padx=120, pady=5, sticky="w")


        # Call toggle_always_on_top to set the window behavior
        self.toggle_always_on_top()

        self.root.mainloop()

    def open_chat_program(self):
        import os

        # Specify the path to the Messenger executable
        messenger_path = os.path.join(os.path.expanduser('~'), "AppData", "Local", "Programs", "Messenger", "Messenger.exe")

        try:
            # Open the Messenger application
            os.startfile(messenger_path)
        except FileNotFoundError:
            messagebox.showerror("File Not Found", "The chat program executable was not found at the specified path. Please install the Messenger application.")


# Update the generate_hash method
    def generate_hash(self):
        username = self.username_entry.get().strip()
        usergroup = self.usergroup_entry.get().strip()

        if username and usergroup:
            combined_data = f"{username}:{usergroup}"
            hash_code = hashlib.sha256(combined_data.encode()).hexdigest()
            self.hash_entry.config(state="normal")
            self.hash_entry.delete(0, tk.END)
            self.hash_entry.insert(0, hash_code)
            self.hash_entry.config(state="readonly")

            if hash_code:
                if self.check_user_authorization(username, usergroup, hash_code):
                    messagebox.showinfo("Authorization Success", "User and User Group are authorized. Hash Security Enabled")
                    # Enable the buttons if the user is authorized
                    self.encrypt_button.config(state=tk.NORMAL)
                    self.decrypt_button.config(state=tk.NORMAL)
                    self.check_encrypted_button.config(state=tk.NORMAL)
                else:
                    messagebox.showwarning("Authorization Failure", "User and User Group are Incorrect, please check (CASE SENSITIVE !!)  Un-authorized.")
                    # Disable the buttons if the user is not authorized
                    self.encrypt_button.config(state=tk.DISABLED)
                    self.decrypt_button.config(state=tk.DISABLED)
                    self.check_encrypted_button.config(state=tk.DISABLED)
        else:
            messagebox.showwarning("Missing Information", "Group Message: Please provide both username and user group before 'GenHash', Button.")


    # Implement the clear_hash method
    def clear_hash(self):
        self.username_entry.delete(0, tk.END)
        self.usergroup_entry.delete(0, tk.END)
        self.hash_entry.config(state="normal")
        self.hash_entry.delete(0, tk.END)
        self.hash_entry.config(state="readonly")
        # Enable the buttons since the hash has been cleared
        self.encrypt_button.config(state=tk.NORMAL)
        self.decrypt_button.config(state=tk.NORMAL)
        self.check_encrypted_button.config(state=tk.NORMAL)
        # ...


# Modify the check_user_authorization method

    def check_user_authorization(self, username, usergroup, hash_code):
        try:
            if not os.path.exists('user_data.txt'):
                messagebox.showinfo("Database Not Found", "No user database found. Please create a user database first.")
                return False

            with open('user_data.txt', 'r') as file:
                # Read only the first line
                line = file.readline().strip()
                if not line:
                    messagebox.showinfo("Empty Database", "The user database is empty.")
                    return False

                encoded_data = line
                decoded_data = base64.b64decode(encoded_data).decode()
                data_entry = json.loads(decoded_data)
                stored_username = data_entry.get("username", "")
                stored_usergroup = data_entry.get("group", "")
                stored_hash_code = data_entry.get("hash", "")

                if hash_code == stored_hash_code:
                    if username == stored_username and usergroup == stored_usergroup:
                        self.authorization_results[(username, usergroup)] = True
                        return True

        except Exception as e:
            print(f"An error occurred while checking authorization: {e}")

        self.authorization_results[(username, usergroup)] = False
        return False

            # ...


    def check_encrypted(self):
        try:
            # Get the encrypted text from the clipboard
            clipboard_text = pyperclip.paste()

            # Check if the clipboard text is empty
            if not clipboard_text.strip():
                messagebox.showwarning("Clipboard Empty", "No encrypted data found in the clipboard.")
                return

            # Split the clipboard text by '@'
            split_text = clipboard_text.split('@')

            # Check if split_text has at least two elements
            if len(split_text) >= 2:
                key_length = int(split_text[1].strip())
            else:
                # Handle the case when the split result doesn't have enough elements
                messagebox.showwarning("Invalid Input", "Invalid input format for decryption.")
                return

            public_mode = key_length <= 63

            if public_mode:
                # Public messaging scenario
                decrypted_text = self.cipher.decrypt(clipboard_text)
            else:
                # Existing group messaging logic
                hash_code = split_text[0].strip()

                if hash_code:
                    # Continue with username and user group checks
                    username = self.username_entry.get().strip()
                    usergroup = self.usergroup_entry.get().strip()

                    if not (username and usergroup):
                        messagebox.showwarning("Missing Information", "Please provide both username and user group before performing decryption.")
                        return

                    # Check if the hash code exists in the user_data.txt file
                    if self.check_hash_in_user_base(hash_code):
                        # Retrieve user data from the user_data.txt file based on the hash code
                        sender_username, sender_usergroup = self.get_user_data_from_hash(hash_code)

                        if sender_username and sender_usergroup:
                            # Display sender's information in the GUI
                            self.senderusername_entry.config(state="normal")
                            self.senderusername_entry.delete(0, tk.END)
                            self.senderusername_entry.insert(0, sender_username)
                            self.senderusername_entry.config(state="readonly")

                            self.senderusergroup_entry.config(state="normal")
                            self.senderusergroup_entry.delete(0, tk.END)
                            self.senderusergroup_entry.insert(0, sender_usergroup)
                            self.senderusergroup_entry.config(state="readonly")

                            # Proceed with decryption using the hash code
                            decrypted_text = self.decode_secret_code(clipboard_text, hash_code)
                        else:
                            messagebox.showinfo("User Data Not Found", "No user data found for the given hash code.")
                            return
                    else:
                        messagebox.showinfo("Unauthorized", "This message isn't for your eyes.  Try adding the User's Details to the DataBase")
                        return
                else:
                    messagebox.showwarning("Invalid Input", "Invalid input format for decryption.")
                    return

            # Save the decrypted text to a .txt file
            with open('decrypted_text.txt', 'w') as file:
                file.write(decrypted_text)

            # Open the decrypted text file with the default program
            try:
                subprocess.Popen(['open', 'decrypted_text.txt'])  # On macOS
            except FileNotFoundError:
                try:
                    subprocess.Popen(['xdg-open', 'decrypted_text.txt'])  # On Linux
                except FileNotFoundError:
                    try:
                        subprocess.Popen(['start', 'decrypted_text.txt'], shell=True)  # On Windows
                    except FileNotFoundError:
                        messagebox.showwarning("File Not Found", "Unable to open 'decrypted_text.txt'. You can manually open it.")
        except ValueError as e:
            messagebox.showerror("Decryption Error", "No Encrypted Data found on the Clip Board or in the Wrong Format!,  Check Clip Monitor...")
            # messagebox.showerror("Decryption Error", str(e))

            # Return focus to the generator window
            self.root.focus_set()


    # Add the open_log_file method to the SecretCodeGeneratorApp class
    def open_log_file(self):
        log_file = 'SCG.log'
        if os.path.exists(log_file):
            try:
                subprocess.Popen(['notepad.exe', log_file])  # Open the log file in Notepad
            except FileNotFoundError:
                messagebox.showerror("File Not Found", "Notepad not found. Please open the log file manually.")
        else:
            messagebox.showerror("File Not Found", "The log file 'SCG.log' does not exist.")

    def configure_logging(self):
        log_file = 'SCG.log'
        if not os.path.exists(log_file):
            with open(log_file, 'w'):
                pass

        # Define a custom log message format
        log_format = '%(asctime)s - %(levelname)s - %(message)s'

        # Create a Formatter with the desired date format
        formatter = logging.Formatter(log_format, datefmt='%d%b%Y %H:%M')

        # Create a FileHandler for writing log messages to the file
        file_handler = logging.FileHandler(log_file, mode='a')  # Use 'a' mode to append to the log file
        file_handler.setLevel(logging.INFO)

        # Set the formatter for the FileHandler
        file_handler.setFormatter(formatter)

        # Create a Logger and add the FileHandler
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    def log_event(self, event_message):
        # Append each log entry with a newline character
        logging.info(event_message + '\n')

    # Define Clear input window Button Action
    def clear_input_window(self):
        self.text_entry.delete(1.0, tk.END)


    def confirm_clear_log_file(self):
        result = messagebox.askyesno("Confirm Clear Log", "Are you sure you want to clear the log file?")
        if result:
            self.clear_log_file()

    def clear_log_file(self):
        log_file = 'SCG.log'
        if os.path.exists(log_file):
            try:
                with open(log_file, 'w') as log_file:
                    log_file.write('')  # Truncate the log file to clear its contents
                messagebox.showinfo("Log File Cleared", "The log file has been cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while clearing the log file: {str(e)}")
        else:
            messagebox.showerror("File Not Found", "The log file 'SCG.log' does not exist.")

    def run_user_base_program(self):
        # Check if the Python script exists
        if os.path.exists('UserBase.py'):
            program_to_run = "python UserBase.py"
        # If the Python script doesn't exist, check for the executable
        elif os.path.exists('UserBase.exe'):
            program_to_run = "UserBase.exe"
        else:
            messagebox.showerror("File Not Found", "UserBase program not found.")
            return

        try:
            subprocess.Popen(program_to_run, shell=True)
        except FileNotFoundError:
            messagebox.showerror("File Not Found", f"Error: {program_to_run} not found.")

    # ComplexCaesarCipherHash Encryption and Decryption
    def generate_secret_code(self, message, hash_key=None):
        if hash_key:
            encrypted_message = self.caesar_cipher_hash.encrypt_with_hash(message, hash_key)
            return encrypted_message
        else:
            encrypted_message = self.caesar_cipher.encrypt(message)
            return encrypted_message

    def decode_secret_code(self, encoded_message, hash_key=None):
        if hash_key:
            decoded_message = self.caesar_cipher_hash.decrypt_with_hash(encoded_message, hash_key)
            return decoded_message
        else:
            decoded_message = self.caesar_cipher.decrypt(encoded_message)
            return decoded_message


        self.public_mode = True   #Set true for public


    def encrypt_text(self):
        self.current_action = "Encrypt"
        input_text = self.text_entry.get(1.0, tk.END).strip()
        hash_code = self.hash_entry.get().strip()

        if not hash_code:
            # If no hash is present, use the random key
            encrypted_result = self.cipher.encrypt(input_text)
        else:
            username = self.username_entry.get().strip()
            usergroup = self.usergroup_entry.get().strip()

            if not (username and usergroup):
                messagebox.showwarning("Missing Information", "Please provide both username and user group before performing encryption.")
                return

            encrypted_result = self.generate_secret_code(input_text, hash_code)

        self.log_event("Input: " + input_text)
        self.log_event("Encrypted: " + encrypted_result)

        # Display the encrypted result in the output window and update the GUI
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_result)
        self.root.update_idletasks()  # Update the GUI

        # Automatically copy the encrypted result to the clipboard
        pyperclip.copy(encrypted_result)



    def decrypt_text(self):
        self.current_action = "Decrypt"
        input_text = self.text_entry.get(1.0, tk.END).strip()  # Get input text from the text entry

        # Split the input text by '@'
        split_text = input_text.split('@')

        # Check if split_text has at least two elements
        if len(split_text) >= 2:
            key_length = int(split_text[1].strip())
        else:
            # Handle the case when the split result doesn't have enough elements
            messagebox.showwarning("Invalid Input", "Invalid input format for decryption.")
            return

        self.public_mode = key_length <= 63

        if not self.public_mode:
            # Existing group messaging logic
            hash_code = split_text[0].strip()

            if hash_code:
                # Continue with username and user group checks
                username = self.username_entry.get().strip()
                usergroup = self.usergroup_entry.get().strip()

                if not (username and usergroup):
                    messagebox.showwarning("Missing Information", "Please provide both username and user group before performing decryption.")
                    return

                # Check if the hash code exists in the user_data.txt file
                if self.check_hash_in_user_base(hash_code):
                    # Retrieve user data from the user_data.txt file based on the hash code
                    sender_username, sender_usergroup = self.get_user_data_from_hash(hash_code)

                    if sender_username and sender_usergroup:
                        # Display sender's information in the GUI
                        self.senderusername_entry.config(state="normal")
                        self.senderusername_entry.delete(0, tk.END)
                        self.senderusername_entry.insert(0, sender_username)
                        self.senderusername_entry.config(state="readonly")

                        self.senderusergroup_entry.config(state="normal")
                        self.senderusergroup_entry.delete(0, tk.END)
                        self.senderusergroup_entry.insert(0, sender_usergroup)
                        self.senderusergroup_entry.config(state="readonly")

                        # Proceed with decryption using the hash code
                        decrypted_result = self.decode_secret_code(input_text, hash_code)
                    else:
                        messagebox.showinfo("User Data Not Found", "No user data found for the given hash code.")
                        return
                else:
                    messagebox.showinfo("Unauthorized", "This message isn't for your eyes.  Try adding the User's Details to the DataBase")
                    return
            else:
                messagebox.showwarning("Invalid Input", "Invalid input format for decryption.")
                return
        else:
            # Public messaging scenario
            decrypted_result = self.cipher.decrypt(input_text)

            # Clear sender's information in the GUI for public messages
            self.senderusername_entry.config(state="normal")
            self.senderusername_entry.delete(0, tk.END)
            self.senderusername_entry.config(state="readonly")

            self.senderusergroup_entry.config(state="normal")
            self.senderusergroup_entry.delete(0, tk.END)
            self.senderusergroup_entry.config(state="readonly")

        self.log_event("Input: " + input_text)
        self.log_event("Decrypted: " + decrypted_result)

        # Display the decrypted result in the output window
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, decrypted_result)

        # Automatically copy the decrypted result to the clipboard
        pyperclip.copy(decrypted_result)

    
    # Helper method to check if the message is authorized
    def is_message_authorized(self, hash_code):
        # Your logic to check authorization goes here
        # For example, you can check if the hash code exists in an authorized messages list
        authorized_messages = ["authorized_hash_1", "authorized_hash_2", ...]

        return hash_code in authorized_messages


    # Helper method to get the line containing the hash code from the user_base.txt file
    def get_line_from_user_base(self, hash_code):
        try:
            if not os.path.exists('user_data.txt'):
                messagebox.showinfo("Database Not Found", "No user base database found. Please create a user base database first.")
                return ""

            with open('user_data.txt', 'r') as file:
                for line in file:
                    if line.strip() == hash_code:
                        return line.strip()
        except Exception as e:
            print(f"An error occurred while getting line from user base: {e}")

        return ""


    # Helper method to check if the hash code exists in the user_data.txt file
    def check_hash_in_user_base(self, hash_code):
        try:
            user_data_path = 'user_data.txt'
            if not os.path.exists(user_data_path):
                messagebox.showinfo("Database Not Found", f"No user data database found at {user_data_path}. Please create a user data database first.")
                return False

            with open(user_data_path, 'r') as file:
                for line in file:
                    encoded_data = line.strip()
                    try:
                        decoded_data = base64.b64decode(encoded_data).decode()
                        data_entry = json.loads(decoded_data)
                        stored_hash_code = data_entry.get("hash", "")

                        if hash_code == stored_hash_code:
                            return True
                    except Exception as e:
                        print(f"An error occurred while decoding user data: {e}")

        except Exception as e:
            print(f"An error occurred while checking hash in user data: {e}")

        return False


    # Helper method to get user data from the user_data.txt file based on the hash code
    def get_user_data_from_hash(self, hash_code):
        try:
            if not os.path.exists('user_data.txt'):
                messagebox.showinfo("Database Not Found", "No user data database found. Please create a user data database first.")
                return "", ""

            with open('user_data.txt', 'r') as file:
                for line in file:
                    encoded_data = line.strip()
                    decoded_data = base64.b64decode(encoded_data).decode()
                    data_entry = json.loads(decoded_data)
                    stored_hash_code = data_entry.get("hash", "")
                    stored_username = data_entry.get("username", "")
                    stored_usergroup = data_entry.get("group", "")

                    print("File Data:", stored_hash_code, stored_username, stored_usergroup)

                    if hash_code == stored_hash_code:
                        return stored_username, stored_usergroup

        except Exception as e:
            print(f"An error occurred while getting user data from hash: {e}")

        return "", ""
        
    def is_authorized(self, username, usergroup):
        try:
            with open('user_data.txt', 'r') as file:
                for line in file:
                    decoded_data = base64.b64decode(line.strip()).decode()
                    data_entry = json.loads(decoded_data)
                    stored_username = data_entry.get("username", "")
                    stored_usergroup = data_entry.get("groups", "")
                    if username == stored_username and usergroup in stored_usergroup:
                        return True
            return False
        except Exception as e:
            print(f"An error occurred while checking authorization: {e}")
            return False

    def perform_action(self):
        text = self.text_entry.get(1.0, tk.END).strip()
        if text:
            username = self.username_entry.get().strip()
            usergroup = self.usergroup_entry.get().strip()
            if not username and not usergroup:
                result = self.cipher.encrypt(text)  # Use the regular ComplexCaesarCipher encryption
                self.log_event("Input: " + text)
                self.log_event("Encrypted: " + result)
            elif (username, usergroup) in self.authorization_results and self.authorization_results[(username, usergroup)]:
                result = self.send_to_complex_caesar_cipher_hash(text)  # Process the message through ComplexCaesarCipherHash
                self.log_event("Input: " + text)
                self.log_event("Processed through ComplexCaesarCipherHash: " + result)
            else:
                if self.current_action == "Encrypt":
                    result = self.cipher.encrypt(text)  # Use the regular ComplexCaesarCipher encryption
                    self.log_event("Input: " + text)
                    self.log_event("Encrypted: " + result)
                elif self.current_action == "Decrypt":
                    result = self.cipher.decrypt(text)  # Use the regular ComplexCaesarCipher decryption
                    self.log_event("Input: " + text)
                    self.log_event("Decrypted: " + result)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, result)
        else:
            messagebox.showwarning("Input Error", "Please enter text.")
                
        
    def clear_message_windows(self):
        # Clear both input and message windows
        self.text_entry.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
       
    def copy_to_clipboard(self):
        output_text = self.output_text.get(1.0, tk.END).strip()
        if output_text:
            pyperclip.copy(output_text)
            # messagebox.showinfo("Clipboard", "Text copied to clipboard.")
        else:
            messagebox.showwarning("Empty Text", "No text to copy to clipboard.")

    def paste_from_clipboard(self):
        clipboard_text = pyperclip.paste()
        self.text_entry.delete(1.0, tk.END)
        self.text_entry.insert(tk.END, clipboard_text)

    def run_clipid(self):
        # Check if the Python script exists
        if os.path.exists('Clipid.py'):
            program_to_run = "python Clipid.py"
        # If the Python script doesn't exist, check for the executable
        elif os.path.exists('Clipid.exe'):
            program_to_run = "Clipid.exe"
        else:
            messagebox.showerror("File Not Found", "Clipid program not found.")
            return

        try:
            subprocess.Popen(program_to_run, shell=True)
        except FileNotFoundError:
            messagebox.showerror("File Not Found", f"Error: {program_to_run} not found.")


    def toggle_always_on_top(self):
        self.root.attributes("-topmost", self.always_on_top.get())

    def change_theme(self, event):
        selected_theme = self.theme_var.get()
        self.style.set_theme(selected_theme)
        # Save the selected theme to the config.ini file
        self.save_theme_config(selected_theme)

    def save_theme_config(self, selected_theme):
        config = configparser.ConfigParser()
        config['Settings'] = {'Theme': selected_theme}
        with open('config.ini', 'w') as config_file:
            config.write(config_file)

    def load_theme_config(self):
        config = configparser.ConfigParser()
        if os.path.exists('config.ini'):
            config.read('config.ini')
            if 'Settings' in config and 'Theme' in config['Settings']:
                self.current_theme = config['Settings']['Theme']
            else:
                self.current_theme = "aquativo"  # Default theme
        else:
            self.current_theme = "aquativo"  # Default theme

        # Apply the loaded theme
        self.style.set_theme(self.current_theme)

if __name__ == "__main__":
    app = SecretCodeGeneratorApp()
