## USERBASE ##

import tkinter as tk
import tkinter.messagebox
from tkinter import ttk
import os
import sys
import json
import base64
import hashlib
import configparser
import ttkthemes
import ctypes
import time
import tkinter.filedialog
import shutil


# Initialize a dictionary to store user-group associations
user_groups = {}
# Initialize a dictionary to store group-user associations
group_users = {}


def center_window(window, window_width, window_height):
    # Get the screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # Calculate the position for the window to be centered
    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)

    # Set the window geometry to be centered while keeping the size the same
    window.geometry(f"{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}")

# Create the main window
root = tk.Tk()
root.title("User Group Management -- COLEuk -- Ver 4.1.2")

# Set the window size to 650x445 (adjusted width and height)
window_width = 650
window_height = 445
root.geometry(f"{window_width}x{window_height}")

# Center the window on the screen
center_window(root, window_width, window_height)


# Call the center_window function to center the window
center_window(root, window_width, window_height)

# Function to check if the admin passcode file exists
def check_adminpasscode_file():
    adminpasscode_path = 'adminpasscode'  # File path without extension
    if not os.path.exists(adminpasscode_path):
        create_adminpasscode_window()
    else:
        verify_adminpasscode()


# Function to generate the recovery record using the hash version of the admin passcode
def generate_recovery_record():
    admin_passcode_file = "adminpasscode"
    if os.path.exists(admin_passcode_file):
        with open(admin_passcode_file, 'r') as file:
            admin_passcode = file.readline().strip()  # Read the first line only
            print("Admin Passcode:", admin_passcode)  # Add this line for debugging
            if len(admin_passcode) == 64:
                hashed_passcode = hashlib.sha256(admin_passcode.encode()).hexdigest()
                return hashed_passcode
            else:
                print("Admin passcode is not a 64-character hash.")
                return None
    else:
        print("Admin passcode file not found.")
        return None

    
def save_recovery_record():
    recovery_record_file = 'recovery_record'  # Recovery file without Extension

    # Delete the file if it exists
    if os.path.exists(recovery_record_file):
        os.remove(recovery_record_file)

    recovery_record = generate_recovery_record()

    if recovery_record is not None:
        with open(recovery_record_file, 'w') as recovery_file:
            recovery_file.write(recovery_record)

        # Close the file before trying to copy or delete it
        recovery_file.close()

        # Set the hidden attribute for the file (works on Windows systems)
        try:
            ctypes.windll.kernel32.SetFileAttributesW(recovery_record_file, 2)  # 2 sets the file to hidden
        except AttributeError:  # For non-Windows systems
            pass

    # Ask the user for the location to save the recovery record file
    file_path = tkinter.filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path and os.path.exists(recovery_record_file):
        shutil.copy(recovery_record_file, file_path)



# Function to create the admin passcode using a Tkinter input window
def create_adminpasscode_window():
    def save_adminpasscode():
        adminpasscode = passcode_entry.get().strip()
        username = username_entry.get().strip()
        usergroup = usergroup_entry.get().strip()

        if len(adminpasscode) < 6 or len(adminpasscode) > 12 or not adminpasscode.isdigit():
            tk.messagebox.showerror("Invalid passcode", "Please enter a passcode with 6 to 12 digits.")
        elif not username or not usergroup:
            tk.messagebox.showerror("Missing Information", "Please enter your username and user group.")
        else:
            hashed_passcode = hashlib.sha256(adminpasscode.encode()).hexdigest()
            adminpasscode_path = 'adminpasscode'  # File path without extension
            user_data_path = 'user_data.txt'

            with open(adminpasscode_path, 'a') as file:
                file.write(hashed_passcode + '\n')  # Line 1: Store hashed passcode

                # Line 2: Store user information in the new format
                combined_data = f"{username}:{usergroup}"
                hashed_data = hashlib.sha256(combined_data.encode()).hexdigest()
                user_data = {"username": username, "group": usergroup, "hash": hashed_data}
                encoded_user_info = base64.b64encode(json.dumps(user_data).encode()).decode()
                file.write(encoded_user_info + '\n')

            try:
                # Check if user_data.txt file exists
                if not os.path.exists(user_data_path):
                    # Create user_data.txt and copy data from line 2 of adminpasscode
                    with open(user_data_path, 'w') as user_data_file:
                        with open(adminpasscode_path, 'r') as adminpasscode_file:
                            # Read the second line from adminpasscode
                            adminpasscode_file.readline()  # Read and discard line 1
                            user_data = adminpasscode_file.readline().strip()  # Read line 2
                            # Write user_data to user_data.txt
                            user_data_file.write(user_data)

                # Set the hidden attribute for the adminpasscode file (works on Windows systems)
                ctypes.windll.kernel32.SetFileAttributesW(adminpasscode_path, 2)  # 2 sets the file to hidden
            except AttributeError:  # For non-Windows systems
                pass

            passcode_window.destroy()
            check_adminpasscode_file()  # Return to the initial passcode input window            

            
    passcode_window = tk.Toplevel(root)
    passcode_window.title("Admin Passcode Creation")
    window_width = 460
    window_height = 300
    passcode_window.geometry(f"{window_width}x{window_height}")
    center_window(passcode_window, window_width, window_height)

    passcode_label = tk.Label(passcode_window, text="Create a new admin passcode (min 6 numbers, max 12 numbers):")
    passcode_label.pack(pady=10)
    passcode_entry = ttk.Entry(passcode_window, show="*")
    passcode_entry.pack(pady=5)

    username_label = tk.Label(passcode_window, text="Enter your username:")
    username_label.pack(pady=5)
    username_entry = ttk.Entry(passcode_window)
    username_entry.pack(pady=5)

    usergroup_label = tk.Label(passcode_window, text="Enter your user group:")
    usergroup_label.pack(pady=5)
    usergroup_entry = ttk.Entry(passcode_window)
    usergroup_entry.pack(pady=5)

    save_button = ttk.Button(passcode_window, text="Save Passcode", command=save_adminpasscode)
    save_button.pack(pady=10)

    # Grab the focus to the passcode_window
    passcode_window.grab_set()

    # Withdraw the main window until the passcode is successfully created
    root.withdraw()

    

# Function to remove adminpasscode, recovery_record and user_data.txt files
def remove_files():
    if os.path.exists('adminpasscode'):
        os.remove('adminpasscode')
        print("Admin passcode file removed.")

    if os.path.exists('user_data.txt'):
        os.remove('user_data.txt')
        print("User data file removed.")

    if os.path.exists('recovery_record'):
        os.remove('recovery_record')
        print("Recovery Record Removed.")

# Function to restart the program and ask for a new password
def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)

# Function to verify the admin passcode
def verify_adminpasscode():
    def verify_passcode():
        adminpasscode_path = 'adminpasscode'  # File path without extension
        input_passcode = passcode_entry.get().strip()
        if not os.path.exists(adminpasscode_path):
            tk.messagebox.showerror("File not found", "Admin passcode file not found.")
            return

        with open(adminpasscode_path, 'r') as file:
            stored_passcode_line = file.readline().strip()
            stored_passcode = stored_passcode_line.split(':')[0]  # Extract hashed passcode from the line

            input_passcode_hashed = hashlib.sha256(input_passcode.encode()).hexdigest()
#            print("Input Passcode Hash:", input_passcode_hashed)
#            print("Stored Passcode Hash:", stored_passcode)
            
            if input_passcode_hashed == stored_passcode:
                data_operations_frame.grid()
                user_operations_frame.grid()
                passcode_window.destroy()
                root.deiconify()  # Show the main window after successfully verifying the passcode
                load_data()  # Load the data once the passcode is verified
            else:
                tk.messagebox.showerror("Incorrect passcode", "The passcode entered is incorrect.")


    def on_forgotten_passcode():
        if passcode_window:
            passcode_window.withdraw()  # Close the passcode_window if it exists

        Pc_Reset_window = tk.Toplevel(root)
        Pc_Reset_window.title("Pc_Reset")
        Pc_Reset_window.geometry("325x175")

        # Center the Pc_Reset_window on the screen
        Pc_Reset_window_width = 425
        Pc_Reset_window_height = 175
        center_window(Pc_Reset_window, Pc_Reset_window_width, Pc_Reset_window_height)

        Pc_Reset_label = tk.Label(Pc_Reset_window, text="WARNING:  Load Recovery File & Reset Passcode (Database is Preserved) |  OR  | Destroy User Base & Passcode before resetting Passcode?", wraplength=400)
        Pc_Reset_label.pack(pady=20)

        def on_destroy():
            remove_files()
            Pc_Reset_window.destroy()
            root.destroy()  # Destroy the main window
            restart_program()  # Restart the program

        # Function to restart the program and ask for a new password
        def restart_program():
            python = sys.executable
            os.execl(python, python, *sys.argv)

        def on_abort():
            Pc_Reset_window.destroy()
        if passcode_window.winfo_exists():  # Check if the window exists
            passcode_window.deiconify()
        else:
            print("Passcode window does not exist.")
            passcode_window.deiconify()

        def on_recovery():
            # Ask the user to select their recovery file
            file_path = tkinter.filedialog.askopenfilename()

            if file_path and os.path.exists(file_path):
                # Read the contents of the user's recovery file
                with open(file_path, 'r') as user_recovery_file:
                    user_recovery_hash = user_recovery_file.read().strip()

                # Read the contents of the recovery record file
                recovery_record_file = 'recovery_record'
                if os.path.exists(recovery_record_file):
                    with open(recovery_record_file, 'r') as recovery_record:
                        recovery_record_hash = recovery_record.read().strip()

                    # Compare the contents of the two files
                    if user_recovery_hash == recovery_record_hash:
                        # If the contents match, delete the adminpasscode file
                        admin_passcode_file = "adminpasscode"
                        if os.path.exists(admin_passcode_file):
                            os.remove(admin_passcode_file)
                            print("Admin Passcode Reset, Sucessfully")

                            # Open the 'Admin Passcode Creation' dialog
                            create_adminpasscode_window()

                            # Destroy the current window
                            Pc_Reset_window.destroy()
                        else:
                            tk.messagebox.showerror("File not found", "Admin passcode file not found.")
                    else:
                        tk.messagebox.showerror("Recovery Failed", "Recovery code does not match the stored admin passcode.")
                else:
                    tk.messagebox.showerror("File not found", "Recovery record file not found.")
            else:
                tk.messagebox.showerror("File not selected", "Please select a valid recovery file.")
            
            # Show the Pc_Reset window
            passcode_window.deiconify()
                   
            

        agree_button = ttk.Button(Pc_Reset_window, text="Destroy & Reset", command=on_destroy)
        agree_button.pack(pady=10, side=tk.RIGHT)

        abort_button = ttk.Button(Pc_Reset_window, text="Abort Recovery", command=on_abort)
        abort_button.pack(pady=10, side=tk.LEFT)

        recovery_button = ttk.Button(Pc_Reset_window, text="Recovery File", command=on_recovery)
        recovery_button.pack(pady=10)
        recovery_button.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
       

    
    passcode_window = tk.Toplevel(root)
    passcode_window.title("Admin Passcode Verification")
    passcode_window.geometry("360x240")

    # Center the passcode_window on the screen
    passcode_window_width = 360
    passcode_window_height = 240
    center_window(passcode_window, passcode_window_width, passcode_window_height)

    passcode_label = tk.Label(passcode_window, text="Enter admin passcode:")
    passcode_label.pack(pady=10)
    passcode_entry = ttk.Entry(passcode_window, show="*")
    passcode_entry.pack(pady=5)
    verify_button = ttk.Button(passcode_window, text="Verify Passcode", command=verify_passcode)
    verify_button.pack(pady=10)
    forgotten_passcode_button = ttk.Button(passcode_window, text="Forgotten Passcode", command=on_forgotten_passcode)
    forgotten_passcode_button.pack(pady=10)

    root.withdraw()

    

# Call check_adminpasscode_file function on program start
check_adminpasscode_file()


# Read the theme name from config.ini or use a default theme
config = configparser.ConfigParser()
if os.path.exists('config.ini'):
    config.read('config.ini')
    if 'Settings' in config and 'Theme' in config['Settings']:
        current_theme = config['Settings']['Theme']
    else:
        current_theme = "ubuntu"  # Default theme
else:
    current_theme = "ubuntu"  # Default theme

# Initialize ttkthemes
style = ttkthemes.ThemedStyle(root)
style.set_theme(current_theme)

# Function to change the theme when a new theme is selected from the dropdown
def change_theme(*args):
    new_theme = selected_theme.get()
    style.set_theme(new_theme)

# Get a list of available ttk themes using ttkthemes
available_themes = [current_theme]  # Include only the current theme

# Create a StringVar to store the selected theme
selected_theme = tk.StringVar()


# Function to update the listbox with data
def update_listbox():
    # Clear the listbox
    members_listbox.delete(0, tk.END)
    # Add users and their group associations to the listbox
    for username, groups in user_groups.items():
        for group in groups:
            members_listbox.insert(tk.END, f"Username: {username}, User Group: {group}")


# Function to load all available theme styles
def load_all_theme_styles():
    global style
    for theme in available_themes:
        style.set_theme(theme)
        root.update()  # Update the GUI to reflect the new theme
        yield theme

# Call your theme loading function to load the current theme
for theme in load_all_theme_styles():
    print(f"Loaded theme: {theme}")
    
# Configure column weights to ensure widgets span the entire width
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.rowconfigure(0, weight=0)
root.rowconfigure(1, weight=0)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=0)
root.rowconfigure(4, weight=0)
root.rowconfigure(5, weight=0)
root.rowconfigure(6, weight=0)
root.rowconfigure(7, weight=0)



# Create and place labels and entry fields for username and user group
username_label = ttk.Label(root, text="Username:")
username_label.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
username_entry = ttk.Entry(root)
username_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W + tk.E)

usergroup_label = ttk.Label(root, text="User Group:")
usergroup_label.grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
usergroup_entry = ttk.Entry(root)
usergroup_entry.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W + tk.E)

# Create StringVar objects for the selected user and group
selected_user = tk.StringVar()
selected_group = tk.StringVar()

# Create a listbox to display members
members_listbox = tk.Listbox(root)
members_listbox.grid(row=2, column=0, columnspan=3, padx=2, pady=2, sticky=tk.W + tk.E + tk.N + tk.S)  # Span multiple columns and rows

# Create a vertical scrollbar for the listbox
scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL, command=members_listbox.yview)
scrollbar.grid(row=2, column=3, sticky=tk.N + tk.S)

# Configure the listbox to use the scrollbar
members_listbox.configure(yscrollcommand=scrollbar.set)


# Function to create a user
def create_user():
    username = username_entry.get().strip()
    usergroup = usergroup_entry.get().strip()

    # Check if username and usergroup are not empty
    if not username or not usergroup:
        return

    # Concatenate the username and usergroup
    combined_data = f"{username}:{usergroup}"
    # Hash the combined data using SHA-256
    hashed_data = hashlib.sha256(combined_data.encode()).hexdigest()

    # Check if the user already exists in the dictionary
    if username in user_groups:
        if usergroup not in user_groups[username]:
            user_groups[username].append(usergroup)
    else:
        user_groups[username] = [usergroup]

    # Check if the usergroup already exists in the group_users dictionary
    if usergroup in group_users:
        if username not in group_users[usergroup]:
            group_users[usergroup].append(username)
    else:
        group_users[usergroup] = [username]

    # Update the listbox
    update_listbox()
    # Save the data to the file
    save_data()


    
# Bind the listbox select event to a function that displays the selected user and group
def on_user_select(event):
    selected_index = members_listbox.curselection()
    if selected_index:
        selected_user_data = members_listbox.get(selected_index)
        selected_user.set(selected_user_data)  # Update the selected_user variable

# Function to delete a selected user
def delete_selected_user():
    selected_index = members_listbox.curselection()

    if selected_index:
        selected_user_data = members_listbox.get(selected_index)
        parts = selected_user_data.split(', ')
        username = parts[0].split(': ')[1]
        usergroup = parts[1].split(': ')[1]

        if username in user_groups:
            if usergroup in user_groups[username]:
                user_groups[username].remove(usergroup)
                if not user_groups[username]:
                    del user_groups[username]

        # Update the listbox
        update_listbox()
        # Clear the selected user and group
        selected_user.set("")
        selected_group.set("")
        # Save the data to the file
        save_data()

# Function to save user data with a hash to a file
def save_data():
    try:
        with open('user_data.txt', 'w') as file:
            for username, groups in user_groups.items():
                for group in groups:
                    # Combine username and group
                    combined_data = f"{username}:{group}"
                    # Hash the combined data using SHA-256
                    hashed_data = hashlib.sha256(combined_data.encode()).hexdigest()
                    # Convert user data to a JSON string
                    data_to_save = json.dumps({"username": username, "group": group, "hash": hashed_data})
                    # Encode the data using Base64
                    encoded_data = base64.b64encode(data_to_save.encode()).decode()
                    # Write the encoded data followed by a newline character
                    file.write(encoded_data + '\n')
    except Exception as e:
        print(f"An error occurred while saving data: {e}")

        
# Function to load, decrypt, and verify user data from a file
def load_data():
    global user_groups  # Declare user_groups as a global variable

    try:
        loaded_data = {}
        # Check if the data file exists
        if os.path.exists('user_data.txt'):
            with open('user_data.txt', 'r') as file:
                for line in file:
                    # Decode the data using Base64
                    decoded_data = base64.b64decode(line.strip()).decode()
                    # Deserialize the JSON data
                    data_entry = json.loads(decoded_data)
                    # Extract the username, group, and hash
                    username = data_entry["username"]
                    group = data_entry["group"]
                    stored_hash = data_entry.get("hash", "")

                    # Combine username and group
                    combined_data = f"{username}:{group}"
                    # Hash the combined data using SHA-256
                    computed_hash = hashlib.sha256(combined_data.encode()).hexdigest()

                    # Verify the hash
                    if stored_hash == computed_hash:
                        if username in loaded_data:
                            if group not in loaded_data[username]:
                                loaded_data[username].append(group)
                        else:
                            loaded_data[username] = [group]

            # Update the user_groups dictionary
            user_groups = loaded_data

            # Update the listbox
            update_listbox()  # Add this line to update the listbox
    except Exception as e:
        print(f"An error occurred while loading data: {e}")

        

# Call load_data function when the program starts
load_data()


# Function to retrieve and display the hash for the selected user
def show_hash():
    selected_index = members_listbox.curselection()

    if selected_index:
        selected_user_data = members_listbox.get(selected_index)
        parts = selected_user_data.split(', ')
        username = parts[0].split(': ')[1]
        usergroup = parts[1].split(': ')[1]

        # Combine username and group
        combined_data = f"{username}:{usergroup}"
        # Hash the combined data using SHA-256
        computed_hash = hashlib.sha256(combined_data.encode()).hexdigest()

        # Display the hash in a pop-up messagebox
        tk.messagebox.showinfo("Hash for Selected User", f"Hash: {computed_hash}")

# Create a button to show the hash
#show_hash_button = tk.Button(root, text="Show Hash", command=show_hash, padx=5, pady=2)
#show_hash_button.grid(row=5, column=2, padx=5, pady=2, sticky=tk.W+tk.E)


# Function to close the application
def close_app():
    root.destroy()

# Create a "Close" button at the bottom of the form
#close_button = tk.Button(root, text="Close", command=close_app, padx=5, pady=2)
#close_button.grid(row=7, column=0, columnspan=3, padx=2, pady=10, sticky=tk.W+tk.E)


# Check if the data file exists when the program starts and load the data if it exists
if os.path.exists('user_data.txt'):
    load_data()

# Bind listbox select event
members_listbox.bind('<<ListboxSelect>>', on_user_select)

# Create a frame for user operations (Create User and Delete User)
user_operations_frame = tk.Frame(root)
user_operations_frame.grid(row=3, column=0, columnspan=2, padx=2, pady=2, sticky=tk.W+tk.E)

#create_button = tk.Button(user_operations_frame, text="Create User", command=create_user, padx=5, pady=2)
#create_button.grid(row=0, column=0)

# Add space between the buttons using a Label as a spacer
spacer1 = tk.Label(user_operations_frame, text=" ", padx=5)
spacer1.grid(row=0, column=1)

#delete_button = tk.Button(user_operations_frame, text="Delete Selected User", command=delete_selected_user, padx=5, pady=2)
#delete_button.grid(row=0, column=2)

# Create a frame for save and load operations (Save Data and Load Data)
data_operations_frame = tk.Frame(root)
data_operations_frame.grid(row=4, column=0, columnspan=2, padx=2, pady=2, sticky=tk.W+tk.E)

#save_button = tk.Button(data_operations_frame, text="Save Data", command=save_data, padx=5, pady=2)
#save_button.grid(row=0, column=0)

# Create a button to save the recovery record
save_recovery_record_button = ttk.Button(root, text="Save  ~Recovery Record~", command=save_recovery_record, padding=(200, 0))
save_recovery_record_button.grid(row=6, column=0, columnspan=3, padx=2, pady=5, sticky=tk.W + tk.E)

# Add space between the buttons using a Label as a spacer
spacer2 = tk.Label(data_operations_frame, text=" ", padx=5)
spacer2.grid(row=0, column=1)

#load_button = tk.Button(data_operations_frame, text="Load Data", command=load_data, padx=5, pady=2)
#load_button.grid(row=0, column=2)

# Create labels to display selected user and group
selected_user_label = tk.Label(root, text="Selected User:")
selected_user_label.grid(row=5, column=0, padx=2, pady=2, sticky=tk.W)
selected_user_display = tk.Label(root, textvariable=selected_user)
selected_user_display.grid(row=5, column=1, padx=2, pady=2, sticky=tk.W)


# Create themed buttons using ttk
create_button = ttk.Button(user_operations_frame, text="Create User", command=create_user)
create_button.grid(row=0, column=0)

delete_button = ttk.Button(user_operations_frame, text="Delete Selected User", command=delete_selected_user)
delete_button.grid(row=0, column=2)

show_hash_button = ttk.Button(root, text="Show Hash", command=show_hash)
show_hash_button.grid(row=5, column=2, padx=5, pady=2, sticky=tk.W + tk.E)

#save_button = ttk.Button(data_operations_frame, text="Save Data", command=save_data)
#save_button.grid(row=0, column=0)

#load_button = ttk.Button(data_operations_frame, text="Load Data", command=load_data)
#load_button.grid(row=0, column=2)

close_button = ttk.Button(root, text="Close  ~Group Management~", command=close_app, padding=(200, 0))
close_button.grid(row=7, column=0, columnspan=3, padx=2, pady=5, sticky=tk.W + tk.E)


#####
# Function to update the admin passcode
def update_adminpasscode_window():
    update_passcode_window = tk.Toplevel(root)
    update_passcode_window.title("Update Admin Passcode")
    window_width = 460
    window_height = 250
    update_passcode_window.geometry(f"{window_width}x{window_height}")
    center_window(update_passcode_window, window_width, window_height)

    current_passcode_label = tk.Label(update_passcode_window, text="Enter current admin passcode:")
    current_passcode_label.pack(pady=10)
    current_passcode_entry = ttk.Entry(update_passcode_window, show="*")
    current_passcode_entry.pack(pady=5)

    new_passcode_label = tk.Label(update_passcode_window, text="Enter new admin passcode (min 6 numbers, max 12 numbers):")
    new_passcode_label.pack(pady=10)
    new_passcode_entry = ttk.Entry(update_passcode_window, show="*")
    new_passcode_entry.pack(pady=5)

    def update_adminpasscode():
        current_passcode = current_passcode_entry.get().strip()
        new_passcode = new_passcode_entry.get().strip()

        adminpasscode_path = 'adminpasscode'  # File path without extension
        if not os.path.exists(adminpasscode_path):
            tk.messagebox.showerror("File not found", "Admin passcode file not found.")
            return

        with open(adminpasscode_path, 'r') as file:
            lines = file.readlines()

        if not lines:
            tk.messagebox.showerror("File is empty", "Admin passcode file is empty.")
            return

        stored_passcode = lines[0].strip()
        current_passcode_hashed = hashlib.sha256(current_passcode.encode()).hexdigest()

        if current_passcode_hashed != stored_passcode:
            tk.messagebox.showerror("Incorrect passcode", "The passcode entered is incorrect.")
        elif len(new_passcode) < 6 or len(new_passcode) > 12 or not new_passcode.isdigit():
            tk.messagebox.showerror("Invalid passcode", "Please enter a passcode with 6 to 12 digits.")
        else:
            try:
                # Extract additional data from the existing file
                additional_data = "".join(lines[1:])

                # Delete the existing file
                os.remove(adminpasscode_path)

                # Create a new file with the updated content and additional data
                with open(adminpasscode_path, 'w') as file:
                    file.write(hashlib.sha256(new_passcode.encode()).hexdigest() + "\n")
                    file.write(additional_data)

                # Set the hidden attribute for the file (works on Windows systems)
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(adminpasscode_path, 2)  # 2 sets the file to hidden
                except AttributeError:  # For non-Windows systems
                    pass

                update_passcode_window.destroy()
                tk.messagebox.showinfo("Success", "Admin passcode updated successfully.")
            except Exception as e:
                print(f"An error occurred while updating the passcode file: {e}")



    update_button = ttk.Button(update_passcode_window, text="Update Passcode", command=update_adminpasscode)
    update_button.pack(pady=10)

    # Grab the focus to the update_passcode_window
    update_passcode_window.grab_set()

    # Withdraw the main window until the passcode is successfully updated
    root.withdraw()


# Create a button to update the passcode
update_passcode_button = ttk.Button(root, text="Change Passcode", command=update_adminpasscode_window)
update_passcode_button.grid(row=3, column=2, padx=5, pady=2, sticky=tk.W + tk.E)





# Start the GUI main loop
root.mainloop()
