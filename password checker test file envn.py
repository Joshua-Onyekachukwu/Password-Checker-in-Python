import tkinter as tk
from tkinter import messagebox
import hashlib
import requests
from bs4 import BeautifulSoup
from yagmail import password

# Function to generate the SHA-256 hash and return it
def generate_hash():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    # Generate SHA-256 hash
    sha_hash = hashlib.sha256(password.encode()).hexdigest()

    # Display the hash in the GUI
    output_text.set(sha_hash)

    # Print and show the hash
    print(sha_hash)
    messagebox.showinfo("Password Hash", "Your password has been hashed successfully.")

    # Save the hash to a file
    save_hash_to_file(sha_hash)

    return sha_hash


# Function to save the generated hash to a file
def save_hash_to_file(hash_value, filename="hash.txt"):
    with open(filename, "w") as file:
        file.write(hash_value)
    print(f"Hash saved to {filename}")


# Function to load the hash from a file
def load_hash_from_file(filename="hash.txt"):
    try:
        with open(filename, "r") as file:
            hash_value = file.read().strip()  # Strip to remove any extra spaces or newlines
        print(f"Hash loaded from {filename}: {hash_value}")
        return hash_value
    except FileNotFoundError:
        print("Hash file not found!")
        return None


# Function to modify the hash (for example, adding a string to the hash)
def modify_hash(original_hash):
    # For example, we just append a string to the hash
    modified_hash = original_hash + "modified"
    return modified_hash


# Function to save the modified hash to a new file
def save_modified_hash_to_file(modified_hash, filename="modified_hash.txt"):
    with open(filename, "w") as file:
        file.write(modified_hash)
    print(f"Modified hash saved to {filename}")


# GUI setup
root = tk.Tk()
root.title("SHA-256 Password Hash Generator")

# Input field for password
tk.Label(root, text="Enter Password:").pack(pady=5)
entry = tk.Entry(root, show="*", width=40)
entry.pack(pady=5)

# Button to trigger hash generation
tk.Button(root, text="Generate SHA-256 Hash", command=generate_hash).pack(pady=10)

# Output field for displaying hash
output_text = tk.StringVar()
tk.Entry(root, textvariable=output_text, width=60, state='readonly').pack(pady=5)

# Run the GUI
root.mainloop()

# Example Usage:
# After generating and saving the hash, you can load it, modify it, and save the new hash
hash_value = load_hash_from_file("hash.txt")
if hash_value:
    modified_hash = modify_hash(hash_value)
    save_modified_hash_to_file(modified_hash, "modified_hash.txt")


# Accessing the first 5 characters of the hash (from the file if needed)
if hash_value:
    first_5_chars = hash_value[:5]  # Extract the first 5 characters of the hash
    print(f"The first 5 characters of the hash are: {first_5_chars}")


query_char = first_5_chars

# GUI setup
root = tk.Tk()
root.title("SHA-256 Password Generator")

# Input field
tk.Label(root, text="Enter Password:").pack(pady=5)
entry = tk.Entry(root, show="*", width=40)
entry.pack(pady=5)

# Button to generate hash
tk.Button(root, text="Generate SHA-256 Hash", command=generate_hash).pack(pady=10)

# Output field
output_text = tk.StringVar()
tk.Entry(root, textvariable=output_text, width=60, state='readonly').pack(pady=5)

# Run the GUI
root.mainloop()


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Something went wrong: {response.status_code}, check the API and Try Again')
    return response.text
def pwned_api_check(password):
    # check password if it exist in API response
    pass

request_api_data('234')
