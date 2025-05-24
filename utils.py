import json
import os

def save_to_json(original, encrypted, password, filename='messages.json'):
    entry = {
        "original": original,
        "encrypted": encrypted,
        "password": password
    }
    data = []
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as file:  # Added encoding for consistency
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                pass  # Safely handle corrupted JSON files
    data.append(entry)
    with open(filename, 'w', encoding='utf-8') as file:  # Added encoding for consistency
        json.dump(data, file, indent=4)

def load_all_messages(filename='messages.json'):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as file:  # Added encoding for consistency
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return []  # Return an empty list if JSON is corrupted
    return []
