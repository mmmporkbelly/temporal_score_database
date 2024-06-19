"""
Features:
- Validates JSON files in a specified directory for JSON formatting correctness.
- Checks for Unicode decoding errors, which are common in data files with diverse origins.
- Provides suggestions for correcting identified errors.
"""

import os
import json


# Function to validate JSON files for correct formatting and encoding
def parse_json_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                    print(f"Successfully parsed {file_path}")
                    # Should eventually add something to remove all non UTF-8 values here

                except json.JSONDecodeError as e:
                    print(f"JSON formatting error in {file_path}: {e}")
                except UnicodeDecodeError as e:
                    print(f"Unicode decoding error in {file_path}: {e}")
                    print("Suggested steps to correct:")
                    print("1. Ensure the file is encoded in UTF-8.")
                    print("2. If the file contains non-UTF-8 characters, try opening it with the correct encoding.")
                    print("3. Use a text editor to manually inspect and correct any invalid characters.")