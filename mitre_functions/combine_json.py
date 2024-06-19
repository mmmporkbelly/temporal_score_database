import os
import json
import logging
from tqdm import tqdm


# Recursively find all JSON files in the directory and subdirectories.
def find_json_files(directory):
    json_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files


# Combine all json files by year
def combine_json_files_by_year(root_path, output_folder):

    # Check if the output folder exists, create if not
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        logging.info(f"Created output folder at {output_folder}")

    # Process each year folder
    for year in sorted(os.listdir(root_path)):
        year_path = os.path.join(root_path, year)
        if os.path.isdir(year_path):  # Ensure it's a directory
            combined_data = []
            json_files = find_json_files(year_path)

            if not json_files:
                logging.warning(f"No JSON files found in {year_path}")
                continue

            for file_path in tqdm(json_files, desc=f"Processing {year} JSON files"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        combined_data.append(data)
                    logging.info(f"Successfully added {file_path}")
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to decode JSON from {file_path}: {e}")
                except Exception as e:
                    logging.error(f"Error processing file {file_path}: {e}")

            # Save the combined data to a new JSON file for the year
            output_file = os.path.join(output_folder, f"{year}.json")
            try:
                with open(output_file, 'w', encoding='utf-8') as f_out:
                    json.dump(combined_data, f_out, ensure_ascii=False, indent=4)
                logging.info(f"Combined data written to {output_file}")
            except Exception as e:
                logging.error(f"Failed to write combined data to {output_file}: {e}")
