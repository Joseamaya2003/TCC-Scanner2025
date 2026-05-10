import os
import json
from datetime import datetime

# Define the folder path directly using the absolute path provided by the user.
# This ensures the script looks for the folder at the exact location,
# regardless of where the Python script itself is executed.
folder_path = "/Users/jamaya/Downloads/TCCapp-main/TCCApp/scan/lynis-report"

def categorize_lynis_data(file_content, filename=""):
    """
    Parses the content of a Lynis report file and categorizes the findings.
    This function is a placeholder. You need to implement the actual parsing logic
    based on the structure and content of your Lynis report files.

    Args:
        file_content (str): The raw content of a Lynis report file.
        filename (str): The name of the file being processed (for context in findings).

    Returns:
        dict: A dictionary with categorized findings.
    """
    categorized_findings = {
        "SSH": {
            "description": "SSH - Root login disabled, SSH version, pubkey-only auth",
            "findings": []
        },
        "Patch Status": {
            "description": "Patch Status OS up to date, no pending security patches",
            "findings": []
        },
        "Firewall": {
            "description": "Firewall UFW/iptables enabled and active",
            "findings": []
        },
        "Accounts/Passwords": {
            "description": "Accounts/Passwords - No default users, password policy strength",
            "findings": []
        },
        "Filesystem": {
            "description": "Filesystem - World-writable files, permissions on /etc/passwd",
            "findings": []
        },
        "Services": {
            "description": "Services - Unused services disabled",
            "findings": []
        },
        "Logging/Auditing": {
            "description": "Logging/Auditing - Syslog or auditd enabled and running",
            "findings": []
        }
    }

    # --- START: Implement your Lynis report parsing logic here ---
    # Example placeholder:
    # You would typically parse 'file_content' line by line or section by section
    # to extract relevant information and add it to the 'findings' list for each category.

    if "SSH" in file_content.upper(): # Very basic example, replace with robust parsing
        categorized_findings["SSH"]["findings"].append(f"Found SSH related text in {filename}. (Needs detailed parsing)")
    if "FIREWALL" in file_content.upper() or "UFW" in file_content.upper():
        categorized_findings["Firewall"]["findings"].append(f"Found firewall related text in {filename}. (Needs detailed parsing)")
    # Add more sophisticated parsing logic for each category here.
    # You might use regex, string splitting, or a dedicated parsing library
    # depending on the complexity of your Lynis report format.

    # If no specific findings are extracted, you can add a default message
    for category_key, category_value in categorized_findings.items():
        if not category_value["findings"]:
            category_value["findings"].append(f"No specific findings extracted for {category_key} from {filename}. (Parsing logic needed)")

    # --- END: Implement your Lynis report parsing logic here ---

    return categorized_findings

def folder_to_json(folder_path):
    """
    Reads all files from a specified folder and formats their content into a JSON string.
    The output JSON now includes report metadata and categorized findings for better readability.

    Args:
        folder_path (str): The path to the folder containing the files.

    Returns:
        str: A JSON formatted string representing the report, or None if an error occurs.
    """
    # Get the absolute path to ensure correct resolution
    absolute_folder_path = os.path.abspath(folder_path)

    # Check if the provided path is a valid directory
    if not os.path.isdir(absolute_folder_path):
        print(f"Error: The path '{absolute_folder_path}' is not a valid directory.")
        return None

    all_file_raw_data = []
    all_categorized_data = {} # To aggregate findings from all files

    try:
        # Initialize categorized_findings structure to ensure all categories are present
        # even if no files contribute to them.
        initial_categories = categorize_lynis_data("", "initial_template")
        for category_key in initial_categories:
            all_categorized_data[category_key] = {
                "description": initial_categories[category_key]["description"],
                "findings": []
            }

        # Iterate over all items in the specified folder
        for filename in os.listdir(absolute_folder_path):
            file_path = os.path.join(absolute_folder_path, filename)

            # Check if the current item is a file (and not a subdirectory)
            if os.path.isfile(file_path):
                try:
                    # Read the content of the file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Store raw file data
                    all_file_raw_data.append({
                        "filename": filename,
                        "content": content
                    })

                    # Categorize the content of the current file
                    current_file_categorized = categorize_lynis_data(content, filename)

                    # Aggregate findings from the current file into the overall categorized data
                    for category_key, category_value in current_file_categorized.items():
                        all_categorized_data[category_key]["findings"].extend(category_value["findings"])

                except Exception as e:
                    print(f"Warning: Could not read file '{filename}'. Error: {e}")
            else:
                print(f"Skipping '{filename}' as it is not a regular file.")

        # Construct the full report dictionary with metadata
        report_data = {
            "report_metadata": {
                "report_name": "Lynis Scan Report (Categorized)",
                "source_folder": folder_path,
                "absolute_source_path": absolute_folder_path,
                "generation_timestamp": datetime.now().isoformat()
            },
            "categorized_findings": all_categorized_data,
            "raw_files_content": all_file_raw_data # Keep raw content for reference
        }

        # Convert the dictionary to a JSON formatted string
        # The 'indent=4' makes the JSON output human-readable
        json_output = json.dumps(report_data, indent=4)
        return json_output

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    # Call the function to process the folder
    json_result = folder_to_json(folder_path)

    if json_result:
        print("\n--- JSON Output ---")
        print(json_result)
        print("\n--- End of JSON Output ---")

        # Automatically save the JSON output to a file
        output_filename = "lynis_categorized_report.json" # More descriptive default filename
        try:
            with open(output_filename, 'w', encoding='utf-8') as outfile:
                outfile.write(json_result)
            print(f"JSON output successfully saved to '{output_filename}'")
        except Exception as e:
            print(f"Error saving JSON to file: {e}")
    else:
        print("Failed to generate JSON output.")
