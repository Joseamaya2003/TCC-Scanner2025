import os
import html
from datetime import datetime

# Define the folder path directly using the absolute path provided by the user.
# This ensures the script looks for the folder at the exact location,
# regardless of where the Python script itself is executed.
folder_path = "./"

def extract_lynis_metadata(file_content):
    """
    Extracts high-level metadata from a Lynis report.

    Returns:
        dict: Dictionary with metadata fields (tests performed, plugin info, hardening index, etc.)
    """
    metadata = {
        "Tests Performed": "Not found",
        "Plugins Active": "Not found",
        "Total Plugins": "Not found",
        "Hardening Index": "Not found",
        "Hardening Strength": "Not found"
    }

    for line in file_content.splitlines():
        lower_line = line.lower()
        if "tests performed" in lower_line:
            metadata["Tests Performed"] = line.split(":", 1)[-1].strip()
        elif "plugins active" in lower_line:
            metadata["Plugins Active"] = line.split(":", 1)[-1].strip()
        elif "plugins total" in lower_line or "total plugins" in lower_line:
            metadata["Total Plugins"] = line.split(":", 1)[-1].strip()
        elif "hardening index" in lower_line:
            metadata["Hardening Index"] = line.split(":", 1)[-1].strip()
        elif "hardening strength" in lower_line:
            metadata["Hardening Strength"] = line.split(":", 1)[-1].strip()

    return metadata


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
    # This is where you would parse 'file_content' to populate the 'findings' lists.
    # For demonstration, we'll use simple string checks and add the filename for context.

    # Example: SSH findings
    # Enhanced SSH findings
    ssh_lines = [line for line in file_content.splitlines() if "ssh" in line.lower()]
    if ssh_lines:
        categorized_findings["SSH"]["findings"].append(f"[{filename}] Found {len(ssh_lines)} SSH-related entries.")

    for line in ssh_lines:
        lower_line = line.lower()
        if "openssh" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] OpenSSH detected: {line.strip()}")
        if "permitrootlogin no" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] Root login disabled via SSH.")
        elif "permitrootlogin yes" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] WARNING: Root login enabled via SSH.")
        if "passwordauthentication no" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] Password authentication disabled (suggests pubkey-only auth).")
        if "ssh configuration" in lower_line or "sshd_config" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] SSH configuration mentioned: {line.strip()}")
        if "running ssh daemon" in lower_line or "ssh service is running" in lower_line:
            categorized_findings["SSH"]["findings"].append(f"[{filename}] SSH service is running.")

       # Enhanced Firewall findings
    firewall_lines = [line for line in file_content.splitlines() if any(
        kw in line.lower() for kw in ["firewall", "ufw", "iptables", "firewalld", "nftables"]
    )]

    if firewall_lines:
        categorized_findings["Firewall"]["findings"].append(f"[{filename}] Found {len(firewall_lines)} firewall-related entries.")

    for line in firewall_lines:
        lower_line = line.lower()
        if "status: active" in lower_line or "firewall is enabled" in lower_line or "ufw active" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] Firewall appears active: {line.strip()}")
        elif "inactive" in lower_line or "not running" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] WARNING: Firewall appears inactive: {line.strip()}")
        if "iptables" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] iptables referenced: {line.strip()}")
        if "firewalld" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] firewalld referenced: {line.strip()}")
        if "nftables" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] nftables referenced: {line.strip()}")
        if "configuration file" in lower_line:
            categorized_findings["Firewall"]["findings"].append(f"[{filename}] Firewall configuration file mentioned: {line.strip()}")

    # Example: Patch Status (very basic, would need more sophisticated parsing)
     # Enhanced Patch Status detection
    patch_lines = [line for line in file_content.splitlines() if any(keyword in line.lower() for keyword in ["patch", "update", "package", "security"])]

    for line in patch_lines:
        lower_line = line.lower()
        if "no updates available" in lower_line or "system is up-to-date" in lower_line or "up to date" in lower_line:
            categorized_findings["Patch Status"]["findings"].append(f"[{filename}] OS appears up to date: {line.strip()}")
        elif "missing security update" in lower_line or "outdated" in lower_line or "pending updates" in lower_line or "available updates" in lower_line:
            categorized_findings["Patch Status"]["findings"].append(f"[{filename}] WARNING: Possible missing or outdated updates: {line.strip()}")
        elif "security patch" in lower_line:
            categorized_findings["Patch Status"]["findings"].append(f"[{filename}] Security patch information found: {line.strip()}")
        elif "apt" in lower_line or "yum" in lower_line or "package manager" in lower_line:
            categorized_findings["Patch Status"]["findings"].append(f"[{filename}] Package manager referenced: {line.strip()}")

    # Enhanced Accounts/Passwords detection
    acct_lines = [line for line in file_content.splitlines() if any(
        kw in line.lower() for kw in ["password", "account", "user", "auth", "login"]
    )]

    for line in acct_lines:
        lower_line = line.lower()
        if "default user" in lower_line and "not found" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] No common default users found.")
        elif "default user" in lower_line or "default account" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] WARNING: Default user/account mentioned: {line.strip()}")
        if "empty password" in lower_line or "accounts without password" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] WARNING: Empty or missing password detected: {line.strip()}")
        if "password complexity" in lower_line or "password strength" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] Password policy mentioned: {line.strip()}")
        if "password aging" in lower_line or "password expiry" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] Password aging policy found: {line.strip()}")
        if "inactive user" in lower_line or "inactive account" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] Inactive account/user check mentioned: {line.strip()}")
        if "root account" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] Root account status: {line.strip()}")
        if "authentication method" in lower_line or "pam" in lower_line or "ldap" in lower_line:
            categorized_findings["Accounts/Passwords"]["findings"].append(f"[{filename}] Authentication method referenced: {line.strip()}")

        # Enhanced Filesystem findings
    fs_lines = [line for line in file_content.splitlines() if any(
        kw in line.lower() for kw in ["/etc/passwd", "/etc/shadow", "file permissions", "world-writable", "sticky bit", "/tmp", "/var", "/home"]
    )]

    if fs_lines:
        categorized_findings["Filesystem"]["findings"].append(f"[{filename}] Found {len(fs_lines)} filesystem-related entries.")

    for line in fs_lines:
        lower_line = line.lower()
        if "world-writable" in lower_line:
            categorized_findings["Filesystem"]["findings"].append(f"[{filename}] WARNING: World-writable file(s) found: {line.strip()}")
        if "/etc/passwd" in lower_line and "permission" in lower_line:
            categorized_findings["Filesystem"]["findings"].append(f"[{filename}] /etc/passwd permissions mentioned: {line.strip()}")
        if "/etc/shadow" in lower_line and "permission" in lower_line:
            categorized_findings["Filesystem"]["findings"].append(f"[{filename}] /etc/shadow permissions mentioned: {line.strip()}")
        if "/tmp" in lower_line and "sticky bit" not in lower_line:
            categorized_findings["Filesystem"]["findings"].append(f"[{filename}] WARNING: /tmp directory may be missing sticky bit: {line.strip()}")
        if "sticky bit" in lower_line:
            categorized_findings["Filesystem"]["findings"].append(f"[{filename}] Sticky bit setting found: {line.strip()}")

       # Enhanced Services findings
    svc_lines = [line for line in file_content.splitlines() if any(
        kw in line.lower() for kw in ["service", "daemon", "systemctl", "init.d", "rc.d"]
    )]

    if svc_lines:
        categorized_findings["Services"]["findings"].append(f"[{filename}] Found {len(svc_lines)} service-related entries.")

    for line in svc_lines:
        lower_line = line.lower()
        if "unused" in lower_line and "disabled" in lower_line:
            categorized_findings["Services"]["findings"].append(f"[{filename}] Unused service disabled: {line.strip()}")
        elif "unused" in lower_line and "enabled" in lower_line:
            categorized_findings["Services"]["findings"].append(f"[{filename}] WARNING: Unused service enabled: {line.strip()}")
        elif "active (running)" in lower_line or "enabled" in lower_line:
            categorized_findings["Services"]["findings"].append(f"[{filename}] Service enabled or running: {line.strip()}")


        # Enhanced Logging/Auditing findings
    log_lines = [line for line in file_content.splitlines() if any(
        kw in line.lower() for kw in ["logging", "auditd", "syslog", "journald", "rsyslog"]
    )]

    if log_lines:
        categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] Found {len(log_lines)} logging-related entries.")

    for line in log_lines:
        lower_line = line.lower()
        if "auditd" in lower_line and "running" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] auditd is running: {line.strip()}")
        elif "auditd" in lower_line and "not running" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] WARNING: auditd not running: {line.strip()}")
        if "syslog" in lower_line and "running" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] syslog is running: {line.strip()}")
        elif "syslog" in lower_line and "not running" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] WARNING: syslog not running: {line.strip()}")
        if "journald" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] journald mentioned: {line.strip()}")
        if "rsyslog" in lower_line:
            categorized_findings["Logging/Auditing"]["findings"].append(f"[{filename}] rsyslog mentioned: {line.strip()}")


    # Add a default message if no specific findings were extracted for a category
    for category_key, category_value in categorized_findings.items():
        if not category_value["findings"]:
            category_value["findings"].append(f"No specific findings extracted for {category_key} from {filename}. (Parsing logic needed or no relevant data found)")

    # --- END: Implement your Lynis report parsing logic here ---

    return categorized_findings

def folder_to_html_report(folder_path):
    """
    Reads all files from a specified folder and generates an HTML report
    displaying categorized findings and raw file contents.

    Args:
        folder_path (str): The path to the folder containing the files.

    Returns:
        str: An HTML formatted string representing the report, or None if an error occurs.
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
        initial_categories = categorize_lynis_data("", "initial_template")
        for category_key in initial_categories:
            all_categorized_data[category_key] = {
                "description": initial_categories[category_key]["description"],
                "findings": []
            }

        # Get list of files in the folder
        file_list = [
            os.path.join(absolute_folder_path, f)
            for f in os.listdir(absolute_folder_path)
            if os.path.isfile(os.path.join(absolute_folder_path, f))
        ]

        if not file_list:
            print(f"No files found in '{absolute_folder_path}'.")
            return None

        # Find the most recently modified file
        latest_file_path = max(file_list, key=os.path.getmtime)
        latest_filename = os.path.basename(latest_file_path)


        try:
            with open(latest_file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract high-level Lynis metadata (only once, for the latest or main log)
            lynis_metadata = extract_lynis_metadata(content)


            # Store raw file data
            all_file_raw_data.append({
                "filename": latest_filename,
                "content": content
            })
            
            # Categorize the content
            current_file_categorized = categorize_lynis_data(content, latest_filename)

            # Aggregate findings
            for category_key, category_value in current_file_categorized.items():
                all_categorized_data[category_key]["findings"].extend(category_value["findings"])

        except Exception as e:
            print(f"Error reading latest file '{latest_filename}': {e}")
            return None


        # --- Start HTML Generation ---
        report_title = "Lynis Scan Security Report"
        generation_timestamp = datetime.now().isoformat()

        html_parts = []
        html_parts.append(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(report_title)}</title>
    <style>
        body {{
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f7f6;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 20px auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            border-bottom: 2px solid #eee;
            padding-bottom: 15px;
        }}
        h2 {{
            color: #34495e;
            font-size: 1.8em;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #16a085;
            font-size: 1.3em;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .metadata p {{
            font-size: 0.95em;
            color: #555;
            margin-bottom: 5px;
        }}
        .metadata ul {{
            list-style: none;
            padding-left: 0;
            }}
        .metadata ul li {{
            margin-bottom: 6px;
            font-size: 1em;
        }}

        .category-section {{
            background-color: #f9f9f9;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .category-section ul {{
            list-style: disc;
            padding-left: 25px;
            margin-top: 10px;
        }}
        .category-section li {{
            margin-bottom: 8px;
            color: #444;
        }}
        .category-section li.warning {{
            color: #e67e22;
            font-weight: bold;
        }}
        .category-section li.error {{
            color: #c0392b;
            font-weight: bold;
        }}
        .raw-file-entry {{
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
            padding: 15px;
            background-color: #fdfdfd;
        }}
        .raw-file-name {{
            font-size: 1.1em;
            color: #0056b3;
            margin-bottom: 8px;
            font-weight: bold;
        }}
        .raw-file-content {{
            background-color: #eee;
            padding: 10px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.85em;
            color: #555;
            max-height: 250px; /* Limit height for long content */
            overflow-y: auto; /* Add scrollbar if content exceeds max-height */
        }}
        .no-findings {{
            font-style: italic;
            color: #777;
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #777;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{html.escape(report_title)}</h1>

        <div class="metadata">
            <h2>Report Metadata</h2>
            <p><strong>Source Folder:</strong> <code>{html.escape(folder_path)}</code></p>
            <p><strong>Absolute Path:</strong> <code>{html.escape(absolute_folder_path)}</code></p>
            <p><strong>Generated On:</strong> {html.escape(generation_timestamp)}</p>
        </div>

                <div class="metadata">
            <h3>Lynis Scan Summary</h3>
            <ul>
                <li><strong>Tests Performed:</strong> {html.escape(lynis_metadata.get("Tests Performed", "Not found"))}</li>
                <li><strong>Plugins Active:</strong> {html.escape(lynis_metadata.get("Plugins Active", "Not found"))}</li>
                <li><strong>Total Plugins:</strong> {html.escape(lynis_metadata.get("Total Plugins", "Not found"))}</li>
                <li><strong>Hardening Index:</strong> {html.escape(lynis_metadata.get("Hardening Index", "Not found"))}</li>
                <li><strong>Hardening Strength:</strong> {html.escape(lynis_metadata.get("Hardening Strength", "Not found"))}</li>
            </ul>
        </div>


        <h2>Categorized Security Findings</h2>
""")

        # Add categorized findings to HTML
        for category_key, category_data in all_categorized_data.items():
            html_parts.append(f"""
        <details class="category-section">
            <summary><strong>🔐 {html.escape(category_key)}</strong> - {html.escape(category_data["description"])} </summary>
            <ul>
""")
            if category_data["findings"]:
                for finding in category_data["findings"]:
                    # Basic classification for styling (can be improved with more robust parsing)
                    li_class = ""
                    if "WARNING:" in finding.upper():
                        li_class = "warning"
                    elif "ERROR:" in finding.upper():
                        li_class = "error"
                    html_parts.append(f'<li class="{li_class}">{html.escape(finding)}</li>')
            else:
                html_parts.append('<li class="no-findings">No specific findings for this category.</li>')

            html_parts.append("""
            </ul>
        </details>
""")

        # Add raw file contents to HTML
        html_parts.append("""
        <h2>Raw File Contents (For Reference)</h2>
""")
        if all_file_raw_data:
            for file_entry in all_file_raw_data:
                html_parts.append(f"""
        <div class="raw-file-entry">
            <div class="raw-file-name">File: {html.escape(file_entry["filename"])}</div>
            <pre class="raw-file-content">{html.escape(file_entry["content"])}</pre>
        </div>
""")
        else:
            html_parts.append('<p class="no-findings">No readable files found in the source folder.</p>')

        html_parts.append("""
        <footer>
            <p>Generated by Python Script on {html.escape(generation_timestamp)}</p>
        </footer>
    </div>
</body>
</html>
""")
        return "".join(html_parts)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    # Call the function to process the folder
    html_result = folder_to_html_report(folder_path)

    if html_result:
        # Automatically save the HTML output to a file
        output_filename = "lynis_security_report.html" # HTML output filename
        try:
            with open(output_filename, 'w', encoding='utf-8') as outfile:
                outfile.write(html_result)
            print(f"\nHTML report successfully generated and saved to '{output_filename}'")
            print(f"You can open '{output_filename}' in your web browser to view the report.")
        except Exception as e:
            print(f"Error saving HTML report to file: {e}")
    else:
        print("Failed to generate HTML report.")
