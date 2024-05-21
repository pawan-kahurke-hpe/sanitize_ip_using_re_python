
# Log File Sanitization and De-sanitization Script

## Overview
This script provides functionality to sanitize sensitive data (such as IP addresses and hostnames) in log files by replacing them with placeholders. It also allows for the reverse operation, where placeholders in a sanitized file are replaced back with the original sensitive data.

## Prerequisites
- Python 3.x
- Basic understanding of regular expressions

## Script Explanation

### Importing Required Modules

```python
import re
```
The re module is imported to use regular expressions for identifying and replacing sensitive data patterns in the log file.
Defining Regex Patterns
python
Copy code
# Define regex patterns for IP addresses and hostnames
```python
IP_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
HOSTNAME_PATTERN = re.compile(r'\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b')
```
IP_PATTERN is a compiled regular expression that matches IPv4 addresses (e.g., 192.168.1.10).
HOSTNAME_PATTERN is a compiled regular expression that matches domain names (e.g., server.example.com).
Sanitization Function
```python
def sanitize(input_file, output_file):
    with open(input_file, 'r') as file:
        log_data = file.read()
    
    sanitized_data = log_data
    
    # Replace IP addresses
    sanitized_data = IP_PATTERN.sub('<IP_ADDRESS>', sanitized_data)
    
    # Replace hostnames
    sanitized_data = HOSTNAME_PATTERN.sub('<HOSTNAME>', sanitized_data)
    
    with open(output_file, 'w') as file:
        file.write(sanitized_data)
    
    print("Sanitization complete. Sanitized data written to:", output_file)
```
Function Definition: sanitize(input_file, output_file) - Takes two parameters: the path to the input log file and the path to the output sanitized file.
Reading the Input File: Opens and reads the content of the input log file.
Sanitizing Data: Replaces all IP addresses with the placeholder <IP_ADDRESS> and all hostnames with the placeholder <HOSTNAME>.
Writing the Output File: Writes the sanitized data to the output file.
Completion Message: Prints a message indicating that the sanitization is complete and specifies the output file path.
De-sanitization Function
python
Copy code
def desanitize(input_file, output_file, original_data_file):
    with open(original_data_file, 'r') as file:
        original_data = file.read()
    
    with open(input_file, 'r') as file:
        sanitized_data = file.read()
    
    desanitized_data = sanitized_data
    
    # Replace placeholders with original IP addresses and hostnames
    ip_matches = IP_PATTERN.findall(original_data)
    hostname_matches = HOSTNAME_PATTERN.findall(original_data)
    
    for ip in ip_matches:
        desanitized_data = desanitized_data.replace('<IP_ADDRESS>', ip, 1)
    
    for hostname in hostname_matches:
        desanitized_data = desanitized_data.replace('<HOSTNAME>', hostname, 1)
    
    with open(output_file, 'w') as file:
        file.write(desanitized_data)
    
    print("De-sanitization complete. Original data written to:", output_file)
Function Definition: desanitize(input_file, output_file, original_data_file) - Takes three parameters: the path to the sanitized log file, the path to the output de-sanitized file, and the path to the original log file.
Reading Original Data: Opens and reads the content of the original log file.
Reading Sanitized Data: Opens and reads the content of the sanitized log file.
Reverting Placeholders: Replaces the placeholders <IP_ADDRESS> and <HOSTNAME> in the sanitized data with the corresponding original IP addresses and hostnames extracted from the original data.
Writing the Output File: Writes the de-sanitized data to the output file.
Completion Message: Prints a message indicating that the de-sanitization is complete and specifies the output file path.
Example Usage
python
Copy code
# Input log file with sensitive data
input_log_file = 'logfile.txt'
# Output log file with sanitized data
sanitized_log_file = 'sanitized_logfile.txt'
# Output log file with de-sanitized data
desanitized_log_file = 'desanitized_logfile.txt'

# Perform sanitization
sanitize(input_log_file, sanitized_log_file)

# Perform de-sanitization (assuming we have the original data for this example)
desanitize(sanitized_log_file, desanitized_log_file, input_log_file)
File Paths: Specifies the paths for the input log file, the sanitized output log file, and the de-sanitized output log file.
Sanitization: Calls the sanitize function to sanitize the sensitive data in the input log file and save the result to the sanitized log file.
De-sanitization: Calls the desanitize function to revert the placeholders in the sanitized log file back to the original sensitive data and save the result to the de-sanitized log file.
Sample Log File (logfile.txt)
plaintext
Copy code
2024-05-20 10:15:30 Connection from 192.168.1.10 to server.example.com
2024-05-20 10:16:00 Connection from 172.16.0.5 to database.example.org
2024-05-20 10:17:45 User login from 10.0.0.2 to app.example.net
Running the Script
Create the Sample Log File: Save the above content to a file named logfile.txt.

Save the Python Script: Save the provided Python script to a file named sanitize_logs.py.

Execute the Script: Run the script using Python:

bash
Copy code
python sanitize_logs.py
Check the Output Files:

Sanitized File (sanitized_logfile.txt): This file will contain the sanitized log data with IP addresses and hostnames replaced by placeholders.
De-sanitized File (desanitized_logfile.txt): This file will contain the original log data restored from the sanitized file.
