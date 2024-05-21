import re

# Define regex patterns for IP addresses and hostnames
IP_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
HOSTNAME_PATTERN = re.compile(r'\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b')

def sanitize(input_file, output_file):
    with open(input_file, 'r') as file:
        log_data = file.read()
    
    sanitized_data = log_data
    
    # Replace IP addresses
    sanitized_data = IP_PATTERN.sub('1.2.3.4', sanitized_data)
    
    # Replace hostnames
    sanitized_data = HOSTNAME_PATTERN.sub('map.local.com', sanitized_data)
    
    with open(output_file, 'w') as file:
        file.write(sanitized_data)
    
    print("Sanitization complete. Sanitized data written to:", output_file)

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

# Example usage
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
