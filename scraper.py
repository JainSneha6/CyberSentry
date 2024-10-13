import requests
from bs4 import BeautifulSoup
import re

url = 'http://localhost:5000/requests'

response = requests.get(url)

if response.status_code == 200:
    soup = BeautifulSoup(response.content, 'html.parser')
    requests_list = soup.find_all('li')

    # SQL Injection patterns
    sql_injection_patterns = [
        r"\s*OR\s*1=1",                          # Basic OR condition
        r"'\s*--",                                # Comment after a quote
        r"'\s*#",                                  # Comment after a quote
        r"' UNION SELECT",                        # Union select statement
        r"DROP\s+TABLE\s+\w+",                   # Drop table
        r"SELECT\s+\*?\s+FROM\s+\w+",            # Select all from a table
        r"SELECT\s+\w+\s+FROM\s+\w+",            # Select specific columns
        r"AND\s+\(SELECT\s+\d+\s+FROM",         # Subquery in AND
        r"INSERT\s+INTO\s+\w+\s+VALUES\s*\(",    # Insert statement
        r"EXEC\s+sp_.*",                          # Execute stored procedure
        r"DECLARE\s+\w+\s+AS",                    # Variable declaration
        r"CREATE\s+TABLE\s+\w+",                 # Create table
        r"ALTER\s+TABLE\s+\w+\s+ADD",            # Alter table
        r"SHOW\s+TABLES",                         # Show tables
        r"SET\s+@@session.sql_mode",              # SQL mode manipulation
        r"TRUNCATE\s+TABLE\s+\w+",               # Truncate table
        r"SELECT\s+FROM\s+INFORMATION_SCHEMA.*", # Information schema access
    ]

    def is_sql_injection_possible(parameter_value):
        for pattern in sql_injection_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    vulnerabilities_found = []
    # Check for SQL Injection
    for req in requests_list:
        request_text = req.get_text()
        if 'with args:' in request_text:
            args_text = request_text.split('with args: ')[1].strip()
            cleaned_request_text = args_text.replace('ImmutableMultiDict(', '').replace(')', '').strip()
            cleaned_request_text = cleaned_request_text.replace("'", "").replace("[", "").replace("]", "")
            param_list = [param.strip().strip('"') for param in cleaned_request_text.split(',') if param.strip()]
            param_list = [param for param in param_list if 'input' not in param]

            for param_value in param_list:
                if param_value:
                    if is_sql_injection_possible(param_value):
                        vulnerabilities_found.append(f"Potential SQL Injection in: {request_text.strip()}")
                        break

    # Print SQL Injection results
    if vulnerabilities_found:
        print("Potential SQL Injection Vulnerabilities Found:")
        for vulnerability in vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No SQL injection vulnerabilities found.")

    # XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",                   # Script tags
        r"javascript:.*",                              # JavaScript URLs
        r"on\w*=\s*['\"].*?['\"]",                     # Event handler attributes
        r"<img.*?src=['\"]*.*?['\"].*?onerror=.*?>",  # Image error handling
        r"<iframe.*?>.*?</iframe>",                    # Iframes
        r"<a.*?href=['\"]*javascript:.*?['\"].*?>",   # Links with JavaScript
        r"<meta.*?http-equiv=['\"]refresh['\"].*?>",  # Meta refresh
        r"<link.*?href=['\"]*.*?['\"].*?rel=['\"]stylesheet['\"]",  # Stylesheet links
        r"<body.*?onload=.*?>",                       # Body onload
        r"<svg.*?onload=.*?>",                        # SVG onload
        r"document\.cookie",                          # Cookie manipulation
        r"eval\s*\(.*?\)",                            # Eval function
        r"setTimeout\s*\(.*?\)",                      # Timeout function
        r"setInterval\s*\(.*?\)",                     # Interval function
        r"onerror\s*=\s*['\"].*?['\"]",                # General error handling
        r"<style.*?>.*?</style>",                      # Style injection
    ]

    def is_xss_possible(parameter_value):
        for pattern in xss_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    xss_vulnerabilities_found = []
    for req in requests_list:
        request_text = req.get_text()
        if 'example?input=' in request_text:
            args_text = request_text.split('example?input=')[1].strip()
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
            param_list = [param for param in param_list if 'input' not in param]

            for param_value in param_list:
                if param_value:
                    if is_xss_possible(param_value):
                        xss_vulnerabilities_found.append(f"Potential XSS in: {request_text.strip()}")
                        break

    # Print XSS results
    if xss_vulnerabilities_found:
        print("Potential XSS Vulnerabilities Found:")
        for vulnerability in xss_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No XSS vulnerabilities found.")

    # Command Injection patterns for Windows
    command_injection_patterns = [
        r"(?:^|&|\|)(?:cmd|powershell|start|echo|dir|type|del|copy|move|mkdir|rmdir)(?:\s+[^&|]*)?$",  # General command execution
        r"^cmd\s+/c\s+.*$",                     # Executing cmd commands
        r"^start\s+.*$",                        # Starting a new command prompt window
        r"^powershell\s+.*$",                  # PowerShell commands
        r"^echo\s+.*$",                        # Echoing a command output
        r"^dir\s+.*$",                          # Directory listing
        r"^type\s+.*$",                         # Reading a file
        r"^del\s+.*$",                          # Deleting a file
        r"^copy\s+.*$",                         # Copying a file
        r"^move\s+.*$",                         # Moving a file
        r"^mkdir\s+.*$",                        # Creating a directory
        r"^rmdir\s+.*$",                        # Removing a directory
    ]

    def is_command_injection_possible(parameter_value):
        for pattern in command_injection_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    command_injection_vulnerabilities_found = []
    # Check for Command Injection
    for req in requests_list:
        request_text = req.get_text()
        if 'example?input=' in request_text:
            args_text = request_text.split('example?input=')[1].strip()
            print(args_text)
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
            param_list = [param for param in param_list if 'input' not in param]

            for param_value in param_list:
                print(param_value)
                if param_value:
                    if is_command_injection_possible(param_value):
                        command_injection_vulnerabilities_found.append(f"Potential Command Injection in: {request_text.strip()}")
                        break

    # Print Command Injection results
    if command_injection_vulnerabilities_found:
        print("Potential Command Injection Vulnerabilities Found:")
        for vulnerability in command_injection_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No Command Injection vulnerabilities found.")

else:
    print(f"Failed to retrieve the requests page: {response.status_code}")
