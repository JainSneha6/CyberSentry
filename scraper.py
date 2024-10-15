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
        r"\s*OR\s*1=1",                          
        r"\s*--",                                
        r"\s*#",                                  
        r"UNION SELECT",                        
        r"DROP\s+TABLE\s+\w+",                   
        r"SELECT\s+\*?\s+FROM\s+\w+",            
        r"SELECT\s+\w+\s+FROM\s+\w+",            
        r"AND\s+\(SELECT\s+\d+\s+FROM",         
        r"INSERT\s+INTO\s+\w+\s+VALUES\s*\(",    
        r"EXEC\s+sp_.*",                          
        r"DECLARE\s+\w+\s+AS",                    
        r"CREATE\s+TABLE\s+\w+",                 
        r"ALTER\s+TABLE\s+\w+\s+ADD",            
        r"SHOW\s+TABLES",                         
        r"SET\s+@@session.sql_mode",              
        r"TRUNCATE\s+TABLE\s+\w+",               
        r"SELECT\s+FROM\s+INFORMATION_SCHEMA.*", 
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
        r"<script.*?>.*?</script>",                   
        r"javascript:.*",                              
        r"on\w*=\s*['\"].*?['\"]",                     
        r"<img.*?src=['\"]*.*?['\"].*?onerror=.*?>",  
        r"<iframe.*?>.*?</iframe>",                    
        r"<a.*?href=['\"]*javascript:.*?['\"].*?>",   
        r"<meta.*?http-equiv=['\"]refresh['\"].*?>",  
        r"<link.*?href=['\"]*.*?['\"].*?rel=['\"]stylesheet['\"]",  
        r"<body.*?onload=.*?>",                       
        r"<svg.*?onload=.*?>",                        
        r"document\.cookie",                          
        r"eval\s*\(.*?\)",                            
        r"setTimeout\s*\(.*?\)",                      
        r"setInterval\s*\(.*?\)",                     
        r"onerror\s*=\s*['\"].*?['\"]",                
        r"<style.*?>.*?</style>",                     
    ]

    def is_xss_possible(parameter_value):
        for pattern in xss_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    xss_vulnerabilities_found = []
    for req in requests_list:
        request_text = req.get_text()
        if 'xss_vul?input=' in request_text:
            args_text = request_text.split('xss_vul?input=')[1].strip()
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
        r"(?:^|&|\|)(?:cmd|powershell|start|echo|dir|type|del|copy|move|mkdir|rmdir)(?:\s+[^&|]*)?$",  
        r"^cmd",                     
        r"^start\s*.*$",                        
        r"^powershell\s*.*$",                  
        r"^echo\s*.*$",                        
        r"^dir\s*.*$",                          
        r"^type\s*.*$",                         
        r"^del\s*.*$",                          
        r"^copy\s*.*$",                         
        r"^move\s*.*$",                         
        r"^mkdir\s*.*$",                        
        r"^rmdir\s*.*$",                      
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
        if 'com_inj_vul?input=' in request_text:
            args_text = request_text.split('com_inj_vul?input=')[1].strip()
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
            param_list = [param for param in param_list if 'input' not in param]

            for param_value in param_list:
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

    idor_patterns = [
        r"user_id=\d+",  # Pattern for user_id in query parameters
        r"account_id=\d+",  # Pattern for account_id
        r"order_id=\d+",  # Pattern for order_id
        r"document_id=\d+",  # Pattern for document_id
        r"file_id=\d+",  # Pattern for file_id
        r"ticket_id=\d+",  # Pattern for ticket_id
    ]

    def is_idor_possible(parameter_value):
        for pattern in idor_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    idor_vulnerabilities_found = []
    # Check for IDOR
    for req in requests_list:
        request_text = req.get_text()
        if 'idor_vul?' in request_text:
            args_text = request_text.split('idor_vul?')[1].strip()
            param_list = [param.strip() for param in args_text.split('&') if param.strip()]

            for param_value in param_list:
                if is_idor_possible(param_value):
                    idor_vulnerabilities_found.append(f"Potential IDOR vulnerability in: {request_text.strip()}")
                    break

    # Print IDOR results
    if idor_vulnerabilities_found:
        print("Potential IDOR Vulnerabilities Found:")
        for vulnerability in idor_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No IDOR vulnerabilities found.")

    # LFI/RFI patterns
    file_inclusion_patterns = [
        r"file://",                        # File URI
        r"http://",                        # External URL (RFI)
        r"https://",                       # Secure external URL (RFI)
        r"\.php",                          # PHP file inclusion
        r"\.asp",                          # ASP file inclusion
        r"\.jsp",                          # JSP file inclusion
        r"\.ini",                          # Configuration file inclusion
        r"\.log",                          # Log file inclusion
    ]

    def is_file_inclusion_possible(parameter_value):
        for pattern in file_inclusion_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    file_inclusion_vulnerabilities_found = []
    for req in requests_list:
        request_text = req.get_text()
        if 'file_inclusion_vul?file=' in request_text:
            args_text = request_text.split('file_inclusion_vul?file=')[1].strip()
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
            param_list = [param for param in param_list]

            for param_value in param_list:
                if param_value:
                    if is_file_inclusion_possible(param_value):
                        file_inclusion_vulnerabilities_found.append(f"Potential File Inclusion in: {request_text.strip()}")
                        break

    # Print File Inclusion results
    if file_inclusion_vulnerabilities_found:
        print("Potential File Inclusion Vulnerabilities Found:")
        for vulnerability in file_inclusion_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No File Inclusion vulnerabilities found.")
        
    directory_traversal_patterns = [
        r"\.\./\.\./\.\./",               # Directory traversal
        r"\.\./",                          # Basic directory traversal
        r"/etc/passwd",                    # Linux password file
        r"boot.ini",                       # Windows boot file
    ]
    
    def is_directory_traversal_possible(parameter_value):
        for pattern in directory_traversal_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False
    
    directory_vulnerabilities_found = []
    for req in requests_list:
        request_text = req.get_text()
        if 'dir_trav_vul?pattern=' in request_text:
            args_text = request_text.split('dir_trav_vul?pattern=')[1].strip()
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
            param_list = [param for param in param_list if 'file' not in param]

            for param_value in param_list:
                if param_value:
                    if is_directory_traversal_possible(param_value):
                        directory_vulnerabilities_found.append(f"Potential Directory Traversal in: {request_text.strip()}")
                        break

    # Print File Inclusion results
    if directory_vulnerabilities_found:
        print("Potential Directory Traversal Vulnerabilities Found:")
        for vulnerability in directory_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No Directory Traversal vulnerabilities found.")

    # Open Redirect patterns
    open_redirect_patterns = [
        r"http?://",  # Matches URLs
        r"//",         # Matches protocol-relative URLs
    ]

    def is_open_redirect_possible(parameter_value):
        for pattern in open_redirect_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    open_redirect_vulnerabilities_found = []
    # Check for Open Redirect
    for req in requests_list:
        request_text = req.get_text()
        if 'open_redirect_vul?url=' in request_text:
            args_text = request_text.split('open_redirect_vul?url=')[1].strip()
            param_list = [param.strip() for param in args_text.split('&') if param.strip()]

            for param_value in param_list:
                if is_open_redirect_possible(param_value):
                    open_redirect_vulnerabilities_found.append(f"Potential Open Redirect vulnerability in: {request_text.strip()}")
                    break

    # Print Open Redirect results
    if open_redirect_vulnerabilities_found:
        print("Potential Open Redirect Vulnerabilities Found:")
        for vulnerability in open_redirect_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No Open Redirect vulnerabilities found.")

    ssrf_patterns = [
        r"(localhost|127\.0\.0\.1)",  # Localhost
        r"(0\.0\.0\.0)",               # All IP addresses
        r"(\d{1,3}\.){3}\d{1,3}",     # IPv4 format
        r"([a-z0-9\-]+\.)+[a-z]{2,}",  # Domain names
        r"file://",                    # File protocol
        r"ftp://",                     # FTP protocol
    ]

    def is_ssrf_possible(parameter_value):
        for pattern in ssrf_patterns:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return True
        return False

    ssrf_vulnerabilities_found = []
    for req in requests_list:
        request_text = req.get_text()
        if 'ssrf_vul?url=' in request_text:
            args_text = request_text.split('ssrf_vul?url=')[1].strip()
            param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]

            for param_value in param_list:
                if param_value:
                    if is_ssrf_possible(param_value):
                        ssrf_vulnerabilities_found.append(f"Potential SSRF vulnerability in: {request_text.strip()}")
                        break

    # Print SSRF results
    if ssrf_vulnerabilities_found:
        print("Potential SSRF Vulnerabilities Found:")
        for vulnerability in ssrf_vulnerabilities_found:
            print(f"- {vulnerability}")
    else:
        print("No SSRF vulnerabilities found.")

    found = False

    for req in requests_list:
        request_text = req.get_text()
        if 'xxe_vul' in request_text:
            found = True

    if found:
        print("Potential XXE Vulnerabilities Found: file:///C:/Windows/System32/drivers/etc/hosts")  
    else:
        print("No XXE  vulnerabilities found.")
    
    

else:
    print(f"Failed to retrieve requests. Status code: {response.status_code}")



