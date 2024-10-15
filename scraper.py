import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
from bs4 import BeautifulSoup
import re
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = ""
SENDER_PASSWORD = ""
RECIPIENT_EMAIL = ""
EMAIL_SUBJECT = "CyberSentry Vulnerability Scan Report"

def send_email(subject, body):
        try:
            msg = MIMEMultipart()
            msg['From'] = SENDER_EMAIL
            msg['To'] = RECIPIENT_EMAIL
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.send_message(msg)
            
            print("Email sent successfully.")
        except Exception as e:
            print(f"Failed to send email: {e}")

class CyberSecurityScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("CyberSentry - Vulnerability Scanner")
        master.geometry("900x700")
        master.configure(bg="#0A0E12")

        self.url = "http://localhost:5000/requests"  
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_frame = tk.Frame(self.master, bg="#0A0E12")
        title_frame.pack(pady=20)
        
        title_label = tk.Label(title_frame, text="CyberSentry", font=("Orbitron", 32, "bold"), fg="#00FFAA", bg="#0A0E12")
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Advanced Vulnerability Scanner", font=("Orbitron", 16), fg="#00FFAA", bg="#0A0E12")
        subtitle_label.pack()

        # Scan Button
        scan_button = tk.Button(self.master, text="INITIATE SCAN", command=self.start_scan, font=("Arial", 16, "bold"), 
                                bg="#00FFAA", fg="#0A0E12", padx=20, pady=10, relief=tk.FLAT,
                                activebackground="#00CC88", activeforeground="#0A0E12")
        scan_button.pack(pady=30)

        # Progress Bar
        self.progress_frame = tk.Frame(self.master, bg="#0A0E12")
        self.progress_frame.pack(pady=10)
        self.progress_label = tk.Label(self.progress_frame, text="Scan Progress", font=("Arial", 12), fg="#00FFAA", bg="#0A0E12")
        self.progress_label.pack()
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient="horizontal", length=400, mode="determinate", style="TProgressbar")
        self.progress_bar.pack(pady=5)

        # Custom style for progress bar
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar", thickness=25, troughcolor='#1A242C', background='#00FFAA')

        # Results Text Area
        result_frame = tk.Frame(self.master, bg="#0A0E12")
        result_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        result_label = tk.Label(result_frame, text="Scan Results", font=("Arial", 16, "bold"), fg="#00FFAA", bg="#0A0E12")
        result_label.pack()
        
        self.results_text = scrolledtext.ScrolledText(result_frame, width=90, height=20, font=("Consolas", 11),
                                                      bg="#1A242C", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.results_text.pack(pady=10, fill=tk.BOTH, expand=True)

        # Customize the scrollbar
        self.results_text.vbar.config(troughcolor='#0A0E12', bg='#00FFAA')

    def start_scan(self):
        self.results_text.delete(1.0, tk.END)
        self.progress_bar["value"] = 0
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        try:
            response = requests.get(self.url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                requests_list = soup.find_all('li')
                self.check_vulnerabilities(requests_list)
            else:
                self.update_results(f"Failed to retrieve requests. Status code: {response.status_code}")
        except requests.RequestException as e:
            self.update_results(f"Error occurred while fetching the target: {str(e)}")
        self.progress_bar["value"] = 100

    def check_vulnerabilities(self, requests_list):
        vulnerabilities = [
            ("SQL Injection", self.sql_injection_patterns(), 'with args:'),
            ("XSS", self.xss_patterns(), 'xss_vul?input='),
            ("Command Injection", self.command_injection_patterns(), 'com_inj_vul?input='),
            ("IDOR", self.idor_patterns(), 'idor_vul?'),
            ("File Inclusion", self.file_inclusion_patterns(), 'file_inclusion_vul?file='),
            ("Directory Traversal", self.directory_traversal_patterns(), 'dir_trav_vul?pattern='),
            ("Open Redirect", self.open_redirect_patterns(), 'open_redirect_vul?url='),
            ("SSRF", self.ssrf_patterns(), 'ssrf_vul?url=')
        ]

        total_checks = len(vulnerabilities) + 1  # +1 for XXE check
        for index, (vuln_type, patterns, identifier) in enumerate(vulnerabilities):
            self.check_pattern(requests_list, patterns, vuln_type, identifier)
            self.progress_bar["value"] = (index + 1) * (100 / total_checks)
            self.master.update_idletasks()
            time.sleep(0.5)  # Simulate scanning time

        # XXE Check
        xxe_found = any('xxe_vul' in req.get_text() for req in requests_list)
        if xxe_found:
            self.update_results("⚠️ Potential XXE Vulnerability Found:\n   file:///C:/Windows/System32/drivers/etc/hosts")
        else:
            self.update_results("✅ No XXE vulnerabilities found.")
            
        if "⚠️" in self.results_text.get(1.0, tk.END):
            report_body = self.results_text.get(1.0, tk.END)
            send_email(EMAIL_SUBJECT, report_body)

    def check_pattern(self, requests_list, patterns, vulnerability_type, request_identifier):
        vulnerabilities_found = []
        for req in requests_list:
            request_text = req.get_text()
            if request_identifier in request_text:
                args_text = request_text.split(request_identifier)[1].strip()
                param_list = [param.strip().strip('"') for param in args_text.split(',') if param.strip()]
                param_list = [param for param in param_list if 'input' not in param]

                for param_value in param_list:
                    if param_value and any(re.search(pattern, param_value, re.IGNORECASE) for pattern in patterns):
                        vulnerabilities_found.append(f"   {request_text.strip()}")
                        break

        if vulnerabilities_found:
            self.update_results(f"⚠️ Potential {vulnerability_type} Vulnerabilities Found:")
            for vulnerability in vulnerabilities_found:
                self.update_results(vulnerability)
        else:
            self.update_results(f"✅ No {vulnerability_type} vulnerabilities found.")

    def update_results(self, message):
        self.results_text.insert(tk.END, message + "\n\n")
        self.results_text.see(tk.END)
        self.results_text.update_idletasks()

    # Vulnerability patterns methods
    def sql_injection_patterns(self):
        return [
            r"\s*OR\s*1=1", r"\s*--", r"\s*#", r"UNION SELECT", r"DROP\s+TABLE\s+\w+",
            r"SELECT\s+\*?\s+FROM\s+\w+", r"SELECT\s+\w+\s+FROM\s+\w+", r"AND\s+\(SELECT\s+\d+\s+FROM",
            r"INSERT\s+INTO\s+\w+\s+VALUES\s*\(", r"EXEC\s+sp_.*", r"DECLARE\s+\w+\s+AS",
            r"CREATE\s+TABLE\s+\w+", r"ALTER\s+TABLE\s+\w+\s+ADD", r"SHOW\s+TABLES",
            r"SET\s+@@session.sql_mode", r"TRUNCATE\s+TABLE\s+\w+", r"SELECT\s+FROM\s+INFORMATION_SCHEMA.*"
        ]

    def xss_patterns(self):
        return [
            r"<script.*?>.*?</script>", r"javascript:.*", r"on\w*=\s*['\"].*?['\"]",
            r"<img.*?src=['\"]*.*?['\"].*?onerror=.*?>", r"<iframe.*?>.*?</iframe>",
            r"<a.*?href=['\"]*javascript:.*?['\"].*?>", r"<meta.*?http-equiv=['\"]refresh['\"].*?>",
            r"<link.*?href=['\"]*.*?['\"].*?rel=['\"]stylesheet['\"]", r"<body.*?onload=.*?>",
            r"<svg.*?onload=.*?>", r"document\.cookie", r"eval\s*\(.*?\)", r"setTimeout\s*\(.*?\)",
            r"setInterval\s*\(.*?\)", r"onerror\s*=\s*['\"].*?['\"]", r"<style.*?>.*?</style>"
        ]

    def command_injection_patterns(self):
        return [
            r"(?:^|&|\|)(?:cmd|powershell|start|echo|dir|type|del|copy|move|mkdir|rmdir)(?:\s+[^&|]*)?$",
            r"^cmd", r"^start\s*.*$", r"^powershell\s*.*$", r"^echo\s*.*$", r"^dir\s*.*$",
            r"^type\s*.*$", r"^del\s*.*$", r"^copy\s*.*$", r"^move\s*.*$", r"^mkdir\s*.*$", r"^rmdir\s*.*$"
        ]

    def idor_patterns(self):
        return [
            r"user_id=\d+", r"account_id=\d+", r"order_id=\d+",
            r"document_id=\d+", r"file_id=\d+", r"ticket_id=\d+"
        ]

    def file_inclusion_patterns(self):
        return [
            r"file://", r"http://", r"https://", r"\.php",
            r"\.asp", r"\.jsp", r"\.ini", r"\.log"
        ]

    def directory_traversal_patterns(self):
        return [
            r"\.\./\.\./\.\./", r"\.\./", r"/etc/passwd", r"boot.ini"
        ]

    def open_redirect_patterns(self):
        return [r"http?://", r"//"]

    def ssrf_patterns(self):
        return [
            r"(localhost|127\.0\.0\.1)", r"(0\.0\.0\.0)", r"(\d{1,3}\.){3}\d{1,3}",
            r"([a-z0-9\-]+\.)+[a-z]{2,}", r"file://", r"ftp://"
        ]

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityScannerApp(root)
    root.mainloop()