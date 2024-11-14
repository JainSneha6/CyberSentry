import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
from bs4 import BeautifulSoup
import joblib
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import matplotlib.pyplot as plt
import numpy as np

# Load the trained model
model = joblib.load('url_vulnerability_model.joblib')

SENDER_EMAIL = ""
SENDER_PASSWORD = ""
RECIPIENT_EMAIL = ""
EMAIL_SUBJECT = "CyberSentry Vulnerability Scan Report"

MAX_REQUESTS_PER_MINUTE = 100  # Max requests allowed per minute (for DoS detection)
MAX_RESPONSE_TIME = 2  # Max acceptable response time in seconds

request_count = 0
start_time = time.time()

# Function to send an email report
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

        self.url = "http://localhost:5000/requests"  # URL for scraping test requests
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
            response_time = time.time() - start_time
            self.detect_dos_attack(response, response_time)  # Check for DoS attack

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                requests_list = soup.find_all('li')
                self.assess_vulnerabilities(requests_list)
            else:
                self.update_results(f"Failed to retrieve requests. Status code: {response.status_code}")
        except requests.RequestException as e:
            self.update_results(f"Error occurred while fetching the target: {str(e)}")
        self.progress_bar["value"] = 100

    def assess_vulnerabilities(self, requests_list):
        vulnerabilities_found = []
        risk_scores = {'Low': 0, 'Medium': 0, 'High': 0}
        vulnerabilities_by_type = {}

        for index, req in enumerate(requests_list):
            url = req.get_text().strip()

            # Skip URLs with ImmutableMultiDict in the query parameters
            if 'ImmutableMultiDict' in url:
                continue
            
            predicted_vulnerability = model.predict([url])[0]

            if predicted_vulnerability != "Safe":  # Only display vulnerabilities
                self.update_results(f"⚠️ URL: {url}\nPredicted Vulnerability: {predicted_vulnerability}\n")
                vulnerabilities_found.append(predicted_vulnerability)

                # Increase count for vulnerability type
                vulnerabilities_by_type[predicted_vulnerability] = vulnerabilities_by_type.get(predicted_vulnerability, 0) + 1
                
                # Assign risk scores based on vulnerability type
                if predicted_vulnerability in ['SQL Injection', 'Cross-site Scripting']:
                    risk_scores['High'] += 1
                elif predicted_vulnerability in ['Cross-Site Request Forgery']:
                    risk_scores['Medium'] += 1
                else:
                    risk_scores['Low'] += 1

            # Update progress bar
            progress = (index + 1) * (100 / len(requests_list))
            self.progress_bar["value"] = progress
            self.master.update_idletasks()
            time.sleep(0.5)  # Simulate processing time

        # Send an email report if vulnerabilities are found
        if any("⚠️" in vuln for vuln in vulnerabilities_found):
            report_body = self.results_text.get(1.0, tk.END)
            send_email(EMAIL_SUBJECT, report_body)
        
        # Visualize meaningful graphs
        self.visualize_vulnerabilities(vulnerabilities_by_type)
        self.visualize_risk_distribution(risk_scores)

    def update_results(self, message):
        self.results_text.insert(tk.END, message + "\n\n")
        self.results_text.see(tk.END)
        self.results_text.update_idletasks()

    # Bar Chart for Vulnerabilities by Type
    def visualize_vulnerabilities(self, vulnerabilities_by_type):
        labels = list(vulnerabilities_by_type.keys())
        counts = list(vulnerabilities_by_type.values())
        
        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts, color='salmon')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Count')
        plt.title('Vulnerabilities by Type')
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

    # Pie Chart for Risk Distribution
    def visualize_risk_distribution(self, risk_scores):
        labels = list(risk_scores.keys())
        sizes = list(risk_scores.values())
        colors = ['#ff6666', '#ffcc99', '#66b3ff']

        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        plt.title('Risk Distribution of Vulnerabilities')
        plt.show()

    # DoS attack detection
    def detect_dos_attack(self, response, response_time):
        global request_count, start_time

        current_time = time.time()
        elapsed_time = current_time - start_time

        if elapsed_time >= 60:  # Every minute, reset the count
            start_time = current_time
            request_count = 0

        request_count += 1
        if request_count > MAX_REQUESTS_PER_MINUTE:
            self.update_results(f"⚠️ Potential DoS Attack Detected! Too many requests in a short period.")
            send_email("DoS Attack Detected", "Too many requests were detected within a short time.")
        
        if response_time > MAX_RESPONSE_TIME:
            self.update_results(f"⚠️ High response time detected: {response_time:.2f} seconds.")
            send_email("High Response Time Detected", f"Response time exceeded threshold: {response_time:.2f} seconds.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityScannerApp(root)
    root.mainloop()
