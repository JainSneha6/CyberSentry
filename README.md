# CyberSentry - A Cybersecurity Simulation and Vulnerability Scanner

**CyberSentry** is a powerful vulnerability assessment tool designed to scan and identify security risks in web applications. It leverages machine learning to detect threats such as **SQL Injection, XSS, Command Injection, IDOR, File Inclusion, Directory Traversal, Open Redirect, SSRF, and XXE attacks**.

The tool extracts web request data, analyzes patterns, and provides a comprehensive security report, helping security teams proactively address potential risks.

<p align="center">
  <img src="https://github.com/user-attachments/assets/003eb027-4f3d-466d-bdb9-bb2e666a0491" width="800px">
</p>


## Why CyberSentry?

<details>
  <summary><strong>AI & Machine Learning-Powered Security</strong></summary>
  Unlike traditional rule-based scanners, CyberSentry leverages machine learning and artificial intelligence for vulnerability detection. It identifies threats based on patterns rather than relying solely on predefined signatures, allowing it to detect emerging and zero-day vulnerabilities.
</details>

<details>
  <summary><strong>Faster and More Efficient</strong></summary>
  CyberSentry automates the process of identifying security risks in web applications, reducing manual effort. Its intelligent analysis enables quick identification of threats, minimizing the time required for vulnerability assessment.
</details>

<details>
  <summary><strong>Automated Reporting and Real-Time Insights</strong></summary>
  The tool generates comprehensive security reports and provides real-time visualizations. It categorizes vulnerabilities into different risk levels, allowing security teams to prioritize and address critical threats efficiently.
</details>

<details>
  <summary><strong>User-Friendly and Accessible</strong></summary>
  CyberSentry is designed with a simple yet effective user interface, making it accessible to both security professionals and developers. Its automated approach reduces the need for extensive cybersecurity expertise, making web security more manageable for all users.
</details>

<details>
  <summary><strong>Scalable and Versatile</strong></summary>
  Whether for small web applications or large enterprise systems, CyberSentry adapts to different environments. Its ability to analyze complex security patterns makes it a valuable tool for organizations looking to enhance their security posture.
</details>

<details>
  <summary><strong>Proactive Threat Detection</strong></summary>
  By continuously improving its detection capabilities through machine learning, CyberSentry provides proactive threat identification. This ensures that security vulnerabilities are addressed before they can be exploited by attackers.
</details>

---

## URL Vulnerability Detection Using Machine Learning  

<p align="center">
  <img src="https://github.com/user-attachments/assets/1c51ea85-2028-4898-b465-e46be4ad9727" width="800px">
</p>

Further the **above vulnerabilities** are classified based on their **vulnerability types** using different machine learning models. A dataset of labeled URLs is used to train and evaluate the models.  

### Model Performance Comparison  

| Model | Accuracy (%) | Training Time | Notes |
|--------|------------|--------------|------|
| **Random Forest Classifier** | **87.5** | Medium | Strong performance with minimal tuning. Handles text features well. |
| **Logistic Regression** | 74.2 | Fast | Simple and interpretable but struggles with complex patterns. |
| **Support Vector Machine (SVM)** | 79.6 | Slow | Good performance but computationally expensive on large datasets. |
| **Naïve Bayes** | 70.3 | Very Fast | Works well with text but assumes feature independence. |
| **Gradient Boosting (XGBoost)** | **90.1** | Slow | High accuracy, but requires tuning for best performance. |
| **Neural Networks (Deep Learning)** | **92.8** | Very Slow | Best accuracy but needs large datasets and more computational resources. |

### Key Findings  
- **Neural Networks achieved the highest accuracy (92.8%)**, but required the longest training time.  
- **XGBoost performed well (90.1%)** and is a strong alternative for large datasets.  
- **Random Forest (87.5%)** is a good balance between accuracy and efficiency.  
- **Naïve Bayes (70.3%)** is the fastest but lacks accuracy due to its assumptions.  

---

## URL Vulnerability Detection Using AI Models  

<p align="center">
  <img src="https://github.com/user-attachments/assets/c18d6f10-e859-421b-82a6-14076b9f7410" width="800px">
</p>

Further utilizing **Artificial Intelligence (AI) models** to detect vulnerabilities in URLs based on their characteristics. Several AI architectures, including transformer-based models and deep learning approaches, have been tested to compare their accuracy and efficiency.  

## AI Model Performance Comparison  

| AI Model | Accuracy (%) | Training Time | Notes |
|-----------|------------|--------------|------|
| **BERT (Bidirectional Encoder Representations from Transformers)** | **94.3** | Slow | Excellent performance, understands contextual patterns in URLs. |
| **RoBERTa (Robustly Optimized BERT Approach)** | **95.1** | Very Slow | Slightly better than BERT, but requires more computational power. |
| **GPT-3** | 91.7 | Very Slow | Strong text comprehension, but expensive to fine-tune. |
| **DistilBERT** | 90.4 | Medium | Lighter and faster than BERT, with minimal accuracy loss. |

## Key Findings  
- **RoBERTa achieved the highest accuracy (95.1%)**, but required the longest training time.  
- **BERT (94.3%)** is a strong choice for understanding URL patterns.  
- **GPT-3 (91.7%)** performs well but is computationally expensive.  
- **DistilBERT (90.4%)** offers a **good balance between speed and accuracy**.  

---

## Advanced Vulnerability Scanner

<p align="center">
  <img src="https://github.com/user-attachments/assets/9048ac5b-0d2a-4af4-aa9f-5969bdff8de8" width="800px">
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/4cc0f1e3-b8aa-4653-9ccb-055b0e1ff44f" width="800px">
</p>

### Features

- **Automated Web Security Scanning**  
  - Detects common vulnerabilities in web applications.
  - Uses machine learning and artificial intelligence to classify potential threats.

- **Intelligent Analysis & Reporting**  
  - Provides real-time vulnerability assessments.
  - Categorizes threats into **High, Medium, and Low risk**.

- **Email Notifications**  
  - Sends detailed security reports upon completion of a scan.

- **Data Visualization**  
  - Graphical representation of vulnerabilities by type.
  - Risk distribution insights via pie charts.

### How It Works

1. **Initiate Scan**  
   - The tool fetches requests from a target web application.
   - Analyzes URLs for potential security threats.

2. **Threat Detection**  
   - Uses a pre-trained machine learning and artificial intelligence model to classify vulnerabilities.
   - Identifies security risks based on URL patterns.

3. **Risk Evaluation**  
   - Categorizes vulnerabilities by severity.
   - Logs and displays findings in a user-friendly interface.

4. **Security Report Generation**  
   - Summarizes identified vulnerabilities.
   - Sends an email notification with recommendations.

### Bar Charts

<p align="center">
  <img src="https://github.com/user-attachments/assets/17d74776-4cc1-4bfb-aa94-c5965236c3b2" width="600px">
</p>

### Pie Charts

<p align="center">
  <img src="https://github.com/user-attachments/assets/d108aa8b-9af7-496b-b845-2ff05a40cf75" width="600px">
</p>

### Scan Report Email

<p align="center">
  <img src="https://github.com/user-attachments/assets/eb2da672-8c95-4921-b606-280db04d4f40" width="600px">
</p>

---

## Real-World Use Cases  

CyberSentry can be applied across various industries to enhance cybersecurity and prevent attacks.  

| Industry         | Use Case |
|-----------------|------------------------------------------------------------------|
| **Banking & Finance** | Protects sensitive customer data from SQL Injection & XSS attacks. |
| **Healthcare**       | Secures patient records by detecting IDOR & SSRF vulnerabilities. |
| **E-Commerce**      | Prevents Open Redirect attacks leading to phishing scams. |
| **Enterprises**     | Automates security scans for large-scale web applications. |

By leveraging CyberSentry, organizations can proactively secure their digital assets, ensuring compliance and protection against cyber threats.

---

## Vulnerabilities Covered

<p align="center">
  <img src="https://github.com/user-attachments/assets/7b88f84b-01a0-4479-bc70-41cca8ca9b50" width="800px">
</p>


| #  | Vulnerability Name                            | Description |
|----|----------------------------------------------|-------------|
| 1  | **SQL Injection**                            | Exploiting database queries by injecting malicious SQL code. |
| 2  | **Cross-Site Scripting (XSS)**              | Injecting malicious scripts into webpages viewed by other users. |
| 3  | **Command Injection**                        | Executing arbitrary system commands via insecure user input handling. |
| 4  | **Insecure Direct Object References (IDOR)** | Accessing unauthorized resources due to improper access controls. |
| 5  | **File Inclusion**                           | Including unauthorized files (e.g., Local/Remote File Inclusion). |
| 6  | **Directory Traversal**                      | Gaining access to restricted directories by manipulating file paths. |
| 7  | **Open Redirect**                            | Redirecting users to malicious sites via unvalidated input. |
| 8  | **Server-Side Request Forgery (SSRF)**       | Forcing a server to make requests to unintended locations. |
| 9  | **XML External Entity (XXE)**                | Exploiting vulnerabilities in XML parsers to access local files or execute remote requests. |

---

## Understanding SQL Injections  

<p align="center">
  <img src="https://github.com/user-attachments/assets/6cd48f01-9c00-4efe-a38d-d04caf4bd898" width="800px">
</p>

### What is SQL Injection?  
SQL Injection is a **security vulnerability** that allows an attacker to interfere with database queries. By manipulating input fields, attackers can inject malicious SQL commands, gaining **unauthorized access** or modifying the database.  

---

## Understanding Cross-Site Scripting (XSS)  

<p align="center">
  <img src="https://github.com/user-attachments/assets/6d0a060a-525d-4734-adfa-4718808dad2e" width="800px">
</p>

### What is Cross-Site Scripting (XSS)?  
Cross-Site Scripting (XSS) is a **security vulnerability** that allows attackers to inject **malicious scripts** into web pages viewed by other users. Exploiting XSS can allow attackers to **steal cookies, session tokens, or sensitive information** and even perform actions on behalf of the victim.  

---

## Understanding Command Injection  

<p align="center">
  <img src="https://github.com/user-attachments/assets/a728f792-b69d-4ccd-b9b3-2748eab3cd11" width="800px">
</p>

### What is Command Injection?  
Command Injection is a **security vulnerability** that allows attackers to execute arbitrary system commands on a host operating system via a vulnerable application. By injecting malicious commands, attackers can gain **unauthorized control** over the system, access sensitive data, or disrupt operations.  

---

## Understanding Insecure Direct Object References (IDOR)  

<p align="center">
  <img src="https://github.com/user-attachments/assets/66098445-c6c7-4095-8fb3-cfc0c629e042" width="800px">
</p>

### What is IDOR?  
Insecure Direct Object References (IDOR) is a **security vulnerability** that occurs when an application allows users to access or manipulate objects **without proper authorization checks**. Attackers exploit IDOR to access **sensitive data** or perform **unauthorized actions** by modifying input values such as **URLs, request parameters, or API endpoints**.  

---

## Understanding File Inclusion Vulnerabilities  

<p align="center">
  <img src="https://github.com/user-attachments/assets/7d899798-d4c1-47ec-9f74-7d5cba57a5fc" width="800px">
</p>

### What is File Inclusion?  
File Inclusion is a **security vulnerability** that occurs when an application allows users to include files **without proper validation**. This can lead to **unauthorized access**, **information disclosure**, or even **remote code execution** in severe cases. There are two types of file inclusion vulnerabilities:  

- **Local File Inclusion (LFI)**: Attackers can include and read files **from the server** (e.g., `/etc/passwd`).  
- **Remote File Inclusion (RFI)**: Attackers can include malicious files **from an external source**, leading to **code execution**.  

---

## Understanding Directory Traversal  

<p align="center">
  <img src="https://github.com/user-attachments/assets/91e9d675-1260-4c79-a324-b781add85c6f" width="800px">
</p>

### What is Directory Traversal?  
Directory Traversal is a **security vulnerability** that allows attackers to access restricted files and directories outside of the intended web root. This occurs when applications **fail to properly validate user input**, allowing attackers to manipulate file paths using special characters like `../` to traverse directories.  

---

## Understanding Open Redirect  

<p align="center">
  <img src="https://github.com/user-attachments/assets/7272c2c4-31b7-4d83-a534-cc6e46994b06" width="800px">
</p>

### What is Open Redirect?  
Open Redirect is a **security vulnerability** that occurs when a web application **blindly redirects users** to external URLs without proper validation. Attackers can exploit this weakness to **redirect users to malicious websites**, leading to **phishing attacks, malware distribution, and session hijacking**.  

---

## Understanding Server-Side Request Forgery (SSRF)  

<p align="center">
  <img src="https://github.com/user-attachments/assets/29a95ea1-a938-4b5a-908d-dcc2b0bdc33c" width="800px">
</p>

### What is SSRF?  
Server-Side Request Forgery (SSRF) is a **security vulnerability** where an attacker can **manipulate a server to make unintended HTTP requests**. This can allow attackers to access **internal systems, metadata services, or sensitive endpoints** that are normally inaccessible from the outside.  

---

## Understanding XML External Entity (XXE) Attack  

<p align="center">
  <img src="https://github.com/user-attachments/assets/278f6470-4eb8-471e-82a5-35170552bccf" width="800px">
</p>

### What is XXE?  
XML External Entity (XXE) attack is a **security vulnerability** that allows attackers to exploit weakly configured XML parsers. By injecting **malicious external entities**, attackers can read **sensitive files, perform internal network scans, execute remote code**, or trigger **denial of service (DoS)** attacks.  

---






