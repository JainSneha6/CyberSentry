# CyberSentry - A Cybersecurity Simulation and Vulnerability Scanner

## Overview
CyberSentry is a project designed to simulate common web application vulnerabilities and provide a tool for assessing those vulnerabilities. The project is split into two main components:
- **A Flask-based web application** simulating various security flaws such as SQL Injection, XSS, Command Injection, and more.
- **A Tkinter-based vulnerability assessment tool** that scans the web application for potential security issues.

## Features Overview

| **Feature**                  | **Description**                                                                                               |
|------------------------------|----------------------------------------------------------------------------------------------------------------|
| **Vulnerability Simulation**          | Includes a simulated website with vulnerabilities to demonstrate unauthorized access risks  |
| **Vulnerability Assessment Tool** | A Tkinter-based GUI tool (`CyberSentry`) for scanning and identifying vulnerabilities in web applications.   |

## Simulated Vulnerabilities

| **Vulnerability**                  | **Description**                                                                                               |
|------------------------------------|----------------------------------------------------------------------------------------------------------------|
| **SQL Injection**                  | Demonstrates SQL Injection vulnerability, allowing users to inject SQL commands through input fields.           |
| **XSS (Cross-Site Scripting)**     | Simulates XSS vulnerabilities by reflecting user input directly in the web page, enabling script injection.    |
| **Command Injection**              | Enables command injection by executing user-supplied commands on the server, simulating remote code execution.  |
| **IDOR (Insecure Direct Object References)** | Simulates IDOR by exposing direct access to objects like user IDs without proper authorization.       |
| **File Inclusion**                 | Demonstrates file inclusion vulnerabilities, allowing users to include files from the server or local system.   |
| **Directory Traversal**            | Simulates directory traversal attacks, enabling access to restricted directories or files on the server.        |
| **Open Redirect**                  | Enables open redirect vulnerabilities, allowing redirection to arbitrary URLs specified by the user.           |
| **SSRF (Server-Side Request Forgery)** | Demonstrates SSRF, allowing the user to force the server to make requests to internal or external services. |
| **XXE (XML External Entity)**      | Simulates an XXE vulnerability by parsing XML with external entities, allowing access to local files.           |

## Vulnerability Scanner

| **Feature**                        | **Description**                                                                                             |
|------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Automated Scan**                 | Automatically scans logged requests from the web application to detect potential vulnerabilities.             |
| **Pattern-Based Detection**        | Uses predefined regex patterns to identify common vulnerabilities like SQL Injection, XSS, and Command Injection. |
| **Progress Tracking**              | Displays real-time progress of the scanning process with a visually appealing progress bar.                  |
| **Detailed Results**               | Provides a detailed list of identified vulnerabilities, including their descriptions and where they were found. |
| **Threaded Scanning**              | Uses threading to run scans in the background, keeping the GUI responsive during the scanning process.       |
| **Customizable Patterns**          | Allows adding new patterns to extend the scanner's detection capabilities.                                   |
| **Email Reporting**                | Sends a detailed scan report via email when vulnerabilities are detected, ensuring quick alerts for critical issues. |
| **Beautiful GUI**                  | Features a clean and aesthetic Tkinter-based interface for easy interaction and better user experience.       |



