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

![image](https://github.com/user-attachments/assets/133b29f3-909a-4b99-a230-4acc289d8d8e)
![image](https://github.com/user-attachments/assets/a3d06b1e-26d9-4f55-a474-089828258192)

## Architecture
![image](https://github.com/user-attachments/assets/1191db4e-f5d2-495d-9023-65bd713819d9)


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



