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
| **Email Reporting**          | Automatically sends a vulnerability scan report via email if potential vulnerabilities are found.               |
| **Beautiful GUI**            | A user-friendly and visually appealing interface using Tkinter for better user experience.                     |

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


