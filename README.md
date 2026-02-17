# Communication_LTD – Secure Web Information System

## Project Overview
This project involves the development of a secure web-based information system for a fictional telecommunications company, **Communication_LTD**.The system manages customer data, service packages, and sector-based marketing information while adhering to strict **Secure Development Life Cycle (SDLC)** principles.

## Security Implementation
The core focus of this project was implementing robust security mechanisms to mitigate common web vulnerabilities:

### 1. Authentication & Identity Management
* **Secure Registration:** Implemented complex password policies managed via configuration files (length, history, and character variety).
* **Advanced Hashing:** Passwords are never stored in plain text; they are secured using **HMAC + Salt**.
* **Secure Password Reset:** Developed a reset mechanism using **SHA-1** generated tokens sent via simulated email.

### 2. Vulnerability Mitigation (Vulnerable vs. Secure Versions)
The project demonstrates both vulnerable and patched versions of the following attacks:
* **SQL Injection (SQLi):** Demonstrated attacks on login and data entry forms.Mitigated using **Parameterized Queries** and **Stored Procedures**.
* **Cross-Site Scripting (XSS):** Demonstrated **Stored XSS** attacks. Mitigated through strict character encoding and input validation.

## Tech Stack
* **Backend:** Python (Flask)
* **Database:** Relational Database (MySQL) 
* **Security:** Cryptography (HMAC, Salt, SHA-1), Input Sanitization.
