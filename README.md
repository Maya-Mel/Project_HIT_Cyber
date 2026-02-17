# Communication_LTD – Secure Web Information System

## Project Overview
[cite_start]This project involves the development of a secure web-based information system for a fictional telecommunications company, **Communication_LTD**[cite: 5]. [cite_start]The system manages customer data, service packages, and sector-based marketing information while adhering to strict **Secure Development Life Cycle (SDLC)** principles[cite: 5, 9].

## Security Implementation
[cite_start]The core focus of this project was implementing robust security mechanisms to mitigate common web vulnerabilities[cite: 30, 32]:

### 1. Authentication & Identity Management
* **Secure Registration:** Implemented complex password policies managed via configuration files (length, history, and character variety)[cite: 12, 17, 36].
* [cite_start]**Advanced Hashing:** Passwords are never stored in plain text; they are secured using **HMAC + Salt**[cite: 13].
* [cite_start]**Secure Password Reset:** Developed a reset mechanism using **SHA-1** generated tokens sent via simulated email[cite: 27, 28].

### 2. Vulnerability Mitigation (Vulnerable vs. Secure Versions)
[cite_start]The project demonstrates both vulnerable and patched versions of the following attacks[cite: 35]:
* **SQL Injection (SQLi):** Demonstrated attacks on login and data entry forms. [cite_start]Mitigated using **Parameterized Queries** and **Stored Procedures**[cite: 32, 34].
* **Cross-Site Scripting (XSS):** Demonstrated **Stored XSS** attacks. Mitigated through strict character encoding and input validation[cite: 31, 33].

## Tech Stack
* **Backend:** Python (Flask)
* **Database:** Relational Database (MySQL) [cite: 7, 8]
* **Security:** Cryptography (HMAC, Salt, SHA-1), Input Sanitization.
