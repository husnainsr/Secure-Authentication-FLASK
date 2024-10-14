# 🔐 SecureAuth: A Two-Factor Authentication Web Application

Welcome to **SecureAuth**, a robust authentication system designed to provide a high level of security through two-factor authentication (2FA) using email-based One-Time Passwords (OTPs). This project focuses on implementing a secure login mechanism integrated with SQLite for data management and Flask for backend web development.

---

## 🚀 Project Overview

**SecureAuth** is a web application that enhances user authentication by integrating two-factor authentication (2FA) through email-based OTP verification. The project ensures secure user login with encrypted password storage and an additional OTP verification layer.

### Key Features
- **User Registration & Authentication:** Secure password storage using bcrypt.
- **Email-Based OTP System:** Send and verify OTPs for enhanced security.
- **Session Management:** Handle user sessions and OTP expiration.
- **Security:** Implement rate limiting and protection against SQL injection, CSRF, and XSS attacks.

---

## 🛠️ Tools and Technologies

- **Programming Language:** Python 3.8 or newer
- **Framework:** Flask
- **Database:** SQLite
- **Email Service:** smtplib for email integration
- **Frontend:** HTML/CSS (Bootstrap optional for styling)
- **Security:** Flask-Limiter, bcrypt for password hashing

---
## 📝 Setup and Installation Instructions

### Step 1: Clone the repository.=
First, clone the project repository from GitHub.
```bash
git clone https://github.com/husnainsr/secureAuth.git
cd secureauth
```
### Step 2: Create and activate a virtual environment.=
On Ubuntu/Mac:
```bash
python3 -m venv venv
source venv/bin/activate
```
On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install required dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Step 4: Run the application
```bash
flask run
```

---
## 📋 Project Roadmap

### Deliverable 1: Environment Setup and Database Schema Definition
- **Goal:** Set up the environment and database schema using SQLite and Flask.

#### Husnain – Environment Setup
- Set up Python, Flask, and required libraries.
- Create virtual environment for the project.

#### Isma – SQLite Database Setup
- Configure SQLite database and ensure Flask connectivity.

#### Khadijah – Database Schema Definition
- Define tables for users and sessions.

#### Nibras – Initial Testing
- Test the basic database connection and user registration form.

---

### Deliverable 2: Backend Development for User Registration and Login
- **Goal:** Develop secure user registration and login with encrypted passwords.

#### Husnain – User Registration
- Implement user registration form with email verification.

#### Isma – Secure Password Storage
- Use bcrypt for password hashing and secure storage.

#### Khadijah – User Login System
- Develop a user login form with password authentication.

#### Nibras – Database Integration
- Integrate the backend with SQLite for user data storage and retrieval.

---

### Deliverable 3: OTP Generation, Email Integration, and 2FA
- **Goal:** Implement OTP generation and verification system as part of 2FA.

#### Husnain – OTP Generation
- Develop a secure OTP system with an expiration time.

#### Isma – Email Integration for OTP
- Configure and test email sending for OTP using smtplib.

#### Khadijah – OTP Verification
- Implement OTP verification process and handle expired OTPs.

#### Nibras – OTP Session Management
- Manage user sessions and OTP validity in the database.

---

### Deliverable 4: Frontend, Security Enhancements, and Testing
- **Goal:** Finalize frontend design, add security features, and perform comprehensive testing.

#### Husnain – Frontend Development
- Create user-friendly forms for registration, login, and OTP verification.

#### Isma – Security Features
- Implement rate limiting, session management, and security protections.

#### Khadijah – Session Management
- Ensure session persistence and logout functionality.

#### Nibras – Testing and Debugging
- Conduct functional, security, and usability testing, and write test cases.

---

## 📦 Final Deliverables

1. **Code Repository:**
   - Source code hosted on GitHub with setup instructions.
   - Well-documented codebase.

2. **Written Report:**
   - Architecture and security analysis.
   - Challenges and solutions.

3. **Live Demonstration:**
   - Real-time demonstration of the OTP-based authentication process.

---

## 📅 Timeline

1. **Week 1-2:** Environment setup and database configuration.
2. **Week 3-4:** Backend development for registration and login.
3. **Week 5-6:** Integration of the OTP system.
4. **Week 7:** Testing and security enhancements.
5. **Week 8:** Final review and demonstration preparation.

---

## 🔒 Security Features Implemented
- **Password Hashing:** Using bcrypt with salt for secure password storage.
- **Rate Limiting:** To prevent brute-force attacks on login and OTP requests.
- **CSRF Protection:** Secure forms to prevent Cross-Site Request Forgery attacks.
- **Session Management:** Ensure secure sessions and proper logout functionality.

---

## 📧 Email Configuration
Use a free SMTP service like Gmail to send OTPs. Update the Flask configuration with the email server details securely.
