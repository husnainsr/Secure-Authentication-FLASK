# 🚀 Project To-Do List:🔐 SecureAuth-A Two-Factor Authentication Web Application

## Deliverable 1: Environment Setup and Database Schema Definition
**Goal**: Set up the development environment and define the database schema.

### 👨‍💻 Husnain – Environment Setup
- [x] Github Repo Setup.
- [x] Install Python 3.8 or newer.
- [x] Install and configure Flask.
- [x] Create a Python virtual environment.
- [x] Install required libraries (Flask, bcrypt, smtplib, SQLite).

### 👩‍💻 Isma – SQLite Database Setup
- [x] Install and configure SQLite.
- [x] Create the project database.
- [x] Ensure Flask is connected to the SQLite database.
- [x] Add show all users webpage connected with database.

### 👩‍💻 Khadijah – Database Schema Definition
- [x] Define the `users` table schema:
  - [x] Columns: `user_id` (primary key), `username`, `email`, `hashed_password`, `registration_date`.
- [x] Define the `sessions` table schema:
  - [x] Columns: `session_id`, `user_id` (foreign key), `session_token`, `expires_at`.

### 👨‍💻 Nibras – Initial Testing and Validation
- [x] Test SQLite database connection with Flask.
- [x] Implement a basic user registration form to insert data into the `users` table.
- [x] Ensure tables and fields are correctly created.

---

## Deliverable 2: Backend Development for User Registration and Login
**Goal**: Implement secure user registration, password storage, and user login.

### 👨‍💻 Husnain – User Registration
- [x] Implement a form to register users (username, email, password).
- [x] Validate user inputs (e.g., valid email, strong password).
- [x] Verify email address through a confirmation link sent to the user’s email.

### 👩‍💻 Isma – Secure Password Storage
- [x] Implement password hashing using bcrypt.
- [x] Ensure passwords are securely stored using salt and appropriate hashing techniques.
- [x] Test password storage by registering a few test users.

### 👩‍💻 Khadijah – User Login System
- [x] Implement user login form (username and password).
- [x] Authenticate users using stored hashed passwords (compare hashed versions).
- [x] Set up error handling for incorrect login attempts.

### 👨‍💻 Nibras – Database Integration for Registration/Login
- [x] Implement database interactions for both registration and login (store/retrieve user data).
- [x] Store user details (hashed password) and email confirmation status in the database.
- [x] Test the login process using multiple test users.

---

## Deliverable 3: OTP Generation, Email Integration, and Two-Factor Authentication (2FA)
**Goal**: Implement OTP-based two-factor authentication (2FA) using email.

### 👨‍💻 Husnain – OTP Generation
- [x] Implement a secure OTP generation system.
- [x] Generate a random OTP with a set expiration time (e.g., 5 minutes).
- [x] Ensure that OTPs are unique for each request.

### 👩‍💻 Isma – Email Integration for OTP
- [x] Integrate smtplib for sending OTP via email.
- [x] Configure SMTP settings securely in Flask to send the OTP.
- [x] Test email sending with a free SMTP provider (e.g., Gmail).

### 👩‍💻 Khadijah – OTP Verification
- [x] Create a form where users can enter the OTP they received via email.
- [x] Implement verification of OTP, checking the expiry time.
- [x] Allow users to request a new OTP if the original expires.

### 👨‍💻 Nibras – OTP Session Management
- [x] Store OTPs in the database alongside the user session.
- [x] Manage session state during login and OTP verification.
- [x] Implement error handling for incorrect OTP entries and expired OTPs.

---

## Deliverable 4: Frontend, Security Enhancements, and Final Testing
**Goal**: Finalize the frontend interface, add security features, and conduct extensive testing.

### 👨‍💻 Husnain – Frontend Development
- [x] Create a simple user interface for registration, login, and OTP verification using HTML/CSS.
- [x] Implement secure forms with validation (e.g., email format, password strength).
- [x] Optional: Use Bootstrap for enhanced styling and layout.

### 👩‍💻 Isma – Security Features
- [x] Implement rate limiting for login attempts and OTP requests (using Flask-Limiter).
- [x] Secure the application against common vulnerabilities like SQL injection, CSRF, and XSS.
- [x] Use secure cookies for session management.

### 👩‍💻 Khadijah – Session Management
- [x] Ensure users stay logged in after OTP verification using secure sessions.
- [x] Implement logout functionality to terminate user sessions.
- [x] Test for session persistence after login.

### 👨‍💻 Nibras – Testing and Debugging
- [x] Perform functional testing of the complete system (user registration, login, OTP).
- [x] Conduct security testing to check for vulnerabilities.
- [x] Perform usability testing to ensure the interface is user-friendly.
- [x] Write test cases for all main features to ensure robustness.

---

# Final Deliverables

1. **Code Repository:**
   - [x] Provide all source code with comments and documentation.
   - [x] Ensure the repository is hosted on GitHub or similar with clear setup instructions in a README.

2. **Written Report:**
   - [x] **Husnain:** Document system architecture and database design.
   - [x] **Isma:** Explain security measures implemented (bcrypt, OTP, rate limiting, etc.).
   - [x] **Khadijah:** Write about challenges faced during email integration and database management.
   - [x] **Nibras:** Document the testing process, including security and functional tests.

3. **Live Demonstration:**
   - [x] Demonstrate the full functionality of the system.
   - [x] Show the OTP authentication process by sending and verifying OTP in real-time.
