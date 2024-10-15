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
- [ ] Install and configure SQLite.
- [ ] Create the project database.
- [ ] Ensure Flask is connected to the SQLite database.

### 👩‍💻 Khadijah – Database Schema Definition
- [ ] Define the `users` table schema:
  - [ ] Columns: `user_id` (primary key), `username`, `email`, `hashed_password`, `registration_date`.
- [ ] Define the `sessions` table schema:
  - [ ] Columns: `session_id`, `user_id` (foreign key), `session_token`, `expires_at`.

### 👨‍💻 Nibras – Initial Testing and Validation
- [ ] Test SQLite database connection with Flask.
- [ ] Implement a basic user registration form to insert data into the `users` table.
- [ ] Ensure tables and fields are correctly created.

---

## Deliverable 2: Backend Development for User Registration and Login
**Goal**: Implement secure user registration, password storage, and user login.

### 👨‍💻 Husnain – User Registration
- [ ] Implement a form to register users (username, email, password).
- [ ] Validate user inputs (e.g., valid email, strong password).
- [ ] Verify email address through a confirmation link sent to the user’s email.

### 👩‍💻 Isma – Secure Password Storage
- [ ] Implement password hashing using bcrypt.
- [ ] Ensure passwords are securely stored using salt and appropriate hashing techniques.
- [ ] Test password storage by registering a few test users.

### 👩‍💻 Khadijah – User Login System
- [ ] Implement user login form (username and password).
- [ ] Authenticate users using stored hashed passwords (compare hashed versions).
- [ ] Set up error handling for incorrect login attempts.

### 👨‍💻 Nibras – Database Integration for Registration/Login
- [ ] Implement database interactions for both registration and login (store/retrieve user data).
- [ ] Store user details (hashed password) and email confirmation status in the database.
- [ ] Test the login process using multiple test users.

---

## Deliverable 3: OTP Generation, Email Integration, and Two-Factor Authentication (2FA)
**Goal**: Implement OTP-based two-factor authentication (2FA) using email.

### 👨‍💻 Husnain – OTP Generation
- [ ] Implement a secure OTP generation system.
- [ ] Generate a random OTP with a set expiration time (e.g., 5 minutes).
- [ ] Ensure that OTPs are unique for each request.

### 👩‍💻 Isma – Email Integration for OTP
- [ ] Integrate smtplib for sending OTP via email.
- [ ] Configure SMTP settings securely in Flask to send the OTP.
- [ ] Test email sending with a free SMTP provider (e.g., Gmail).

### 👩‍💻 Khadijah – OTP Verification
- [ ] Create a form where users can enter the OTP they received via email.
- [ ] Implement verification of OTP, checking the expiry time.
- [ ] Allow users to request a new OTP if the original expires.

### 👨‍💻 Nibras – OTP Session Management
- [ ] Store OTPs in the database alongside the user session.
- [ ] Manage session state during login and OTP verification.
- [ ] Implement error handling for incorrect OTP entries and expired OTPs.

---

## Deliverable 4: Frontend, Security Enhancements, and Final Testing
**Goal**: Finalize the frontend interface, add security features, and conduct extensive testing.

### 👨‍💻 Husnain – Frontend Development
- [ ] Create a simple user interface for registration, login, and OTP verification using HTML/CSS.
- [ ] Implement secure forms with validation (e.g., email format, password strength).
- [ ] Optional: Use Bootstrap for enhanced styling and layout.

### 👩‍💻 Isma – Security Features
- [ ] Implement rate limiting for login attempts and OTP requests (using Flask-Limiter).
- [ ] Secure the application against common vulnerabilities like SQL injection, CSRF, and XSS.
- [ ] Use secure cookies for session management.

### 👩‍💻 Khadijah – Session Management
- [ ] Ensure users stay logged in after OTP verification using secure sessions.
- [ ] Implement logout functionality to terminate user sessions.
- [ ] Test for session persistence after login.

### 👨‍💻 Nibras – Testing and Debugging
- [ ] Perform functional testing of the complete system (user registration, login, OTP).
- [ ] Conduct security testing to check for vulnerabilities.
- [ ] Perform usability testing to ensure the interface is user-friendly.
- [ ] Write test cases for all main features to ensure robustness.

---

# Final Deliverables

1. **Code Repository:**
   - [ ] Provide all source code with comments and documentation.
   - [ ] Ensure the repository is hosted on GitHub or similar with clear setup instructions in a README.

2. **Written Report:**
   - [ ] **Husnain:** Document system architecture and database design.
   - [ ] **Isma:** Explain security measures implemented (bcrypt, OTP, rate limiting, etc.).
   - [ ] **Khadijah:** Write about challenges faced during email integration and database management.
   - [ ] **Nibras:** Document the testing process, including security and functional tests.

3. **Live Demonstration:**
   - [ ] Demonstrate the full functionality of the system.
   - [ ] Show the OTP authentication process by sending and verifying OTP in real-time.
