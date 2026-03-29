# Registration & Email Verification

## Overview

To use **WebSecScan**, a user must register an account and verify their email address.

Email verification is implemented using **Mailtrap**, which captures outgoing emails during development instead of sending real emails.

To avoid access and verification issues during evaluation, a **dummy Gmail account** was created and linked to the shared Mailtrap account.

---

## Dummy Gmail & Mailtrap Setup (Important)

A **dummy Gmail account** was created and used to register the Mailtrap account.

This is important because:

- Mailtrap may require an **email verification code** when logging in from a new device
- The verification code is sent to the **email address used for Mailtrap login**
- The User may be using a different laptop/device

By sharing **both the Mailtrap credentials AND the Gmail credentials**, the User can always access the verification code if required.

---

## Shared Access Credentials

### Dummy Gmail Account

This Gmail account receives Mailtrap verification codes if Mailtrap asks for email confirmation.

- **Gmail Address:** testuser16666@gmail.com  
- **Gmail Password:** Testuser1234@

---

### Mailtrap Account

All verification emails sent by WebSecScan arrive in this Mailtrap inbox.

- **Website:** https://mailtrap.io/  
- **Login Email:** testuser16666@gmail.com  
- **Password:** Testuser1234@

> If Mailtrap asks for a verification code, simply log in to Gmail using the same credentials and retrieve the code.

---

## Step-by-Step Registration Guide

### 1. Create an Account on WebSecScan

1. Open the application in your browser:    http://localhost:3000

2. Navigate to the **Registration** page.

3. Fill out the registration form:
- **Email:** any valid format (e.g. `user@example.com`)
- **Username:** choose any username
- **Password:** choose any password

4. Click **Register**.

The account is created but **not active yet**.

---

### 2. Open Mailtrap to Verify Email

1. Open https://mailtrap.io/
2. Log in using the shared Mailtrap credentials
3. If Mailtrap requests email verification:
- Log in to Gmail using the dummy Gmail credentials
- Copy the verification code from the email
- Complete the Mailtrap login
4. Navigate to **Email Testing → Inboxes**
5. Open the inbox

You will see the verification email sent by WebSecScan.

---

### 3. Verify the WebSecScan Account

1. Open the verification email inside Mailtrap
2. Copy the **verification link**
3. Paste the link into your browser and open it

A confirmation message will appear indicating that the account has been successfully verified.

---

### 4. Log In

1. Go back to:  http://localhost:3000

2. Open the **Login** page

3. Enter:
- **Username:** the registered username
- **Password:** the registered password

4. Click **Login**

You are now logged in and can:
- Perform web security scans
- View scan history

---

## Notes

- Mailtrap is used **only for development and evaluation**
- No real emails are sent to external addresses
- All verification emails arrive in the same Mailtrap inbox
- The dummy Gmail account guarantees Mailtrap access from any device
- Email verification is mandatory before login

---