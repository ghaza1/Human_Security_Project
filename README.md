# ? Secure Library Management System

> A modern, secure, and lightweight SaaS-style application for managing library resources and confidential notes, powered by robust Role-Based Access Control (RBAC).

![Project Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/Security-OIDC%20%2F%20PKCE-blue)
![Backend](https://img.shields.io/badge/Backend-Flask-lightgrey)

## ? Overview

The **Secure Library Management System** is a full-stack application designed to demonstrate secure human security management principles. It moves away from complex command-line interfaces to a clean, user-friendly **Web Dashboard**.

The system integrates **Keycloak** for industry-standard Identity and Access Management (IAM), ensuring that only authorized personnel can access sensitive data. It utilizes **PKCE (Proof Key for Code Exchange)** for secure, client-side authentication without exposing client secrets.

## ? Key Features

* **? Enterprise-Grade Security:**
    * **OIDC Authentication:** Seamless login/logout using Keycloak.
    * **PKCE Flow:** Secure token exchange directly in the browser.
    * **Session Management:** Automatic session expiry and secure token storage.

* **?? Role-Based Access Control (RBAC):**
    * **Viewer:** Read-only access to books and notes.
    * **Editor:** Ability to add new books and notes.
    * **Admin:** Full control, including deleting records.

* **? Modern UI/UX:**
    * **Clean Interface:** Minimalist "SaaS" style design using CSS variables and Flexbox.
    * **Dynamic Dashboard:** The UI automatically adjusts based on your user role (hiding/showing buttons).
    * **Responsive:** Works seamlessly on desktop and mobile.

* **? Backend API:**
    * **Python Flask:** Lightweight and fast REST API.
    * **Secure Endpoints:** All API routes are protected by JWT (JSON Web Token) verification.

## ?? Tech Stack

* **Frontend:** HTML5, CSS3 (Custom SaaS Theme), JavaScript (Vanilla ES6+)
* **Backend:** Python 3, Flask, Flask-CORS
* **Security:** Keycloak (Identity Provider), OpenID Connect (OIDC)
* **Database:** In-memory JSON storage (for demonstration purposes)

## ? The Team

This project was built with ?? by:

* **Ahmed Ghazal**
* **Mohamed Essam**
* **Mohamed Elsharkawy**
* **Mohamed Sherif**
* **Kerolous Nasser**
* **Ahmed Haitham**

---

## ? Getting Started

Follow these instructions to get the project up and running on your local machine.

### Prerequisites

* Python 3.x installed
* Keycloak Server running (Port 8081)
* A modern web browser

### 1. Backend Setup

1.  Navigate to the project folder.
2.  Install required Python packages:
    ```bash
    pip install flask flask-cors python-keycloak
    ```
3.  Start the Flask server:
    ```bash
    python app.py
    ```
    *Terminal should output:* `Running on http://127.0.0.1:5000`

### 2. Frontend Setup

1.  Open `index.html` in your browser.
    * *Tip:* For the best experience, use a live server (e.g., VS Code Live Server) or simply double-click the file.
2.  Ensure your browser is not blocking pop-ups for the login redirect.

### 3. Keycloak Configuration (Brief)

* **Realm:** `secured-library`
* **Client ID:** `frontend-client`
* **Web Origins:** `*` (or your specific frontend URL)
* **Roles:** Create roles like `read_only`, `crud_no_delete`, and `full_crud`.

---

## ? Usage Guide

1.  **Login:** Click the "Authenticate" button on the landing page. You will be redirected to the Keycloak login page.
2.  **Dashboard:** Once logged in, you will see the Dashboard.
    * **Books:** View the library catalog.
    * **Notes:** View secure notes.
3.  **Actions (Based on Role):**
    * If you are an **Admin**, you will see forms to "Add Book" and "Add Note", and red "Delete" buttons next to items.
    * If you are a **Viewer**, you will only see the lists.
4.  **Logout:** Click "Logout" in the top right to end your session securely.

## ? Screenshots

*(Add screenshots of your Landing Page and Dashboard here)*

---

## ? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
