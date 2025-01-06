#  Claims Management System

## Project Overview

This project is a **Flask-based web application** designed for managing user claims. It features a **login system**, **user registration**, and **claim submission** functionalities. Users can submit claims, and administrators can view and manage them. The system uses **Flask-Login** for user authentication and **Flask-SQLAlchemy** for database management, with **Flask-Migrate** to handle database migrations.

---

## Features

- **User Authentication**: Secure login and registration using hashed passwords.
- **Role-Based Access**: Distinction between regular users and administrators.
  - Regular users can submit and view their own claims.
  - Admin users can view and manage all claims.
- **Claim Submission**: Users can submit claims with descriptions and track their status.
- **Admin Dashboard**: Admins can view all submitted claims and update their statuses.

## Prerequisites

To run this project, you'll need the following:

- **Python 3.8+**
- **Flask** (Python web framework)
- **Flask-SQLAlchemy** (Database ORM)
- **Flask-Migrate** (Database migration support)
- **Flask-Login** (User authentication management)
- **SQLite** (Default database used in the project, replaceable with any supported SQL database)

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/flask-claims-management-system.git
    cd flask-claims-management-system
    ```

2. **Set up a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Initialize the SQLite database**:
    ```bash
    flask db init
    flask db migrate
    flask db upgrade
    ```

5. **Run the application**:
    ```bash
    python app.py
    ```

6. **Access the app**:
   - Open your browser and go to `http://127.0.0.1:5000/`.

## Project Structure


