# 🔐 SecurePass-Manager (C++)

A secure and user-friendly **Console-Based Password Manager** developed in **C++** that allows users to securely store and manage credentials for multiple accounts. The application provides user authentication, password strength analysis, email validation, and file-based data persistence.

---

## 📖 Overview

This project is designed to help users manage their login credentials for different platforms from a single application. Each registered user has their own encrypted storage file (basic file-based storage), allowing credentials to remain separated and organized.

The project demonstrates concepts of:

- Object-Oriented Programming (OOP)
- File Handling
- Data Structures (Vector)
- Regular Expressions (Regex)
- User Authentication
- Password Validation
- CRUD Operations

---

## ✨ Features

- 👤 User Registration
- 🔑 User Login Authentication
- ➕ Add New Account Credentials
- ✏️ Update Existing Passwords
- ❌ Delete Saved Accounts
- 🔍 Search Saved Credentials
- 📋 Display All Saved Credentials
- 📧 Email Address Validation using Regex
- 🔒 Password Strength Checker
- 💾 Automatic Data Saving
- 📂 Separate Storage File for Every User

---

## 🛠️ Tech Stack

- Language: C++
- STL (Standard Template Library)
- File Handling (`fstream`)
- Regular Expressions (`regex`)
- Object-Oriented Programming (OOP)

---

## 📁 Project Structure

```
SecurePass-Manager/
│
├── SecurePass-Manager.cpp
├── username.txt          # Created automatically for each registered user
└── README.md
```

---

## ⚙️ How It Works

### 1. Register

- Create a new account
- Username becomes the filename
- Credentials are stored locally

### 2. Login

- Enter username
- Enter password
- Access your password vault

### 3. Password Vault

After login, users can:

- Add credentials
- Update passwords
- Delete credentials
- Search credentials
- Display all stored accounts
- Logout

---

## 🔐 Password Strength Rules

The application evaluates passwords based on:

- Minimum 8 characters
- Uppercase letter
- Lowercase letter
- Numeric digit
- Special character

Password strength is classified as:

- 🟢 Strong
- 🟡 Medium
- 🔴 Weak

---

## 📧 Email Validation

When the account type is:

- Gmail
- Email

The application validates the entered email address using **Regular Expressions (Regex)** before saving.

---

## 💾 Data Storage

All user data is stored in text files.

Example:

```
Yash.txt
```

Each file stores:

- Login Username
- Login Password
- Saved Accounts
- Account Passwords
- Account Type

---

## 🚀 How to Run

### Compile

```bash
g++ main.cpp -o PasswordManager
```

### Execute

Linux/macOS

```bash
./PasswordManager
```

Windows

```bash
PasswordManager.exe
```

---

## 📷 Console Menu

### Login Menu

```
1. Register
2. Login
3. Exit
```

### Main Menu

```
1. Add User
2. Delete User
3. Update User
4. Display Users
5. Search User
6. Logout
```

---

## 🎯 Concepts Used

- Classes & Objects
- Structures
- Operator Overloading
- Vectors
- File Handling
- Regex
- Functions
- Input Validation
- Password Security
- CRUD Operations

---

## 🔮 Future Improvements

- AES Encryption
- Password Generator
- Password Masking
- Hide Password While Typing
- Master Password Recovery
- SQLite/MySQL Database Integration
- GUI using Qt
- Cross-platform Support
- Export/Import Passwords
- Two-Factor Authentication (2FA)

---

## 📚 Learning Outcomes

Through this project, I gained hands-on experience with:

- C++ Object-Oriented Programming
- File Management
- User Authentication
- Data Validation
- Password Security Concepts
- Regular Expressions
- STL Containers
- Console Application Development

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

---

## 📄 License

This project is intended for educational and learning purposes.

---

## 👨‍💻 Author

**Yash Kumawat**

MCA Student | AI & Machine Learning Enthusiast | C++ Developer

GitHub: [https://github.com/yashiscoder]
Website: [https://yashkmt.netlify.app/]
