# 🛡️ Safe.Files Protecting Tool v1.0.0

Safe.Files is a CLI (Command Line Interface)-based application designed to secure various file types using industry-standard AES-256 GCM (Authenticated Encryption). It is built in Go for maximum speed and reliability.

## ✨ Key Features
* High-Level Security: Uses the AES-256 GCM algorithm to ensure data confidentiality and integrity.
* Automatic Format Recovery: Automatically restores the original file name and extension (such as .pdf, .docx, .jpg) after decryption.
* Encrypted Database: Stores recovery codes and metadata in a protected `system.db` database.
* Unique Recovery Log: Generates a recovery text file in the `recovery/` folder with a unique, time-stamped name to prevent overwriting previous logs.

## 🚀 Technical Details
* **Version:** 1.0.0-stable
* **Language:** Go (Golang)
* **Algorithm:** AES-256-GCM
* **Platform:** Windows (Optimized with Version Info & Icon)

## 📂 Folder Structure
This program automatically manages the following directories:
* **`enc/`**: Where encrypted files are stored.
* **`dec/`**: Where decrypted files are stored (returned to their original format).
* **`recovery/`**: Contains text logs for password recovery.
* **`db/`**: Location of encrypted system databases.

## 🛠️ How to Build (With Icon & Version)
This project uses `go-winres` to include icon and version information in the `.exe` file.

1. **Prepare Resources:**
Make sure the `winres/` folder contains `winres.json` and your icon image file.
2. **Generate Resource Object:**
```go
go-winres make
```
3. **Compile to EXE:**
```go
go build
```
