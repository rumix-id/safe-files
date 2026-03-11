# 🛡️ Safe.Files Protecting Tool

Safe.Files is a CLI (Command Line Interface)-based application designed to secure various file types using industry-standard Argon2id + AES-256-GCM (Authenticated Encryption). It is built in Go for maximum speed and reliability.

## ✨ Key Features
* High-Level Security: Uses the Argon2id + AES-256-GCM algorithm to ensure data confidentiality and integrity.
* Automatic Format Recovery: Automatically restores the original file name and extension (such as .pdf, .docx, .jpg) after decryption.
* Encrypted Database: Stores recovery codes and metadata in a protected `system.db` database.
* Unique Recovery Log: Generates a recovery text file in the `recovery/` folder with a unique, time-stamped name to prevent overwriting previous logs.

## 🚀 Technical Details
* **Version:** 2.0.0-Update
* **Language:** Go (Golang)
* **Algorithm:** Argon2id + AES-256-GCM
* **Platform:** Windows

## 📂 Folder Program
This program automatically manages the following directories:
* **`enc/`**: Where encrypted files are stored.
* **`dec/`**: Where decrypted files are stored (returned to their original format).
* **`recovery/`**: Contains text logs for password recovery.
* **`db/`**: Location of encrypted system databases.

## 🛠️ How to Build (With Icon & Version)
This project uses `go-winres` to include icon and version information in the `.exe` file.

1. **Prepare Resources:**
Make sure the `winres/` folder contains `winres.json` and your icon image file.
2. **if go.mod is having problems**
```go
go mod tidy
```
3. **Generate Resource Object:**
```go
go-winres make
```
4. **Compile to EXE:**
```go
go build
```
## 📂 Folder Structure
```text
safe-files
├── winres     # Windows Resource files (icon, application metadata, manifest)
├── LICENSE    # Software usage license
├── README.md  # Main project documentation
├── go.mod     # Go module definitions and project dependencies
├── go.sum     # Security checksums for Go dependencies
├── safe-files.exe   # Executable (binary) build file for Windows
└── safe.files.go    # Main Go application source code
```
