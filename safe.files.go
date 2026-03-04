package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sqweek/dialog"
)

var (
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()
	dbKey  = []byte("Rumix-id-Secure-Internal-DB-K3y!")
	reader = bufio.NewReader(os.Stdin)
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n%s %v\n", red("[FATAL ERROR]:"), r)
			fmt.Print("Press Enter to restart the program...")
			reader.ReadString('\n')
			main()
		}
	}()

	initFolders()
	for {
		clearScreen()
		showBanner()
		fmt.Println("1. Encrypt Files")
		fmt.Println("2. Decrypt Files")
		fmt.Println("3. Password Recovery")
		fmt.Println("4. Exit")
		fmt.Print("\nSelect Option: ")

		choice := readString()

		switch choice {
		case "1":
			handleEncryption()
		case "2":
			handleDecryption()
		case "3":
			handleRecovery()
		case "4":
			handleExit()
		}
	}
}

func showBanner() {
	fmt.Println(white(` ____          __        _____ _ _           
/ ___|  __ _ / _| ___  |  ___(_) | ___  ___ 
\___ \ / _` + "`" + ` | |_ / _ \ | |_  | | |/ _ \/ __|
 ___) | (_| |  _|  __/_|  _| | | |  __/\__ \
|____/ \__,_|_|  \___(_)_|   |_|_|\___||___/`))
	fmt.Println("\n      Safe.Files Protecting Tool by Rumix-id")
	fmt.Println("----------------------------------------------")
	fmt.Println("Encryption and Decryption Using AES-GCM Security")
	fmt.Println()
}

func handleEncryption() {
	fmt.Println("\n[ AES-GCM ] Encryption")
	fmt.Println("Please select the files to be encrypted - Open File Explorer")

	filePath, err := dialog.File().Title("Select File").Load()
	if err != nil || filePath == "" {
		fmt.Println(red("\nWarning: Action canceled by user!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Target Location Files ]")
	fmt.Println(yellow(filePath))

	fmt.Print("\n[ Add Password ]\nAdd password for your file : ")
	rawPassword := readString()
	if rawPassword == "" {
		fmt.Println(red("You must enter a password!"))
		pressEnterToReturn()
		return
	}

	// Membuat hash dari password asli untuk dijadikan kunci utama
	passHash := sha256.Sum256([]byte(rawPassword))
	password := fmt.Sprintf("%x", passHash)
	fmt.Printf("This is an encrypted password : %s\n", password)

	fmt.Println("\n[ Additional for Recovery ]")
	fmt.Println("This is the recovery password, use a unique word or code that is easy to remember.")
	fmt.Print("You are free to enter any text: ")
	recovery := readString()

	fmt.Print("\n[ File Format Name ]\nEnter the name and format for your file (e.g., sample.sky): ")
	outName := readString()
	if outName == "" || !strings.Contains(outName, ".") {
		fmt.Println(red("Invalid file format!"))
		pressEnterToReturn()
		return
	}

	destPath := filepath.Join("enc", outName)

	fmt.Println("\n[ Encryption Process ]")
	stop := make(chan bool)
	go loadingAnimation("...", stop)

	origFileName := filepath.Base(filePath)
	err = encryptFile(filePath, destPath, password, origFileName, recovery)
	stop <- true

	if err != nil {
		fmt.Printf("\n%s\n", red("Encryption failed: File already exists or access denied."))
	} else {
		fmt.Println(green("\nDone, Your file has been secured and encrypted."))
		openExplorer("enc")
	}
	pressEnterToReturn()
}

func handleDecryption() {
	fmt.Println("\n[ AES-GCM ] Decryption")
	fmt.Println("Please select the file to be decrypted - Open File Explorer")
	fmt.Println("Wait...")

	absEnc, _ := filepath.Abs("enc")
	filePath, err := dialog.File().SetStartDir(absEnc).Title("Select File to Decrypt").Load()
	if err != nil || filePath == "" {
		fmt.Println(red("\nWarning: Action canceled!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Target Location Files ]")
	fmt.Println(yellow(filePath))

	fmt.Println("\n[ Enter Password ]")
	fmt.Println("Hint: Ctrl + V or Right Click to paste password")
	fmt.Print("Enter your file password (Encrypted Hash): ")
	password := readString()

	if password == "" {
		fmt.Println(red("You must enter the encrypted hash!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Decryption Process ]")
	stop := make(chan bool)
	go loadingAnimation("...", stop)

	err = decryptFile(filePath, password)
	stop <- true

	if err != nil {
		fmt.Println(red("\nYour password is incorrect!"))
		fmt.Println(red("Decryption failed."))
	} else {
		fmt.Println(green("\nDone, Your file has been decrypted successfully."))
		openExplorer("dec")
	}
	pressEnterToReturn()
}

func handleRecovery() {
	fmt.Println("\n[ Password Recovery ]")
	fmt.Println("Please select the file for recovery - Open File Explorer")
	fmt.Println("Wait...")

	absEnc, _ := filepath.Abs("enc")
	filePath, err := dialog.File().SetStartDir(absEnc).Title("Select File for Recovery").Load()
	if err != nil || filePath == "" {
		fmt.Println(red("\nWarning: Action canceled!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Target Location Files ]")
	fmt.Println(yellow(filePath))

	fmt.Print("\n[ Enter Recovery Code ]\nEnter your recovery code: ")
	recoveryCodeInput := readString()

	fmt.Println("\n[ Recovery Process ]")
	stop := make(chan bool)
	go loadingAnimation("Searching the database.", stop)
	time.Sleep(1 * time.Second)

	dbPath := filepath.Join("db", "system.db")
	content, err := os.ReadFile(dbPath)
	stop <- true

	if err != nil {
		fmt.Println(red("\nDatabase not found! Password recovery failed."))
		pressEnterToReturn()
		return
	}

	decDB, _ := decryptInternal(content)
	var data map[string]interface{}
	json.Unmarshal(decDB, &data)

	fileNameOnly := filepath.Base(filePath)

	if entry, ok := data[fileNameOnly].(map[string]interface{}); ok {
		savedCode := entry["code"].(string)
		originalPass := entry["pass"].(string)

		if recoveryCodeInput == savedCode {
			fmt.Println("\n[ Password Recovered Successfully ]")
			fmt.Println(green("Congratulations! Password recovery successful."))

			dt := time.Now()
			recFileName := fmt.Sprintf("rec-%s %d-%d-%d.txt", fileNameOnly, dt.Day(), int(dt.Month()), dt.Year()%100)
			recContent := fmt.Sprintf("File Name: %s\nOriginal Password (Hash): %s\nRecovery Date: %s", fileNameOnly, originalPass, dt.Format("2006-01-02 15:04:05"))
			_ = os.WriteFile(filepath.Join("recovery", recFileName), []byte(recContent), 0644)

			openExplorer("recovery")
		} else {
			fmt.Println(red("\nIncorrect recovery code! Password recovery failed."))
		}
	} else {
		fmt.Println(red("\nFile not recognized in the database! Password recovery failed."))
	}
	pressEnterToReturn()
}

// --- CORE ENGINE ---

func encryptFile(src, dst, pass, origName, recovery string) error {
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Menggunakan string pass (hash) secara langsung sebagai key
	key := sha256.Sum256([]byte(pass))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	dataWithHeader := append([]byte(origName+"|"), plaintext...)
	ciphertext := gcm.Seal(nonce, nonce, dataWithHeader, nil)

	updateDB(filepath.Base(dst), recovery, pass)
	return os.WriteFile(dst, ciphertext, 0644)
}

func decryptFile(src, pass string) error {
	ciphertext, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Menggunakan string pass (hash) secara langsung
	key := sha256.Sum256([]byte(pass))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, _ := cipher.NewGCM(block)

	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return fmt.Errorf("invalid file structure")
	}

	nonce, ciphertext := ciphertext[:ns], ciphertext[ns:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err // Gagal jika input bukan hash yang benar
	}

	parts := strings.SplitN(string(decrypted), "|", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid header format")
	}

	origName := parts[0]
	actualContent := []byte(parts[1])

	return os.WriteFile(filepath.Join("dec", origName), actualContent, 0644)
}

func updateDB(fileName, recovery, pass string) error {
	dbPath := filepath.Join("db", "system.db")
	data := make(map[string]interface{})

	if content, err := os.ReadFile(dbPath); err == nil {
		dec, _ := decryptInternal(content)
		json.Unmarshal(dec, &data)
	}

	data[fileName] = map[string]string{
		"code": recovery,
		"pass": pass,
	}

	jsonData, _ := json.Marshal(data)
	enc, _ := encryptInternal(jsonData)
	return os.WriteFile(dbPath, enc, 0644)
}

func encryptInternal(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(dbKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptInternal(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(dbKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("database corrupted")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

// --- UTILS ---

func readString() string {
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func pressEnterToReturn() {
	fmt.Print("\nPress Enter to return to the menu")
	reader.ReadString('\n')
}

func initFolders() {
	folders := []string{"enc", "dec", "recovery", "db"}
	for _, f := range folders {
		os.MkdirAll(f, os.ModePerm)
	}
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		exec.Command("cls").Run()
	} else {
		exec.Command("clear").Run()
	}
}

func loadingAnimation(text string, stop chan bool) {
	msgs := []string{".  ", ".. ", "...", "   "}
	i := 0
	for {
		select {
		case <-stop:
			fmt.Print("\r")
			return
		default:
			fmt.Printf("\rPlease Wait... %s %s", text, msgs[i%4])
			i++
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func openExplorer(path string) {
	abs, _ := filepath.Abs(path)
	if runtime.GOOS == "windows" {
		exec.Command("explorer", abs).Start()
	}
}

func handleExit() {
	fmt.Println("\n" + white("Thank you for using Safe.Files Protecting Tool!"))
	time.Sleep(1 * time.Second)
	os.Exit(0)
}
