package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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
	"golang.org/x/crypto/argon2"
)

var (
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()
	dbKey  = []byte("Rumix-id-Secure-Internal-DB-K3y!")
	reader = bufio.NewReader(os.Stdin)
)

const (
	timeCost   = 1
	memoryCost = 64 * 1024
	threads    = 4
	keyLen     = 32
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
	fmt.Println("\n   Safe.Files Protecting Tool by Rumix-id   ")
	fmt.Println("----------------------------------------------")
	fmt.Println("        Argon2id + AES-256-GCM                ")
	fmt.Println()
}

func handleEncryption() {
	fmt.Println("\n[ Argon2id + AES-256-GCM ] Encryption")
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
	rawInput := readString()
	if rawInput == "" {
		fmt.Println(red("You must enter a password!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Deriving Key with Argon2id... ]")

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		fmt.Println(red("Gagal membuat salt!"))
		return
	}

	passHash := argon2.IDKey([]byte(rawInput), salt, timeCost, memoryCost, threads, keyLen)

	// Zeroing RAM: Poin 5
	rawInputBytes := []byte(rawInput)
	for i := range rawInputBytes {
		rawInputBytes[i] = 0
	}

	passwordHex := hex.EncodeToString(passHash)
	fmt.Printf("This is an encrypted password : %s\n", passwordHex)

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
	stop := make(chan bool, 1)
	go loadingAnimation("...", stop)

	origFileName := filepath.Base(filePath)
	err = encryptFileStream(filePath, destPath, passHash, salt, origFileName, recovery)
	stop <- true

	if err != nil {
		fmt.Printf("\n%s: %v\n", red("Encryption failed"), err)
	} else {
		fmt.Println(green("\nDone, Your file has been secured and encrypted."))
		openExplorer("enc")
	}
	pressEnterToReturn()
}

func handleDecryption() {
	fmt.Println("\n[ Argon2id + AES-256-GCM ] Decryption")
	fmt.Println("Please select the file to be decrypted - Open File Explorer")

	absEnc, _ := filepath.Abs("enc")
	filePath, err := dialog.File().SetStartDir(absEnc).Title("Select File to Decrypt").Load()
	if err != nil || filePath == "" {
		return
	}

	fmt.Println("\n[ Target Location Files ]")
	fmt.Println(yellow(filePath))

	fmt.Println("\n[ Enter Password ]")
	fmt.Println("Hint: Enter the Encrypted Hash you received during encryption")
	fmt.Print("Enter your file password (Hash): ")
	password := readString()

	if password == "" {
		fmt.Println(red("You must enter the hash!"))
		pressEnterToReturn()
		return
	}

	fmt.Println("\n[ Decryption Process ]")
	stop := make(chan bool, 1)
	go loadingAnimation("...", stop)

	err = decryptFileStream(filePath, password)
	stop <- true // Pastikan loading dimatikan sebelum pesan error muncul

	if err != nil {
		fmt.Printf("\n%s: %v\n", red("Decryption failed"), err)
	} else {
		fmt.Println(green("\nDone, Your file has been decrypted successfully."))
		openExplorer("dec")
	}
	pressEnterToReturn()
}

func handleRecovery() {
	fmt.Println("\n[ Password Recovery ]")
	fmt.Println("Please select the file for recovery - Open File Explorer")

	absEnc, _ := filepath.Abs("enc")
	filePath, err := dialog.File().SetStartDir(absEnc).Title("Select File for Recovery").Load()
	if err != nil || filePath == "" {
		return
	}

	fmt.Println("\n[ Target Location Files ]")
	fmt.Println(yellow(filePath))

	fmt.Print("\n[ Enter Recovery Code ]\nEnter your recovery code: ")
	recoveryCodeInput := readString()

	fmt.Println("\n[ Recovery Process ]")
	stop := make(chan bool, 1)
	go loadingAnimation("Searching database", stop)

	dbPath := filepath.Join("db", "system.db")
	content, err := os.ReadFile(dbPath)
	stop <- true

	if err != nil {
		fmt.Println(red("\nDatabase not found!"))
		pressEnterToReturn()
		return
	}

	decDB, err := decryptInternal(content)
	if err != nil {
		fmt.Println(red("\nDatabase error!"))
		pressEnterToReturn()
		return
	}
	var data map[string]interface{}
	json.Unmarshal(decDB, &data)

	fileNameOnly := filepath.Base(filePath)

	if entry, ok := data[fileNameOnly].(map[string]interface{}); ok {
		if recoveryCodeInput == entry["code"].(string) {
			fmt.Println(green("\nCongratulations! Password recovery successful."))
			fmt.Printf("\nYour Hash: %s\n", yellow(entry["pass"].(string)))

			dt := time.Now()
			recFileName := fmt.Sprintf("rec-%s.txt", fileNameOnly)
			recContent := fmt.Sprintf("File: %s\nHash: %s\nDate: %s", fileNameOnly, entry["pass"].(string), dt.Format("2006-01-02 15:04:05"))
			_ = os.WriteFile(filepath.Join("recovery", recFileName), []byte(recContent), 0644)
			fmt.Println(green("Info saved in 'recovery' folder."))
			openExplorer("recovery")
		} else {
			fmt.Println(red("\nIncorrect recovery code!"))
		}
	} else {
		fmt.Println(red("\nFile not recognized!"))
	}
	pressEnterToReturn()
}

func encryptFileStream(src, dst string, key, salt []byte, origName, recovery string) error {
	inFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	outFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Header: Nonce (12) + Salt (16)
	outFile.Write(nonce)
	outFile.Write(salt)

	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	// Gabungkan nama asli ke dalam enkripsi
	dataWithHeader := append([]byte(origName+"|"), plaintext...)
	ciphertext := gcm.Seal(nil, nonce, dataWithHeader, nil)

	if _, err := outFile.Write(ciphertext); err != nil {
		return err
	}

	return updateDB(filepath.Base(dst), recovery, hex.EncodeToString(key))
}

func decryptFileStream(src, passHex string) error {
	inFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inFile.Close()

	key, err := hex.DecodeString(passHex)
	if err != nil {
		return fmt.Errorf("invalid hash format")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ns := gcm.NonceSize()
	nonce := make([]byte, ns)
	if _, err := io.ReadAtLeast(inFile, nonce, ns); err != nil {
		return fmt.Errorf("missing nonce")
	}

	salt := make([]byte, 16)
	if _, err := io.ReadAtLeast(inFile, salt, 16); err != nil {
		return fmt.Errorf("missing salt")
	}

	ciphertext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("incorrect password or corrupted data")
	}

	// Zeroing RAM key
	for i := range key {
		key[i] = 0
	}

	parts := strings.SplitN(string(decrypted), "|", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid file header")
	}

	return os.WriteFile(filepath.Join("dec", parts[0]), []byte(parts[1]), 0644)
}

func updateDB(fileName, recovery, pass string) error {
	dbPath := filepath.Join("db", "system.db")
	data := make(map[string]interface{})

	if content, err := os.ReadFile(dbPath); err == nil {
		dec, err := decryptInternal(content)
		if err == nil {
			json.Unmarshal(dec, &data)
		}
	}
	data[fileName] = map[string]string{"code": recovery, "pass": pass}
	jsonData, _ := json.Marshal(data)
	enc, _ := encryptInternal(jsonData)
	return os.WriteFile(dbPath, enc, 0644)
}

func encryptInternal(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dbKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptInternal(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dbKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("db too small")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

// UTILS
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
		os.MkdirAll(f, 0755)
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
	fmt.Println("\n" + white("Thank you for using Rumix Tools!"))
	time.Sleep(1 * time.Second)
	os.Exit(0)
}
