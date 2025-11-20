package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dim13/otpauth/migration"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp/totp"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	storeFileName = ".otpcli.dat"
	scryptN       = 32768
	scryptR       = 8
	scryptP       = 1
	keyLen        = 32
	saltLen       = 16
)

// Account represents a stored OTP entry
type Account struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Secret string `json:"secret"` // Stored as Base32 string
}

func main() {
	app := &cli.App{
		Name:  "otpcli",
		Usage: "A CLI tool for Google Authenticator OTP codes",
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return cli.ShowAppHelp(c)
			}
			return runListCodes()
		},
		Commands: []*cli.Command{
			{
				Name:      "setup",
				Usage:     "Import accounts from a Google Authenticator QR code image",
				ArgsUsage: "<path_to_image>",
				Action:    runSetup,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runSetup(c *cli.Context) error {
	imagePath := c.Args().First()
	if imagePath == "" {
		return errors.New("please provide a path to the QR code image")
	}

	fmt.Printf("Reading image: %s...\n", imagePath)
	migrationURL, err := decodeQRCode(imagePath)
	if err != nil {
		return fmt.Errorf("failed to decode QR code: %w", err)
	}

	fmt.Println("Parsing migration data...")

	parts := strings.Split(migrationURL, "data=")
	if len(parts) < 2 {
		return errors.New("invalid migration URL: missing 'data' parameter")
	}
	dataStr := parts[1]

	dataBytes, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return fmt.Errorf("failed to decode base64 string: %w", err)
	}

	payload, err := migration.Unmarshal(dataBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal migration payload: %w", err)
	}

	var accounts []Account

	for _, p := range payload.OtpParameters {
		secretB32 := base32.StdEncoding.EncodeToString(p.Secret)

		name := p.Name
		if p.Issuer != "" {
			name = fmt.Sprintf("%s (%s)", p.Name, p.Issuer)
		}

		accounts = append(accounts, Account{
			Name:   name,
			Issuer: p.Issuer,
			Secret: secretB32,
		})
	}

	fmt.Printf("Found %d accounts.\n", len(accounts))

	fmt.Print("Enter a new master password to secure your data: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}

	if err := saveAccounts(accounts, password); err != nil {
		return fmt.Errorf("failed to save data: %w", err)
	}

	fmt.Println("Setup complete! You can now run 'otpcli' to generate codes.")
	return nil
}

func runListCodes() error {
	fmt.Print("Enter master password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	accounts, err := loadAccounts(password)
	if err != nil {
		return fmt.Errorf("access denied or file error: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CODE\tTTL\tNAME")
	fmt.Fprintln(w, "----\t---\t----")

	for _, acc := range accounts {
		code, err := totp.GenerateCode(acc.Secret, time.Now())
		if err != nil {
			fmt.Fprintf(w, "ERROR\t-\t%s\n", acc.Name)
			continue
		}

		period := 30
		remain := period - (int(time.Now().Unix()) % period)

		fmt.Fprintf(w, "%s\t%ds\t%s\n", code, remain, acc.Name)
	}
	w.Flush()

	return nil
}

func decodeQRCode(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("image decode error: %w", err)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}

	qrReader := qrcode.NewQRCodeReader()
	result, err := qrReader.Decode(bmp, nil)
	if err != nil {
		return "", err
	}

	return result.GetText(), nil
}

func getStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, storeFileName), nil
}

func saveAccounts(accounts []Account, password []byte) error {
	data, err := json.Marshal(accounts)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return err
	}

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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	finalData := append(salt, ciphertext...)

	path, err := getStorePath()
	if err != nil {
		return err
	}

	return os.WriteFile(path, finalData, 0600)
}

func loadAccounts(password []byte) ([]Account, error) {
	path, err := getStorePath()
	if err != nil {
		return nil, err
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(fileData) < saltLen {
		return nil, errors.New("invalid data file")
	}

	salt := fileData[:saltLen]
	ciphertextWithNonce := fileData[saltLen:]

	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed (wrong password?)")
	}

	var accounts []Account
	if err := json.Unmarshal(plaintext, &accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}
