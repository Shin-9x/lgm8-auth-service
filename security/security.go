package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// EncryptAES encrypts the given plain text using AES-GCM.
//
// Parameters:
//   - plainText: The text to be encrypted.
//   - secretKeyPath: The path to the file containing the secret key.
//
// Returns:
//   - The Base64 encoded ciphertext (nonce + encrypted data) as a string.
//   - An error if any step of the encryption process fails.
func EncryptAES(plainText, secretKeyPath string) (string, error) {
	// Retrieve the secret key from the specified file.
	secretKey, err := getSecretKey(secretKeyPath)
	if err != nil {
		return "", err
	}

	// Ensure the secret key is of correct length (32 bytes for AES-256).
	if len(secretKey) != 32 {
		return "", fmt.Errorf("invalid secret key length: expected 32 bytes, got %d", len(secretKey))
	}

	// Create a new AES cipher using the secret key.
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	// Generate a random 12-byte nonce for AES-GCM.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Create a new AES-GCM cipher using the AES block and nonce.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plain text using AES-GCM.
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plainText), nil)

	// Concatenate the nonce and ciphertext, and encode the result in Base64.
	result := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptAES decrypts the given Base64 encoded ciphertext using AES-GCM.
//
// Parameters:
//   - encryptedText: The Base64 encoded ciphertext (nonce + encrypted data).
//   - secretKeyPath: The path to the file containing the secret key.
//
// Returns:
//   - The decrypted plain text as a string.
//   - An error if any step of the decryption process fails.
func DecryptAES(encryptedText, secretKeyPath string) (string, error) {
	// Decode the Base64 encoded ciphertext.
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// Retrieve the secret key from the specified file.
	secretKey, err := getSecretKey(secretKeyPath)
	if err != nil {
		return "", err
	}

	// Ensure the secret key is of correct length (32 bytes for AES-256).
	if len(secretKey) != 32 {
		return "", fmt.Errorf("invalid secret key length: expected 32 bytes, got %d", len(secretKey))
	}

	// Create a new AES cipher using the secret key.
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	// Create a new AES-GCM cipher using the AES block.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract the nonce and ciphertext from the decoded data.
	nonceSize := 12
	if len(data) < nonceSize {
		return "", fmt.Errorf("invalid encrypted data")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the ciphertext using AES-GCM.
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Convert the decrypted plaintext to a string and return it.
	return string(plaintext), nil
}

// getSecretKey retrieves the secret key from the specified file.
func getSecretKey(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading secret file: %w", err)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("secret file is empty")
	}

	// Ensure the content is exactly 32 bytes
	if len(content) != 32 {
		return nil, fmt.Errorf("secret key file must contain exactly 32 bytes. Actual [%d]", len(content))
	}

	return content, nil
}
