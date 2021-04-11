package strenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength int = 8
	keySize    int = 32
)

// StringEncryptor encapsulates a key generated from a passphrase. Use it to generate a key and
// from a passphrase and encrypt multiple strings with the same key.
type StringEncryptor struct {
	key  []byte
	salt []byte
}

func createKey(passphrase string) ([]byte, []byte, error) {
	salt := make([]byte, saltLength)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, nil, err
	}
	key, err := createKeyWithSalt(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func createKeyWithSalt(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key([]byte(passphrase), salt, 1000, keySize, sha256.New), nil
}

func encrypt(plaintext string, key []byte, salt []byte) (string, error) {
	plaindata := []byte(plaintext)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	cipherdata := make([]byte, saltLength+len(nonce))
	cipherdata = append(salt, nonce...)
	cipherdata = gcm.Seal(cipherdata, nonce, plaindata, nil)
	ciphertext := base64.StdEncoding.EncodeToString(cipherdata)
	return ciphertext, nil
}

func decrypt(cipherdata []byte, key []byte) (string, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}
	nonce := cipherdata[0:gcm.NonceSize()]
	cipherdata = cipherdata[len(nonce):]
	plaindata, err := gcm.Open(nil, nonce, cipherdata, nil)
	if err != nil {
		return "", err
	}
	return string(plaindata), nil
}

// Encrypt takes a plaintext string and a passphrase and returns the encrypted text.
func Encrypt(plaintext string, passphrase string) (string, error) {
	key, salt, err := createKey(passphrase)
	if err != nil {
		return "", err
	}
	return encrypt(plaintext, key, salt)
}

// Decrypt takes a string encrypted with Encrypt, and the passphrase that was used to
// encrypt it, and returns the decrypted plaintext.
func Decrypt(ciphertext string, passphrase string) (string, error) {
	cipherdata, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	salt := cipherdata[0:saltLength]
	cipherdata = cipherdata[saltLength:]
	key, err := createKeyWithSalt(passphrase, salt)
	if err != nil {
		return "", err
	}
	return decrypt(cipherdata, key)
}

// Encrypt encrypts the passed in plaintext using the key associated with the
// StringEncryptor instance.
func (s *StringEncryptor) Encrypt(plaintext string) (string, error) {
	return encrypt(plaintext, s.key, s.salt)
}

// New creates an instance of StringEncryptor that contains an encryption key corresponding
// to the passphrase provided.
func New(passphrase string) (*StringEncryptor, error) {
	key, salt, err := createKey(passphrase)
	if err != nil {
		return nil, err
	}
	return &StringEncryptor{
		key:  key,
		salt: salt,
	}, nil
}
