package signalplus

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// KeySize and NonceSize : constants used for all encryption functions
const (
	KeySize   = 32
	NonceSize = 24
)

//KeyToHex :
func KeyToHex(k *[KeySize]byte) string {
	return hex.EncodeToString(k[:KeySize])
}

// Encrypt : encrypted message is the size original message plus overhead bytes
// and encrypted with symmetric key cryptography
func Encrypt(message []byte, key *[KeySize]byte) ([]byte, error) {
	nonce, err := Nonce()
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(nonce))
	copy(encrypted, nonce[:])
	encrypted = secretbox.Seal(encrypted, message, nonce, key)
	return encrypted, nil
}

// Decrypt : extracts the nonce from the ciphertext and decrypts with symmetric key cryptography
func Decrypt(encrypted []byte, key *[KeySize]byte) ([]byte, error) {
	if len(encrypted) < (NonceSize + secretbox.Overhead) {
		return nil, errors.New("occrypto.Decrypt: encrypted size wrong")
	}

	var nonce [NonceSize]byte
	copy(nonce[:NonceSize], encrypted[:NonceSize])
	message, ok := secretbox.Open(nil, encrypted[NonceSize:], &nonce, key)
	if !ok {
		return nil, errors.New("occrypto.Decrypt: error open secretbox to decrypt")
	}

	return message, nil
}

// Key : create a random secret key.
func Key() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:KeySize])
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Nonce : create a random nonce.
func Nonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:NonceSize])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

// PasswordKey : generate a symmetric key from a passphrase and salt.
func PasswordKey(password []byte, salt []byte) (*[KeySize]byte, error) {
	var naclKey = new([KeySize]byte)
	key, err := scrypt.Key(password, salt, 32768, 8, 1, KeySize)
	if err != nil {
		return nil, err
	}

	copy(naclKey[:], key)
	Zero(key)
	return naclKey, nil
}

// Zero : zero out a byte array with sensitive data
func Zero(data []byte) {
	for i := range data {
		data[i] ^= data[i]
	}
}

// KeyPair : generate a public key cryptography asymmetric key pair (pub, pri, err)
func KeyPair() (*[KeySize]byte, *[KeySize]byte, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	return public, private, err
}

// Seal : encrypt a message with public key cryptography
func Seal(message []byte, recipientPublicKey *[KeySize]byte, senderPrivateKey *[KeySize]byte) ([]byte, error) {
	nonce, err := Nonce()
	if err != nil {
		return nil, err
	}
	encrypted := box.Seal(nonce[:], message, nonce, recipientPublicKey, senderPrivateKey)
	return encrypted, nil
}

// Open : decrypt a message with public key cryptography
func Open(encrypted []byte, senderPublicKey *[KeySize]byte, recipientPrivateKey *[KeySize]byte) ([]byte, bool) {
	var decryptNonce [NonceSize]byte
	copy(decryptNonce[:NonceSize], encrypted[:NonceSize])
	decrypted, ok := box.Open(nil, encrypted[NonceSize:], &decryptNonce, senderPublicKey, recipientPrivateKey)
	return decrypted, ok
}

// Hash64 : convert byte slice to 64bit hash
func Hash64(value []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(value)
	return hash.Sum64()
}
