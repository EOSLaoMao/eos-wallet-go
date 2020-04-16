package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

const EncryptedKeyLen = 32

func hashSha256(src []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(src)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func hashSha512(src []byte) ([]byte, error) {
	h := sha512.New()
	_, err := h.Write(src)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// decrypt using AES CBC mode, and PKCS5Trimming
// k is sha512 hashed password
// c is origin cipher_text string from wallet file
func decrypt(k []byte, c string) ([]byte, error) {
	ck := make([]byte, len(k))
	copy(ck, k)

	cipherText, err := hex.DecodeString(c)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(ck[:EncryptedKeyLen])
	if err != nil {
		return nil, err
	}

	iv := ck[EncryptedKeyLen : EncryptedKeyLen+aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipherText, cipherText)

	// PKCS5Trimming
	padding := cipherText[len(cipherText)-1]
	trimmed := cipherText[:len(cipherText)-int(padding)]

	return trimmed, nil
}
