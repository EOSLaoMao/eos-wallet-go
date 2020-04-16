package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func main() {
	data, err := ioutil.ReadFile("/Users/shawn/eosio-wallet/default.wallet")
	if err != nil {
		panic(err)
	}

	var content map[string]string
	_ = json.Unmarshal(data, &content)
	cipher := content["cipher_keys"]

	password := "PW5Kf7h86a2WvStSY3f5M6ntdiqqD7a6whvbMrWZMNSMtyrUYD92P"
	h := sha512.New()
	_, _ = h.Write([]byte(password))
	key := h.Sum(nil)
	fmt.Println(base64.StdEncoding.EncodeToString(key))

	des, err := decrypt(key, cipher)
	if err != nil {
		panic(err)
	}
	fmt.Println("......base64 decrypted......")
	fmt.Println(base64.StdEncoding.EncodeToString(des))
}

const EncryptedKeyLen = 32

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

	iv := ck[EncryptedKeyLen:EncryptedKeyLen+aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipherText, cipherText)

	// PKCS5Trimming
	padding := cipherText[len(cipherText)-1]
	trimmed := cipherText[:len(cipherText)-int(padding)]

	return trimmed, nil
}
