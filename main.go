package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"io/ioutil"
)

type BytesReader struct {
	Bytes []byte
	index int
}

func NewBytesReader(b []byte) *BytesReader {
	d := make([]byte, len(b))
	copy(d, b)
	return &BytesReader{
		Bytes: d,
	}
}

func (r *BytesReader) get() byte {
	b := r.Bytes[r.index]
	r.index += 1
	return b
}

func (r *BytesReader) Checksum() []byte {
	r.index += sha512.Size
	return r.Bytes[:r.index]
}

func (r *BytesReader) Public() []byte {
	b := r.Bytes[r.index : r.index+34]
	r.index += 34
	return b
}

func (r *BytesReader) Private() []byte {
	b := r.Bytes[r.index : r.index+33]
	r.index += 33
	return b
}

func (r *BytesReader) Remain() []byte {
	return r.Bytes[r.index:]
}

func main() {
	data, err := ioutil.ReadFile("/Users/shawn/eosio-wallet/test.wallet")
	if err != nil {
		panic(err)
	}

	var content map[string]string
	_ = json.Unmarshal(data, &content)
	cipher := content["cipher_keys"]

	password := "PW5Kf7h86a2WvStSY3f5M6ntdiqqD7a6whvbMrWZMNSMtyrUYD92P"
	key, _ := hashSha512([]byte(password))
	fmt.Println(base64.StdEncoding.EncodeToString(key))

	des, err := decrypt(key, cipher)
	if err != nil {
		panic(err)
	}
	fmt.Println("......base64 decrypted......")
	fmt.Println(base64.StdEncoding.EncodeToString(des))

	reader := NewBytesReader(des)
	checksum := reader.Checksum()
	count := reader.get()

	if !bytes.Equal(checksum, key) {
		panic("invalid password")
	}
	fmt.Println("....all bytes....")
	fmt.Println(reader.Bytes)

	fmt.Println("....key count....")
	fmt.Println(count)

	fmt.Println("....public....")
	public := reader.Public()
	fmt.Println(public)

	fmt.Println("....private....")
	private := reader.Private()
	fmt.Println(private)

	printPub(public)
	printPri(private[1:])
}

func printPub(pub []byte) {
	hash := ripemd160checksum(pub[1:], 0)
	size := 33
	raw := make([]byte, size+4)
	copy(raw, pub[1:])
	copy(raw[size:], hash[:4])

	fmt.Println(base58.Encode(raw))
}

func ripemd160checksum(in []byte, curve int) []byte {
	h := New()
	_, _ = h.Write(in) // this implementation has no error path

	if curve != 0 {
		_, _ = h.Write([]byte("K1"))
	}

	sum := h.Sum(nil)
	return sum[:4]
}

func printPri(pri []byte) {
	b := []byte{0x80}
	b = append(b, pri...)

	hash1, _ := hashSha256(b)
	hash2, _ := hashSha256(hash1)

	c := hash2[:4]

	r := append(b, c...)
	fmt.Println(base58.Encode(r))
}
