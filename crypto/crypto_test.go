package  crypto

import (
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	var text = "hello aes"
	var key = GetRandBytes(32)

	cipherText, err := AESCBCPKCS7Encrypt(key, []byte(text))
	if err != nil {
		fmt.Println(err)
		return
	}

	cipher, err := AESCBCPKCS7Decrypt(key, cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(cipher))
}
