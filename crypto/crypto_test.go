package  crypto

import (
	"fmt"
	"github.com/bmizerany/assert"
	"github.com/jpeng-go/chain33-sdk-go/crypto/gm"
	"testing"
)

func TestAES(t *testing.T) {
	var text = "hello aes"
	var key = getRandBytes(32)

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

	assert.Equal(t, text, string(cipher))
}

func TestSM4(t *testing.T) {
	key := []byte{0x1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	fmt.Printf("key = %v\n", key)
	data := []byte{0x1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	fmt.Printf("data = %x\n", data)
	d0 := gm.SM4Encrypt(key, data)
	fmt.Printf("d0 = %x\n", d0)
	d1 := gm.SM4Decrypt(key, d0)
	fmt.Printf("d1 = %x\n", d1)

	assert.Equal(t, data, d1)
}