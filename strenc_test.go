package strenc

import (
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {
	pp := "This is my passphrase"
	pt := "This is my plaintext"
	ct, err := Encrypt(pt, pp)
	if err != nil {
		t.Fatal("Encrypting:", err.Error())
	}
	dt, err := Decrypt(ct, pp)
	if err != nil {
		t.Fatal("Decrypting:", err.Error())
	}
	if pt != dt {
		t.Fatal("Plaintext and decrypted text don't match.", pt, dt)
	}
	se, err := New(pp)
	if err != nil {
		t.Fatal("New:", err.Error())
	}
	p1 := "ABC"
	p2 := "DEF"
	e1, err := se.Encrypt(p1)
	if err != nil {
		t.Fatal(err.Error())
	}
	e2, err := se.Encrypt(p2)
	if err != nil {
		t.Fatal(err.Error())
	}
	d1, err := Decrypt(e1, pp)
	if err != nil {
		t.Fatal(err.Error())
	}
	d2, err := Decrypt(e2, pp)
	if err != nil {
		t.Fatal(err.Error())
	}
	if p1 != d1 {
		t.Fatal("Plaintext and decrypted text don't match.", p1, d1)
	}
	if p2 != d2 {
		t.Fatal("Plaintext and decrypted text don't match.", p1, d1)
	}
}
