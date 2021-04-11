package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aashishkoirala/strenc"
)

type params struct {
	input          string
	passphrase     string
	passphrasefile string
	decrypt        bool
}

func main() {
	os.Exit(run())
}

func run() int {
	p, err := readParams()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		return 1
	}
	var o string
	if p.decrypt {
		o, err = strenc.Decrypt(p.input, p.passphrase)
	} else {
		o, err = strenc.Encrypt(p.input, p.passphrase)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		return 1
	}
	fmt.Println(o)
	return 0
}

func readParams() (*params, error) {
	var p params
	flag.StringVar(&p.input, "i", "", "Input text (plain text if encrypting, cipher text if decrypting). If empty, will read from STDIN.")
	flag.StringVar(&p.passphrase, "p", "", "Passphrase to use for encryption/decryption")
	flag.StringVar(&p.passphrasefile, "pf", "", "Use instead of -p to specify a file that has the passphrase to use for encryption/decryption. Use - as file to read from STDIN. If reading both input and passphrase from STDIN, passphrase will be read first.")
	flag.BoolVar(&p.decrypt, "d", false, "Specify this to decrypt, otherwise encrypt is assumed")
	flag.Parse()
	if p.passphrase == "" && p.passphrasefile == "" {
		flag.Usage()
		return nil, errors.New("must specify passphrase or passphrase file")
	}
	if p.passphrase == "" && p.passphrasefile != "" {
		err := readPassphrase(&p)
		if err != nil {
			return nil, err
		}
	}
	if p.input == "" {
		err := readInput(&p)
		if err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func readPassphrase(p *params) error {
	var data []byte
	var err error
	if p.passphrasefile == "-" {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(p.passphrasefile)
	}
	if err != nil {
		return err
	}
	p.passphrase = string(data)
	return nil
}

func readInput(p *params) error {
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	p.input = string(data)
	return nil
}
