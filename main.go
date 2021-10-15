package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/dchest/captcha"
	"github.com/go-algorand-sdk/client/v2/algod"
	"github.com/go-algorand-sdk/crypto"
	"github.com/go-algorand-sdk/future"
)

const (
	length = 5

	imgH = 80
	imgW = 240

	rounds = 10
)

var (
	account crypto.Account
	client  *algod.Client
)

func main() {
	var err error
	client, err = algod.MakeClient("https://testnet.algoexplorerapi.io", "")

	if err != nil {
		log.Fatalf("Failed to make client: %+v", err)
	}

	account = crypto.GenerateAccount()

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/captcha", generateCaptcha)
	log.Fatal(http.ListenAndServeTLS(":8443", "localhost.crt", "localhost.key", nil))
}

type captchaResponse struct {
	Captcha     []byte `json:"captcha"`
	Transaction []byte `json:"txn"`
	IV          []byte `json:"iv"`
	Padding     int    `json:"pad"`
}

func generateCaptcha(w http.ResponseWriter, r *http.Request) {
	var err error

	if err = r.ParseForm(); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	var (
		solution = captcha.RandomDigits(length)
		ctype    = r.FormValue("type")
		lang     = r.FormValue("lang")

		buff = bytes.NewBuffer([]byte{})
		wt   io.WriterTo
	)

	switch ctype {
	case "audio":
		wt = captcha.NewAudio("", solution, lang)
	default:
		wt = captcha.NewImage("", solution, imgW, imgH)
	}

	if _, err := wt.WriteTo(buff); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	var (
		ciphertext []byte
		iv         []byte
	)

	txn, padding, err := getTransaction()
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	if ciphertext, iv, err = encrypt(solution, txn); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	b, err := json.Marshal(captchaResponse{
		Captcha:     buff.Bytes(),
		Transaction: ciphertext,
		IV:          iv,
		Padding:     padding,
	})

	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	w.Write(b)
}

func getTransaction() ([]byte, int, error) {
	//TODO: Create a transaction && sign it && dump bytes
	sp, err := client.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, 0, err
	}
	sp.LastRoundValid = sp.FirstRoundValid + rounds

	auth := account.Address.String()
	txn, err := future.MakePaymentTxn(auth, auth, 0, nil, "", sp)
	if err != nil {
		return nil, 0, err
	}
	txn.Fee = 0

	_, sbytes, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		return nil, 0, err
	}

	padding := aes.BlockSize - (len(sbytes) % aes.BlockSize)
	return append(sbytes, bytes.Repeat([]byte(" "), padding)...), padding, nil

}

func encrypt(solution, plaintext []byte) ([]byte, []byte, error) {
	key := sha256.Sum256(solution)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	plaintext = pad(aes.BlockSize, plaintext)

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, iv, nil
}

func pad(blockSize int, txt []byte) []byte {
	padding := (blockSize - len(txt)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(txt, padtext...)
}
