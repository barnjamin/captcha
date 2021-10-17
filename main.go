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
	"golang.org/x/crypto/pbkdf2"
)

const (
	length = 5

	keyIters = 10e5

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
	TxId        []byte `json:"txid"`
	IV          []byte `json:"iv"`
	Padding     int    `json:"pad"`
	Iters       int    `json:"iters"`
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

		ciphertext, iv []byte
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

	txn, txid, padding, err := getTransaction()
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	if ciphertext, iv, err = encrypt(solution, txid, txn); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	b, err := json.Marshal(captchaResponse{
		Captcha:     buff.Bytes(),
		Transaction: ciphertext,
		IV:          iv,
		Padding:     padding,
		TxId:        txid,
		Iters:       keyIters,
	})

	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(500)
		return
	}

	w.Write(b)
}

func getTransaction() ([]byte, []byte, int, error) {
	sp, err := client.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, nil, 0, err
	}
	sp.LastRoundValid = sp.FirstRoundValid + rounds

	auth := account.Address.String()
	txn, err := future.MakePaymentTxn(auth, auth, 0, nil, "", sp)
	if err != nil {
		return nil, nil, 0, err
	}
	txn.Fee = 0

	txid, sbytes, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		return nil, nil, 0, err
	}

	padding := aes.BlockSize - (len(sbytes) % aes.BlockSize)
	return append(sbytes, bytes.Repeat([]byte(" "), padding)...), []byte(txid), padding, nil
}

func encrypt(solution, txid, plaintext []byte) ([]byte, []byte, error) {
	key := pbkdf2.Key(solution, txid, keyIters, 32, sha256.New)

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
