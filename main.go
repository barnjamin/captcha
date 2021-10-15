package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/dchest/captcha"
)

const (
	length = 5
	imgH   = 80
	imgW   = 240
)

func main() {

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/captcha", generateCaptcha)
	log.Fatal(http.ListenAndServeTLS(":8443", "localhost.crt", "localhost.key", nil))
}

type captchaResponse struct {
	Captcha     []byte `json:"captcha"`
	Transaction []byte `json:"txn"`
}

func generateCaptcha(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(500)
	}

	var (
		solution = captcha.RandomDigits(length)
		ctype    = r.FormValue("type")
		lang     = r.FormValue("lang")
		sRound   = r.FormValue("round")

		buff = bytes.NewBuffer([]byte{})
		wt   io.WriterTo
	)

	round, _ := strconv.Atoi(sRound)

	switch ctype {
	case "audio":
		wt = captcha.NewAudio("", solution, lang)
	default:
		wt = captcha.NewImage("", solution, imgW, imgH)
	}

	if _, err := wt.WriteTo(buff); err != nil {
		w.WriteHeader(500)
	}

	txn, err := encrypt(solution, getTransaction(round))
	if err != nil {
		w.WriteHeader(500)
	}

	b, err := json.Marshal(captchaResponse{
		Captcha:     buff.Bytes(),
		Transaction: txn,
	})

	if err != nil {
		w.WriteHeader(500)
	}

	w.Write(b)
}

func getTransaction(round int) []byte {
	return []byte(fmt.Sprintf("txn for round: %d", round))
}

func encrypt(solution, plaintext []byte) (ciphertext []byte, err error) {

	key := sha256.Sum256(solution)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	log.Printf("%d", gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(solution, ciphertext []byte) (plaintext []byte, err error) {
	key := sha256.Sum256(solution)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
