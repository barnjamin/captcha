package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

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
	IV          []byte `json:"iv"`
}

func generateCaptcha(w http.ResponseWriter, r *http.Request) {
	var err error

	if err = r.ParseForm(); err != nil {
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

	var (
		ciphertext []byte
		iv         []byte
	)
	if ciphertext, iv, err = encrypt(solution, getTransaction(round)); err != nil {
		w.WriteHeader(500)
	}

	b, err := json.Marshal(captchaResponse{
		Captcha:     buff.Bytes(),
		Transaction: ciphertext,
		IV:          iv,
	})

	if err != nil {
		w.WriteHeader(500)
	}

	w.Write(b)
}

func getTransaction(round int) []byte {
	//return []byte(fmt.Sprintf("txn for round: %d", round))
	txt := "Success!"
	txt += strings.Repeat(" ", aes.BlockSize-(len(txt)%aes.BlockSize))
	return []byte(txt)
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

//func decrypt(solution, ciphertext []byte) ([]byte, error) {
//	key := sha256.Sum256(solution)
//	block, err := aes.NewCipher(key[:])
//	if err != nil {
//		return nil, err
//	}
//
//	iv := ciphertext[:aes.BlockSize]
//	ciphertext = ciphertext[aes.BlockSize:]
//
//	log.Printf("key: %v", key)
//	log.Printf("iv: %v", iv)
//	log.Printf("cipher: %v\n", ciphertext)
//
//	mode := cipher.NewCBCDecrypter(block, iv)
//	mode.CryptBlocks(ciphertext, ciphertext)
//
//	return ciphertext, nil
//}
//
