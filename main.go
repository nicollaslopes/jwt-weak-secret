package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var Red = "\033[31m"
var Magenta = "\033[35m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var EndColor = "\033[0m"
var BrightBlue = "\x1b[94m"
var BrightCyan = "\x1b[96m"

var verbosePtr *bool

func validateSignature(tokenString string, secretKey []byte) (bool, string) {

	token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secretKey, nil
	})

	if token.Valid {
		return true, string(secretKey)
	}

	return false, ""
}

func bruteForce(wordlistPath string, jwt string) (string, float64) {

	file, err := os.Open(wordlistPath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer file.Close()

	start := time.Now()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		if *verbosePtr {
			word := scanner.Text()
			if len(word) > 20 {
				word = word[:20] + "..."
			}
			fmt.Printf("\r\033[K%vTesting: %v %s", Red, EndColor, word)
		}

		isJwtValid, _ := validateSignature(jwt, []byte(scanner.Text()))
		if isJwtValid {
			duration := time.Since(start).Seconds()
			return string([]byte(scanner.Text())), duration
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return "", 0.0
}

func main() {

	var jwtToken string

	verbosePtr = flag.Bool("v", false, "verbose mode")
	pathToWordlist := flag.String("w", "", "path to wordlist")
	flag.Parse()

	fmt.Println("Enter JWT Token: ")
	fmt.Scanln(&jwtToken)

	secretFound, duration := bruteForce(*pathToWordlist, jwtToken)
	fmt.Printf("%v\n[✔] Secret Key Found! %v %v %v %v\n", Green, EndColor, Yellow, string(secretFound), EndColor)
	fmt.Printf("Finished in %.2f seconds.\n\n", duration)

}
