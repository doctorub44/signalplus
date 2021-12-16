package signalplus

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"
)

func fatalError(t *testing.T, err error, s string) {
	if err != nil {
		t.Errorf(s)
	}
}

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func TestCrypto(t *testing.T) {
	key, _ := PasswordKey([]byte("how now brown cow"), []byte("some salt"))
	encrypted, _ := Encrypt([]byte("Secret message with symmetric encryption"), key)
	message, _ := Decrypt(encrypted, key)
	if string(message) != "Secret message with symmetric encryption" {
		fatalError(t, nil, "test 1 failed decryption")
	} else {
		fmt.Println(string(message))
	}

	encrypted, _ = Encrypt([]byte("Second secret message with symmetric encryption"), key)
	message, _ = Decrypt(encrypted, key)
	if string(message) != "Second secret message with symmetric encryption" {
		fatalError(t, nil, "test 2 failed decryption")
	} else {
		fmt.Println(string(message))
	}

	spublic, sprivate, _ := KeyPair()
	rpublic, rprivate, _ := KeyPair()
	encrypted, _ = Seal([]byte("Secret message with public key encryption"), rpublic, sprivate)
	message, _ = Open(encrypted, spublic, rprivate)
	if string(message) != "Secret message with public key encryption" {
		fatalError(t, nil, "test 3 failed decryption")
	} else {
		fmt.Println(string(message))
	}
}

func TestSignal(t *testing.T) {
	flag.Parse()

	if *cpuprofile != "" {
		fmt.Println(*cpuprofile)
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	runtime.GOMAXPROCS(2)

	var alicestate Signalstate
	var bobstate Signalstate
	var alicepair Keypair
	var bobpair Keypair

	//alicesym, err0 := Key()
	bobsym, _ := Key()
	alicepair.Pubkey, alicepair.Prikey, _ = KeyPair()
	bobpair.Pubkey, bobpair.Prikey, _ = KeyPair()
	SetRatchet(&alicestate, 1, 0, 2)
	SetRatchet(&bobstate, 1, 0, 2)
	err := RatchetInitSender(&alicestate, bobsym, bobpair.Pubkey)
	if err != nil {
		panic(err.Error())
	}
	RatchetInitReceiver(&bobstate, bobsym, bobpair)

	header, ciphertext, _ := RatchetEncrypt(&alicestate, []byte("this is alice1"))
	plaintext, _ := RatchetDecrypt(&bobstate, header, ciphertext)
	fmt.Println(string(plaintext))

	header, ciphertext, _ = RatchetEncrypt(&alicestate, []byte("this is alice the second time"))
	plaintext, _ = RatchetDecrypt(&bobstate, header, ciphertext)
	fmt.Println(string(plaintext))

	header, ciphertext3, _ := RatchetEncrypt(&alicestate, []byte("this is alice 3"))
	header3 := header
	header, ciphertext4, _ := RatchetEncrypt(&alicestate, []byte("this is alice 4"))
	header4 := header

	//Skip 2 messages
	header, ciphertext, _ = RatchetEncrypt(&alicestate, []byte("this is alice 5"))
	plaintext, _ = RatchetDecrypt(&bobstate, header, ciphertext)
	fmt.Println(string(plaintext))

	//message 2 shows up out of order
	plaintext, _ = RatchetDecrypt(&bobstate, header3, ciphertext3)
	fmt.Println(string(plaintext))

	//message 3 shows up out of order
	plaintext, _ = RatchetDecrypt(&bobstate, header4, ciphertext4)
	fmt.Println(string(plaintext))

	header, ciphertext, _ = RatchetEncrypt(&alicestate, []byte("this is alice 6"))
	plaintext, _ = RatchetDecrypt(&bobstate, header, ciphertext)
	fmt.Println(string(plaintext))

	start := time.Now()
	for i := 0; i < 1000; i++ {
		header, ciphertext, _ = RatchetEncrypt(&alicestate, []byte("this is alice 7776"))
		plaintext, _ = RatchetDecrypt(&bobstate, header, ciphertext)
	}
	log.Printf("Send 1000 time = %s", time.Since(start))
}
