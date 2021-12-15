package signalplus

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"
)

//VLowSec : security level enumerations for scrypt N
const (
	VLowSec int = 0 + iota
	LowSec
	MedSec
	HighSec
	VHighSec
)

//Keypair :
type Keypair struct {
	Prikey *[KeySize]byte
	Pubkey *[KeySize]byte
}

//Mesghead :
type Mesghead struct {
	Pubkey  *[KeySize]byte
	Nummesg uint64
	Sendnum uint64
}

type skipkey struct {
	key *[KeySize]byte
	num uint64
}

//Ratchetparam :
type Ratchetparam struct {
	ScryptN int
	Count   int
	Period  int
	Last    int
	Ltime   time.Time
}

//MaxSkip :
const MaxSkip = 100
const maxkey = 16

//Signalstate :
type Signalstate struct {
	rpubkey   *[KeySize]byte             //Receivers public key
	rootkey   *[KeySize]byte             //Root symmetric key
	nummesg   uint64                     //Number of messages in previous sending chain
	sendnum   uint64                     //Sending message number
	recvnum   uint64                     //Receiving message number
	sendpair  Keypair                    //Senders Keypair
	recvchain *[KeySize]byte             //Receive chain symmetric key
	sendchain *[KeySize]byte             //Send chain symmetric key
	skipped   map[skipkey]*[KeySize]byte //Skipped messages stores message key for  chain, mesg number
	rparam    Ratchetparam               //Ratchet parameters
	Mesgkey   *[KeySize]byte             //Current message key
	ringkey   [maxkey]*[KeySize]byte     //Message key ring to support multi-threaded decrypt
	ringnum   [maxkey]uint64             //Sendnum for each message key in the ring
	ringstart int                        //Array index start of the ring
	ringend   int                        //Array index end of the ring
}

type skipped struct {
}

var krmutex sync.Mutex

var scryptN = 16384 //16384: 32768 for logins, 2017 1048576 for files, this is for logins
var constant = [KeySize]byte{0x01, 0x45, 0x94, 0x74, 0x04, 0x99, 0x29, 0x43,
	0x81, 0x24, 0x00, 0x11, 0x69, 0x37, 0x53, 0x87,
	0x92, 0x89, 0x20, 0x34, 0x12, 0x14, 0x88, 0x82,
	0x28, 0x38, 0x47, 0x71, 0x70, 0x23, 0x22, 0x55}

//Header :
func Header(pair Keypair, nummesg uint64, sendnum uint64) Mesghead {
	var h Mesghead
	h.Pubkey = pair.Pubkey
	h.Nummesg = nummesg
	h.Sendnum = sendnum
	return h
}

//GetHeader :
func GetHeader(state *Signalstate) Mesghead {
	return Header(state.sendpair, state.nummesg, state.sendnum)
}

//RatchetInitSender :
func RatchetInitSender(state *Signalstate, symkey *[KeySize]byte, rpubkey *[KeySize]byte) error {
	var err error

	state.sendpair, err = GenerateDh()
	if err != nil {
		return err
	}
	state.rpubkey = rpubkey
	state.rootkey, state.sendchain, err = KdfRk(symkey, NewDh(state.sendpair, state.rpubkey), &state.rparam)
	if err != nil {
		return err
	}
	state.recvchain = nil
	state.sendnum = 0
	state.recvnum = 0
	state.nummesg = 0
	state.skipped = make(map[skipkey]*[KeySize]byte)
	state.Mesgkey = symkey
	state.ringstart = -1
	state.ringend = -1
	return nil
}

//RatchetInitReceiver :
func RatchetInitReceiver(state *Signalstate, symkey *[KeySize]byte, recvkp Keypair) {
	state.sendpair = recvkp
	state.rpubkey = nil
	state.rootkey = symkey
	state.sendchain = nil
	state.recvchain = nil
	state.sendnum = 0
	state.recvnum = 0
	state.nummesg = 0
	state.skipped = make(map[skipkey]*[KeySize]byte)
	state.Mesgkey = symkey
	state.ringstart = -1
	state.ringend = -1
}

//RatchetEncrypt :
func RatchetEncrypt(state *Signalstate, plaintext []byte) (Mesghead, []byte, error) {
	var key *[KeySize]byte
	var err error
	state.sendchain, key, err = KdfCk(state.sendchain, &state.rparam)
	head := Header(state.sendpair, state.nummesg, state.sendnum)
	state.sendnum++
	ciphertext, err := Encrypt(plaintext, key)
	state.Mesgkey = key
	//fmt.Printf("RatchetEncrypt mesg key : %x\n\r", key)
	return head, ciphertext, err
}

//RatchetDecrypt :
func RatchetDecrypt(state *Signalstate, head Mesghead, ciphertext []byte) ([]byte, error) {
	var key *[KeySize]byte
	var err error

	plaintext, _ := TrySkippedMessageKeys(state, head, ciphertext)
	if plaintext != nil {
		return plaintext, nil
	}
	if head.Pubkey != state.rpubkey {
		if state.rpubkey == nil {
			SkipMessageKeys(state, head.Nummesg)
			DHRatchet(state, head)
		} else if *head.Pubkey != *state.rpubkey {
			fmt.Println("RatchetDecrypt : Skipping messages : ")
			SkipMessageKeys(state, head.Nummesg)
			DHRatchet(state, head)
		}
	}
	SkipMessageKeys(state, head.Sendnum)

	state.recvchain, key, err = KdfCk(state.recvchain, &state.rparam)
	if err != nil {
		fmt.Printf("RatchetDecrypt : error KdfCk - Ratchet decrypt key : ")
		return nil, err
	}
	state.recvnum++
	state.Mesgkey = key

	AddKeyRing(state, key, head.Sendnum)
	//fmt.Printf("RatchetDecrypt mesg key : %x\n\r", key)
	return Decrypt(ciphertext, key)
}

//AddKeyRing :
func AddKeyRing(state *Signalstate, key *[KeySize]byte, ratchetnum uint64) {
	krmutex.Lock()
	i := (state.ringend + 1) % maxkey
	state.ringnum[i] = ratchetnum
	state.ringkey[i] = key
	state.ringend = i
	if state.ringstart == state.ringend {
		state.ringstart = (state.ringstart + 1) % maxkey
	} else if state.ringstart == -1 {
		state.ringstart = 0
	}
	krmutex.Unlock()
}

//TryKeyRing :
func TryKeyRing(ciphertext []byte, state *Signalstate, ratchetnum uint64) ([]byte, error) {
	//fmt.Printf("TryKeyRing : ratchetnum = %d\n", ratchetnum)
	krmutex.Lock()
	defer krmutex.Unlock()
	if state.ringstart >= 0 {
		for i := state.ringstart; ; i = (i + 1) % maxkey {
			if ratchetnum == state.ringnum[i] {
				plaintext, err := Decrypt(ciphertext, state.ringkey[i])
				if err == nil {
					//fmt.Printf("TryKeyRing : found key in ring ratchetnum = %d\n", ratchetnum)
					return plaintext, err
				}
			}
			if i == state.ringend {
				break
			}
		}
	}
	return nil, fmt.Errorf(fmt.Sprintf("TryKeyRing : no key found in ring ratchetnum = %d", ratchetnum))
}

//TrySkippedMessageKeys :
func TrySkippedMessageKeys(state *Signalstate, head Mesghead, ciphertext []byte) ([]byte, error) {
	var skip skipkey
	skip.key = head.Pubkey
	skip.num = head.Sendnum
	key, ok := state.skipped[skip]
	if ok {
		delete(state.skipped, skip)
		state.Mesgkey = key
		return Decrypt(ciphertext, key)
	}
	return nil, nil
}

//SkipMessageKeys :
func SkipMessageKeys(state *Signalstate, until uint64) error {
	var key *[KeySize]byte
	var skip skipkey
	var err error

	if state.recvnum+MaxSkip < until {
		panic("too many skipped messages")
	}
	if state.recvchain != nil {
		for state.recvnum < until {
			state.recvchain, key, err = KdfCk(state.recvchain, &state.rparam)
			if err != nil {
				return err
			}
			skip.key = state.rpubkey
			skip.num = state.recvnum
			state.skipped[skip] = key
			state.recvnum++
		}
	}
	return nil
}

//DHRatchet :
func DHRatchet(state *Signalstate, head Mesghead) error {
	var err error

	state.nummesg = state.sendnum
	state.sendnum = 0
	state.recvnum = 0
	state.rpubkey = head.Pubkey
	state.rootkey, state.recvchain, err = KdfRk(state.rootkey, NewDh(state.sendpair, state.rpubkey), &state.rparam)
	if err != nil {
		return err
	}
	state.sendpair, err = GenerateDh()
	if err != nil {
		return err
	}
	state.rootkey, state.sendchain, err = KdfRk(state.rootkey, NewDh(state.sendpair, state.rpubkey), &state.rparam)
	return err
}

//NewDh : New elliptic curve Diffie-Hellman
func NewDh(pair Keypair, pubkey *[KeySize]byte) *[KeySize]byte {
	var dhout [KeySize]byte
	curve25519.ScalarMult(&dhout, pair.Prikey, pubkey)
	return &dhout
}

//KdfRk : New root key derivation function - returns new root key and new chain key
func KdfRk(rootkey *[KeySize]byte, dhout *[KeySize]byte, rparam *Ratchetparam) (*[KeySize]byte, *[KeySize]byte, error) {
	key, err := scrypt.Key(rootkey[0:KeySize], dhout[0:KeySize], rparam.ScryptN, 8, 1, KeySize*2)
	if err != nil {
		return nil, nil, err
	}
	var rkey [KeySize]byte
	var ckey [KeySize]byte
	copy(rkey[0:KeySize], key[0:KeySize])
	copy(ckey[0:KeySize], key[KeySize:KeySize*2])
	Zero(key)
	return &rkey, &ckey, err
}

//KdfCk : New chain key derivation function - returns new chain key and new message key
func KdfCk(chainkey *[KeySize]byte, rparam *Ratchetparam) (*[KeySize]byte, *[KeySize]byte, error) {
	key, err := scrypt.Key(chainkey[0:KeySize], constant[0:KeySize], rparam.ScryptN, 8, 1, KeySize*2)
	if err != nil {
		return nil, nil, err
	}
	var ckey [KeySize]byte
	var mkey [KeySize]byte
	copy(ckey[:KeySize], key[:KeySize])
	copy(mkey[:KeySize], key[KeySize:])
	Zero(key)
	return &ckey, &mkey, err
}

//GenerateDh :
func GenerateDh() (Keypair, error) {
	var pair Keypair
	public, private, err := KeyPair()
	if err == nil {
		pair.Prikey = private
		pair.Pubkey = public
	}
	return pair, err
}

//Ratchet : test and return if ratchet is needed
func Ratchet(state *Signalstate) bool {
	if state.rparam.Count > 0 {
		if state.rparam.Last >= state.rparam.Count {
			state.rparam.Last = 0
			if state.rparam.Period > 0 {
				state.rparam.Ltime = time.Now()
			}
			return true
		}
		state.rparam.Last++
	}
	if state.rparam.Period > 0 {
		now := time.Now()
		if int(now.Sub(state.rparam.Ltime).Hours()) >= state.rparam.Period {
			state.rparam.Last = 0
			state.rparam.Ltime = now
			return true
		}
	}
	return false
}

//SetRatchet : set ratchet parameters, message count between ratchets, period in hours between ratchets, security level
func SetRatchet(state *Signalstate, count int, period int, level int) error {
	if level == VLowSec {
		state.rparam.ScryptN = 8192 //
	} else if level == LowSec {
		state.rparam.ScryptN = 16384 //Current scrypt default, ~100ms
	} else if level == MedSec {
		state.rparam.ScryptN = 32768 //Login safe as of 2017, ~200ms
	} else if level == HighSec {
		state.rparam.ScryptN = 65536 //Near term safe
	} else if level == VHighSec {
		state.rparam.ScryptN = 104857 //Longer term or files
	} else {
		return errors.New("Invalid ratchet security level")
	}
	state.rparam.Count = count
	state.rparam.Period = period
	state.rparam.Last = 0
	state.rparam.Ltime = time.Now()
	return nil
}

//ScryptN : return the scrypt KDF algorithm 'N' value
func ScryptN(state *Signalstate) int {
	return state.rparam.ScryptN
}

//SetScryptN : set the scrypt KDF algorithm 'N' value
func SetScryptN(state *Signalstate, scryptn int) {
	state.rparam.ScryptN = scryptn
}

//Level : return the level for a string level
func Level(level string) (int, error) {
	var rlevel int

	switch level {
	case "verylow":
		rlevel = VLowSec
	case "low":
		rlevel = LowSec
	case "medium":
		rlevel = MedSec
	case "high":
		rlevel = HighSec
	case "veryhigh":
		rlevel = VHighSec
	default:
		return rlevel, errors.New("Invalid security level [" + level +
			"]: use 'verylow', low', 'medium', 'high', or 'veryhigh'")
	}

	return rlevel, nil
}
