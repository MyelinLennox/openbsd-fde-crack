// Command openbsd-fde-extract extracts OpenBSD softraid CRYPTO metadata
// from a raw disk image in the format accepted by Hashcat mode 38800.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	sectorSize      int64 = 512
	metadataOffset        = 16 * sectorSize
	metadataBytes         = 64 * sectorSize
	cryptoOption          = 1
	maskAES256ECB         = 1
	checkHMACSHA1         = 1
	kdfPBKDF2             = 1
	kdfKeyDisk            = 2
	kdfBcrypt             = 3
	oldOptionSize         = 2480
	oldOptionOffset       = 8
	chunkSize             = 92
)

var magicLE = []byte{0x6d, 0x61, 0x72, 0x63, 0x43, 0x52, 0x41, 0x4d}
var magicBE = []byte{0x4d, 0x41, 0x52, 0x43, 0x63, 0x72, 0x61, 0x6d}

type hashRecord struct {
	Rounds uint32
	Salt   []byte
	Keys   []byte
	Check  []byte
	KDF    uint32
}

func endianFor(block []byte) (binary.ByteOrder, bool) {
	if bytes.Equal(block[:8], magicLE) {
		return binary.LittleEndian, true
	}
	if bytes.Equal(block[:8], magicBE) {
		return binary.BigEndian, true
	}
	return nil, false
}

func u32(order binary.ByteOrder, b []byte) uint32 { return order.Uint32(b) }

func parseAt(block []byte) (hashRecord, error) {
	if len(block) < 80 {
		return hashRecord{}, errors.New("metadata block is truncated")
	}
	order, ok := endianFor(block)
	if !ok {
		return hashRecord{}, errors.New("no OpenBSD softraid magic")
	}

	// sr_meta_invariant: 8sII16sIIIIIIq8s16s4sI
	invariantLen := 8 + 4 + 4 + 16 + 6*4 + 8 + 8 + 16 + 4 + 4
	metadataLen := 16 + 32 + 4 + 4 + 8 + 8
	if len(block) < invariantLen+metadataLen {
		return hashRecord{}, errors.New("metadata block is truncated")
	}
	invariant := block[:invariantLen]
	var stored [16]byte
	copy(stored[:], block[invariantLen:invariantLen+16])
	digest := md5.Sum(invariant)
	if !bytes.Equal(digest[:], stored[:]) {
		return hashRecord{}, errors.New("metadata MD5 mismatch")
	}

	chunkNo := u32(order, invariant[32:36])
	optNo := u32(order, invariant[52:56])
	pos := invariantLen + metadataLen + int(chunkNo)*chunkSize

	for i := uint32(0); i < optNo; i++ {
		if pos+24 > len(block) {
			break
		}
		typ := u32(order, block[pos:pos+4])
		length := u32(order, block[pos+4:pos+8])
		body := pos + 24
		step := int(length)
		if length == 0 {
			body = pos + oldOptionOffset
			step = oldOptionSize
		}
		if typ == cryptoOption {
			// sr_meta_crypto: IIII64s2048s256sII64s
			cryptoLen := 4*4 + 64 + 2048 + 256 + 4 + 4 + 64
			if body+cryptoLen > len(block) {
				return hashRecord{}, errors.New("CRYPTO metadata is truncated")
			}
			maskAlg := u32(order, block[body+8:body+12])
			checkAlg := u32(order, block[body+2388:body+2392])
			if maskAlg != maskAES256ECB {
				return hashRecord{}, fmt.Errorf("unsupported key masking algorithm %d", maskAlg)
			}
			if checkAlg != checkHMACSHA1 {
				return hashRecord{}, fmt.Errorf("unsupported key check algorithm %d", checkAlg)
			}

			kdfOffset := body + 16 + 64 + 2048 + 256 + 8
			if kdfOffset+140 > len(block) {
				return hashRecord{}, errors.New("KDF metadata is truncated")
			}
			kdf := u32(order, block[kdfOffset+4:kdfOffset+8])
			rounds := u32(order, block[kdfOffset+8:kdfOffset+12])
			if rounds == 0 {
				return hashRecord{}, errors.New("KDF round count is zero")
			}
			if kdf != kdfPBKDF2 {
				return hashRecord{}, fmt.Errorf("KDF %d is not PBKDF2; use Hashcat mode 38810 for bcrypt", kdf)
			}

			r := hashRecord{Rounds: rounds, Salt: append([]byte(nil), block[kdfOffset+12:kdfOffset+140]...), Keys: append([]byte(nil), block[body+80:body+2128]...), Check: append([]byte(nil), block[body+2128:body+2148]...), KDF: kdf}
			return r, nil
		}
		if step <= 0 {
			break
		}
		pos += step
	}
	return hashRecord{}, errors.New("metadata is not a passphrase-protected CRYPTO volume")
}

func hashcatLine(r hashRecord) string {
	return fmt.Sprintf("$openbsd-softraid$%d$%s$%s$%s$%d\n", r.Rounds, hex.EncodeToString(r.Salt), hex.EncodeToString(r.Keys), hex.EncodeToString(r.Check), r.KDF)
}

// verifyMaskKey checks a candidate key-disk mask against the image metadata.
func verifyMaskKey(maskKey, encrypted, expected []byte) bool {
	if len(maskKey) != 32 || len(encrypted)%aes.BlockSize != 0 || len(expected) != sha1.Size {
		return false
	}
	cipher, err := aes.NewCipher(maskKey)
	if err != nil {
		return false
	}
	plain := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i += aes.BlockSize {
		cipher.Decrypt(plain[i:i+aes.BlockSize], encrypted[i:i+aes.BlockSize])
	}
	maskDigest := sha1.Sum(maskKey)
	mac := hmac.New(sha1.New, maskDigest[:])
	_, _ = mac.Write(plain)
	return subtle.ConstantTimeCompare(mac.Sum(nil), expected) == 1
}

func scanKeyFile(path string, record hashRecord) (int64, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(keyData) < 32 {
		return 0, fmt.Errorf("key file is too small: got %d bytes, need at least 32", len(keyData))
	}
	// Try every byte offset. This covers normal 16-byte block boundaries and
	// handles arbitrary junk or padding before and after the actual key.
	for offset := 0; offset+32 <= len(keyData); offset++ {
		if verifyMaskKey(keyData[offset:offset+32], record.Keys, record.Check) {
			return int64(offset), nil
		}
	}
	return 0, errors.New("no valid 32-byte key found in the key file")
}

func readAt(f *os.File, offset int64) ([]byte, error) {
	b := make([]byte, metadataBytes)
	n, err := f.ReadAt(b, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b[:n], nil
}

func findRecord(f *os.File, size int64) (hashRecord, int64, error) {
	tried := map[int64]bool{}
	try := func(offset int64) (hashRecord, bool) {
		if offset < 0 || offset >= size || tried[offset] {
			return hashRecord{}, false
		}
		tried[offset] = true
		b, err := readAt(f, offset)
		if err != nil {
			return hashRecord{}, false
		}
		r, err := parseAt(b)
		return r, err == nil
	}
	if r, ok := try(metadataOffset); ok {
		return r, metadataOffset, nil
	}
	for offset := int64(0); offset+8 <= size; offset += sectorSize {
		b, err := make([]byte, 8), error(nil)
		if _, err = f.ReadAt(b, offset); err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		if !bytes.Equal(b, magicLE) && !bytes.Equal(b, magicBE) {
			continue
		}
		if r, ok := try(offset); ok {
			return r, offset, nil
		}
	}
	// Preserve compatibility with the original project, which accepted a
	// metadata-only blob from older OpenBSD softraid layouts.
	if size >= 10888 {
		read := func(offset int64, n int) []byte {
			b := make([]byte, n)
			if got, _ := f.ReadAt(b, offset); got == n {
				return b
			}
			return nil
		}
		roundsBytes, salt, keys, check := read(10612, 4), read(10616, 128), read(8556, 2048), read(10868, 20)
		if roundsBytes != nil && salt != nil && keys != nil && check != nil {
			return hashRecord{Rounds: binary.LittleEndian.Uint32(roundsBytes), Salt: salt, Keys: keys, Check: check, KDF: kdfPBKDF2}, 0, nil
		}
	}
	return hashRecord{}, 0, errors.New("no passphrase-protected OpenBSD softraid CRYPTO metadata found")
}

func main() {
	input := flag.String("i", "", "path to a raw disk image (.img, .dd, or equivalent)")
	keyFile := flag.String("k", "", "test a raw key file against the image metadata")
	output := flag.String("o", "", "write the Hashcat line to this file (default: stdout)")
	flag.Parse()
	if *input == "" {
		flag.Usage()
		os.Exit(2)
	}
	f, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		fatal(err)
	}
	r, offset, err := findRecord(f, info.Size())
	if err != nil {
		fatal(err)
	}
	if *keyFile != "" {
		keyOffset, err := scanKeyFile(*keyFile, r)
		if err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stdout, "valid key found at offset %d in %s\n", keyOffset, *keyFile)
		return
	}
	line := hashcatLine(r)
	if *output == "" {
		_, err = fmt.Print(line)
	} else {
		err = os.WriteFile(*output, []byte(line), 0600)
	}
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "metadata found at offset %d; use Hashcat mode 38800\n", offset)
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
