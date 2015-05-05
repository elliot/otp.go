package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
)

type HOTP struct {
	Secret  string // Shared Secret
	Counter uint64 // Incrementing Shared Counter
	Window  int    // How many values should be tested to stay in sync
	Length  int    // Number of digits in OTP output
}

func (h *HOTP) counter() []byte {
	bytes := make([]byte, 8)

	binary.BigEndian.PutUint64(bytes, h.Counter)

	return bytes
}

func (h *HOTP) hmac(key, counter []byte) []byte {
	hmac := hmac.New(sha1.New, key)
	hmac.Write(counter)

	return hmac.Sum(nil)
}

func (h *HOTP) truncate(hash []byte) int {
	offset := int(hash[len(hash)-1] & 0xf)

	result := int(hash[offset+0]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff)

	return result
}

func (h *HOTP) Generate() string {
	// Stage 0: Convert the secret to a byte array key
	key := []byte(h.Secret)

	// Stage 1: Generate hash = HMAC-SHA-1(Key, Counter)
	hashed := h.hmac(key, h.counter())

	// Stage 2: Generate a 4-byte string (Dynamic Truncation)
	truncated := h.truncate(hashed)

	// Stage 3: Trim the output to the desired number of digits, zero-padding
	otp := int64(truncated) % int64(math.Pow10(int(h.Length)))

	var output string

	output = fmt.Sprintf("%%0%dd", h.Length)
	output = fmt.Sprintf(output, otp)

	return output
}

func (h *HOTP) Verify() {
	// TODO: Implement forward scanning according to value in h.Window
}

func (h *HOTP) URL(label string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   label,
	}

	v := url.Values{}
	v.Add("secret", h.Secret)
	v.Add("counter", strconv.FormatUint(h.Counter, 10))

	u.RawQuery = v.Encode()

	return u.String()
}
