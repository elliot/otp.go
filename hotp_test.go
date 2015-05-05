package otp

import (
	"testing"
)

func TestHOTP(t *testing.T) {
	// See RFC: https://tools.ietf.org/html/rfc4226#page-32
	var secret = "12345678901234567890"

	var testVectors = []struct {
		count uint64
		hex   string
		dec   string
		otp   string
	}{
		{0, "4c93cf18", "1284755224", "755224"},
		{1, "41397eea", "1094287082", "287082"},
		{2, "82fef30", "137359152", "359152"},
		{3, "66ef7655", "1726969429", "969429"},
		{4, "61c5938a", "1640338314", "338314"},
		{5, "33c083d4", "868254676", "254676"},
		{6, "7256c032", "1918287922", "287922"},
		{7, "4e5b397", "82162583", "162583"},
		{8, "2823443f", "673399871", "399871"},
		{9, "2679dc69", "645520489", "520489"},
	}

	for _, tv := range testVectors {
		otp := &HOTP{
			Secret:  secret,
			Counter: tv.count,
			Length:  6,
		}

		result := otp.Generate()

		if result != tv.otp {
			t.Errorf("otp.HOTP(%d) [secret: '%s']: expected '%s', got '%s'", tv.count, secret, tv.otp, result)
		}
	}
}

func TestHOTPURL(t *testing.T) {
	expected := "otpauth://hotp/testing?counter=0&secret=12345678901234567890"

	otp := &HOTP{
		Secret:  "12345678901234567890",
		Counter: 0,
	}

	result := otp.URL("testing")

	if result != expected {
		t.Errorf("URL('testing'): expected: %s, got: %s", expected, result)
	}
}
