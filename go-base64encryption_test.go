package base64encryption

import (
	"os"
	"testing"
)

// TestNewBase64Encryption tests the creation of a new Base64Encryption instance.
func TestNewBase64Encryption(t *testing.T) {
	// Set environment variable for testing
	os.Setenv("BASE64_ENCRYPTION_KEY", "testEnvKey")
	defer os.Unsetenv("BASE64_ENCRYPTION_KEY") // Clean up after the test

	// Test with a provided key
	be := NewBase64Encryption("testKey")
	if be.key != "testKey" {
		t.Errorf("Expected key to be 'testKey', got '%s'", be.key)
	}

	// Test with an empty key to use default from environment variable
	be = NewBase64Encryption("")
	if be.key != "testEnvKey" {
		t.Errorf("Expected key to be 'testEnvKey', got '%s'", be.key)
	}
}

// TestEncryptDecrypt tests the encryption and decryption methods of Base64Encryption.
func TestEncryptDecrypt(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")

	originalValue := "helloWorld"
	encrypted := be.Encrypt(originalValue, "")
	if encrypted == originalValue {
		t.Errorf("Expected encrypted value to be different from original value")
	}

	decrypted := be.Decrypt(encrypted, "")
	if decrypted != originalValue {
		t.Errorf("Expected decrypted value to be '%s', got '%s'", originalValue, decrypted)
	}
}

// TestEncryptEmptyValue tests encryption when the value is empty.
func TestEncryptEmptyValue(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	encrypted := be.Encrypt("", "")
	if encrypted != "" {
		t.Errorf("Expected encrypted value to be empty, got '%s'", encrypted)
	}
}

// TestDecryptEmptyValue tests decryption when the value is empty.
func TestDecryptEmptyValue(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	decrypted := be.Decrypt("", "")
	if decrypted != "" {
		t.Errorf("Expected decrypted value to be empty, got '%s'", decrypted)
	}
}

// TestSetPrefix tests setting a new prefix.
func TestSetPrefix(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	newPrefix := "newPrefix"
	be.setPrefix(newPrefix)
	if be.prefix != newPrefix {
		t.Errorf("Expected prefix to be '%s', got '%s'", newPrefix, be.prefix)
	}
}

// TestSetKey tests setting a new key.
func TestSetKey(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	newKey := "newSecretKey"
	be.setKey(newKey)
	if be.key != newKey {
		t.Errorf("Expected key to be '%s', got '%s'", newKey, be.key)
	}
}

// TestIsEncrypted tests the isEncrypted method.
func TestIsEncrypted(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	encrypted := be.Encrypt("testValue", "")
	if !be.isEncrypted(encrypted) {
		t.Errorf("Expected value to be encrypted")
	}

	notEncrypted := "plainValue"
	if be.isEncrypted(notEncrypted) {
		t.Errorf("Expected value to not be encrypted")
	}
}

// TestEncodeDecode tests the encode and decode methods.
func TestEncodeDecode(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")

	originalValue := "myString"
	encoded := be.encode(originalValue)
	decoded := be.decode(encoded)

	if originalValue != decoded {
		t.Errorf("Expected decoded value to be '%s', got '%s'", originalValue, decoded)
	}
}

// TestObfuscate tests the obfuscate method.
func TestObfuscate(t *testing.T) {
	be := NewBase64Encryption("mySecretKey")
	obfuscated := be.obfuscate("aGVsbG8=") // base64 of "hello"
	expected := "hello"

	if string(obfuscated) != expected {
		t.Errorf("Expected obfuscated value to be '%s', got '%s'", expected, string(obfuscated))
	}
}
