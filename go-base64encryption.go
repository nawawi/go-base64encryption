package base64encryption

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
)

// Base64Encryption provides methods for encrypting and decrypting strings using base64 encoding
// and a simple XOR-based obfuscation technique.
type Base64Encryption struct {
	prefix string // Prefix used to identify encrypted values
	key    string // Key used for obfuscation during encryption and decryption
}

// NewBase64Encryption creates a new Base64Encryption instance with the provided secret key.
// If the secret key is empty, a default key from the environment variable "BASE64_ENCRYPTION_KEY" is used.
// Parameters:
//
//	secretKey: A string used as the key for encryption and decryption. If empty, a default key is used.
//
// Returns:
//
//	*Base64Encryption: A pointer to a new Base64Encryption instance.
func NewBase64Encryption(secretKey string) *Base64Encryption {
	be := &Base64Encryption{prefix: "a0bc09"}
	if secretKey != "" {
		be.key = strings.TrimSpace(secretKey)
	} else {
		be.key = be.getDefaultKey()
	}
	return be
}

// Encrypt encrypts the given value using the provided secret key. If the secret key is empty,
// the instance's key is used. If the value is already encrypted, it is returned as-is.
// Encryption is achieved by XORing the value with an obfuscated key and then encoding it in base64.
// Parameters:
//
//	value: The string to be encrypted. If empty or already encrypted, it is returned as-is.
//	secretKey: A string used as the key for encryption. If empty, the instance's key is used.
//
// Returns:
//
//	string: The encrypted value, prefixed with the instance's prefix, or the original value if it was empty or already encrypted.
//
// Usage Example:
//
//	enc := be.Encrypt("mySecretValue", "mySecretKey")
func (be *Base64Encryption) Encrypt(value string, secretKey string) string {
	if value == "" || be.isEncrypted(value) {
		return value
	}

	if secretKey != "" {
		secretKey = strings.TrimSpace(secretKey)
	} else {
		secretKey = be.key
	}

	if secretKey == "" {
		return value
	}

	encPad := secretKey
	if len(secretKey) > 12 {
		encPad = secretKey[:12]
	}
	value = encPad + value

	obfuscate := be.obfuscate(secretKey)
	if len(obfuscate) == 0 {
		return value
	}

	encrypted := make([]byte, len(value))
	for i := range value {
		encrypted[i] = value[i] ^ obfuscate[i%len(obfuscate)]
	}

	return be.prefix + be.encode(string(encrypted))
}

// Decrypt decrypts the given encrypted value using the provided secret key. If the secret key is empty,
// the instance's key is used. If the value is not encrypted, it is returned as-is.
// Decryption is achieved by decoding from base64 and XORing with the obfuscated key.
// Parameters:
//
//	encryptedValue: The base64-encoded, encrypted string to be decrypted. Must start with the instance's prefix.
//	secretKey: A string used as the key for decryption. If empty, the instance's key is used.
//
// Returns:
//
//	string: The decrypted value, or the original encrypted value if it could not be decrypted.
//
// Usage Example:
//
//	dec := be.Decrypt("a0bc09<base64-encoded-encrypted-value>", "mySecretKey")
func (be *Base64Encryption) Decrypt(encryptedValue string, secretKey string) string {
	if encryptedValue == "" || !be.isEncrypted(encryptedValue) {
		return encryptedValue
	}

	value := encryptedValue[len(be.prefix):]
	if secretKey != "" {
		secretKey = strings.TrimSpace(secretKey)
	} else {
		secretKey = be.key
	}

	if secretKey == "" {
		return value
	}

	obfuscate := be.obfuscate(secretKey)
	if len(obfuscate) == 0 {
		return encryptedValue
	}

	decoded := be.decode(value)
	decrypted := make([]byte, len(decoded))
	for i := range decoded {
		decrypted[i] = decoded[i] ^ obfuscate[i%len(obfuscate)]
	}

	encPad := secretKey
	if len(secretKey) > 12 {
		encPad = secretKey[:12]
	}
	if len(decrypted) < len(encPad) || encPad != string(decrypted[:len(encPad)]) {
		return encryptedValue
	}

	return string(decrypted[len(encPad):])
}

// isEncrypted checks if the given value is encrypted by matching it against the prefix pattern.
// Parameters:
//
//	value: The string to check if it is encrypted.
//
// Returns:
//
//	bool: True if the value is encrypted (starts with the prefix), false otherwise.
//
// Usage Example:
//
//	isEnc := be.isEncrypted("a0bc09<base64-encoded-encrypted-value>")
func (be *Base64Encryption) isEncrypted(value string) bool {
	re := regexp.MustCompile("^" + regexp.QuoteMeta(be.prefix) + "([a-zA-Z0-9\\-_]+)$")
	return re.MatchString(value)
}

// setPrefix sets a new prefix for identifying encrypted values.
// Parameters:
//
//	value: The new prefix to be set.
//
// Returns:
//
//	string: The updated prefix.
//
// Usage Example:
//
//	newPrefix := be.setPrefix("newPrefix")
func (be *Base64Encryption) setPrefix(value string) string {
	be.prefix = value
	return be.prefix
}

// setKey sets a new key for obfuscation during encryption and decryption.
// Parameters:
//
//	value: The new key to be set.
//
// Returns:
//
//	string: The updated key.
//
// Usage Example:
//
//	newKey := be.setKey("newSecretKey")
func (be *Base64Encryption) setKey(value string) string {
	be.key = value
	return be.key
}

// getEnv retrieves the value of the environment variable with the given name.
// Parameters:
//
//	name: The name of the environment variable.
//
// Returns:
//
//	string: The value of the environment variable.
//
// Usage Example:
//
//	value := be.getEnv("BASE64_ENCRYPTION_KEY")
func (be *Base64Encryption) getEnv(name string) string {
	return os.Getenv(name)
}

// getDefaultKey retrieves the default key from the environment variable "BASE64_ENCRYPTION_KEY".
// Returns:
//
//	string: The default key, or an empty string if the environment variable is not set.
//
// Usage Example:
//
//	defaultKey := be.getDefaultKey()
func (be *Base64Encryption) getDefaultKey() string {
	if key := be.getEnv("BASE64_ENCRYPTION_KEY"); key != "" {
		return strings.TrimSpace(key)
	}
	return ""
}

// encode encodes the given value to base64 and replaces characters to make it URL-safe.
// Parameters:
//
//	value: The string to be encoded.
//
// Returns:
//
//	string: The base64-encoded, URL-safe representation of the input string.
//
// Usage Example:
//
//	encoded := be.encode("myString")
func (be *Base64Encryption) encode(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(value)), "+", "-"), "/", "_"), "=", "")
}

// decode decodes the given base64-encoded value and restores URL-safe characters.
// Parameters:
//
//	value: The base64-encoded, URL-safe string to be decoded.
//
// Returns:
//
//	string: The decoded string.
//
// Usage Example:
//
//	decoded := be.decode("bXlTdHJpbmc_")
func (be *Base64Encryption) decode(value string) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "-", "+"), "_", "/")
	for len(value)%4 != 0 {
		value += "="
	}
	decoded, _ := base64.StdEncoding.DecodeString(value)
	return string(decoded)
}

// obfuscate obfuscates the given value by decoding it from base64.
// Parameters:
//
//	value: The base64-encoded string to be obfuscated.
//
// Returns:
//
//	[]byte: The obfuscated byte slice.
//
// Usage Example:
//
//	obf := be.obfuscate("base64encodedkey")
func (be *Base64Encryption) obfuscate(value string) []byte {
	obfuscated, _ := base64.StdEncoding.DecodeString(value)
	return obfuscated
}
