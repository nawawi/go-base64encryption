# Base64 Encryption

The `base64encryption` package provides simple methods for encrypting and decrypting strings using base64 encoding along with a basic XOR-based obfuscation technique. This package is useful for scenarios where you need to securely encode and decode sensitive information with a key.

## Installation

To use this package, you need to include it in your Go module. If you're using Go modules, you can add it to your project with:

```bash
go get github.com/nawawi/go-base64encryption
```

## Usage

### Importing

import it as "github.com/nawawi/go-base64encryption", use it as base64encryption.

```go
import "github.com/nawawi/go-base64encryption"
```

### Creating an Instance
You can create a new instance of `Base64Encryption` with or without a secret key:

```go
// Create a new instance with a provided key
be := base64encryption.NewBase64Encryption("mySecretKey")

// Create a new instance with an empty key, which will use the default key from the environment variable
be := base64encryption.NewBase64Encryption("")
```

### Encrypting a Value
Encrypt a string with a key:

```go
encrypted := be.Encrypt("mySensitiveData", "mySecretKey")
```

If you do not provide a key, the instance's key will be used:

```go
encrypted := be.Encrypt("mySensitiveData", "")
```

### Decrypting a Value
Decrypt an encrypted string with a key:

```go
decrypted := be.Decrypt(encrypted, "mySecretKey")
```

if you do not provide a key, the instance's key will be used:

```go
decrypted := be.Decrypt(encrypted, "")
```

### Setting Prefix and Key
You can set a new prefix and key for encryption:

```go
be.setPrefix("newPrefix")
be.setKey("newSecretKey")
```

### Checking if a Value is Encrypted
To check if a value is encrypted:

```go
isEncrypted := be.isEncrypted(encryptedValue)
```

## Testing
To run the tests for this package, use:

```go
go test
```

The tests will check the functionality of encryption, decryption, setting keys and prefixes, and more.

## License
This package is open-source and available under the [MIT License](./LICENSE).

## Contributing
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## Contact
For support or questions, please open an issue on the [GitHub repository](https://github.com/nawawi/go-base64encryption/issues)