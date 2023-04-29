//Package aescbc provides higher-level functions to encrypt and decrypt data
//with AES in CBC mode. An encryptor and decryptor are included, both of which
//implement the io.ReadWriter interface.

package aescbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// The AESCBCEncryptor type is used to encrypt plaintext data to AES-CBC encrypyted
// ciphertext.
//
// This type should be created by NewEncryptor() rather than by directly
// instantiating the type in your code.
//
// Exported fields:
// IV: the initialization vector used to initialize the AES cipher
// AESKey: the AES key used to initialize the AES cipher
// CopyBufferSize: the size (in bytes) of the read/write buffer that Copy() will use
type AESCBCEncryptor struct {
	IV             []byte
	AESKey         []byte
	CopyBufferSize int64
	inputoverflow  []byte
	outputoverflow []byte
	cipher         cipher.Block
	cbc            cipher.BlockMode
	isClosed       bool
}

// NewEncrypytor returns an Encryptor instance with properly initialized member variables.
// The AESKey and IV are populated from crypto/rand and the internal AES cihper
// and CBC BlockMode are properly initialized.
//
// After calling NewEncryptor() the calling application should copy the AESKey and
// the IV so that they can be provided to the decrypting application.
//
// There is no functionality to manually set the AESKey or the IV. Writing to these
// values after instantiation will not change the state of the cipher or block
// mode.
func NewAESCBCEncryptor() (*AESCBCEncryptor, error) {
	var err error
	var e AESCBCEncryptor

	//generate a random AES key
	e.AESKey = make([]byte, 32)
	_, err = rand.Read(e.AESKey)
	if err != nil {
		return nil, err
	}

	//generate a random initialization vector
	e.IV = make([]byte, 16)
	_, err = rand.Read(e.IV)
	if err != nil {
		return nil, err
	}

	//input overflow is used when Write() gives us a partial
	//AES block. The remaining bytes, to be used in the next
	//block, are stored here
	//input overflow should never exceed the AES block size
	e.inputoverflow = make([]byte, 0, 16)

	//The output overflow holds encrypted data that hasn't yet been
	//read by Read(). It can grow unbounded as additional data is written.
	e.outputoverflow = make([]byte, 0)

	//Generate an AES cipher in CBC mode
	e.cipher, err = aes.NewCipher(e.AESKey)
	if err != nil {
		return nil, err
	}

	//Generate the CBC manager on top of the AES cipher
	e.cbc = cipher.NewCBCEncrypter(e.cipher, e.IV)

	//Provide a default copy block size of 5MB
	e.CopyBufferSize = 5 * 1024 * 1024

	e.isClosed = false
	return &e, nil
}

// Write implements io.Writer and accepts plaintext to be encrypted. After writing
// plaintext to Write(), ciphertext will become available on the Read() method.
//
// The last block or partial block of plaintext is internally buffered until the
// Close() method is called so that padding can be added to the cipher text.
//
// The Close() method should be called after the last plaintext has been written
// to Write().
func (e *AESCBCEncryptor) Write(p []byte) (n int, err error) {
	//If the writer is closed, error out
	if e.isClosed {
		return 0, errors.New("writer has been closed")
	}

	//If there's any existing input overflow, that must be
	//prepended to the incoming data
	if len(e.inputoverflow) > 0 {
		p = append(e.inputoverflow, p...)
	}

	//We can only encrypt multiples of the block size. If
	//the input is not a multiple of the block size, save the
	//extra in the inputoverflow
	//
	//If the input is a multiple of a full block, keep the last block
	//in the inputoverflow buffer.
	//
	//This way we can correctly pad the last block of data when Close() is called.
	if len(p)%e.cbc.BlockSize() != 0 {
		//Take advantage of integer division here to calculate sizes
		numFullBlocks := len(p) / e.cbc.BlockSize()
		sizeFullBlocks := numFullBlocks * e.cbc.BlockSize()
		extraBytes := len(p) - sizeFullBlocks

		e.inputoverflow = append([]byte(nil), p[len(p)-extraBytes:]...)
		p = p[:sizeFullBlocks]
	} else {
		//We need to retain the last block of plaintext for padding.
		e.inputoverflow = p[len(p)-e.cbc.BlockSize():]
		p = p[:len(p)-e.cbc.BlockSize()]
	}

	//Encrypt the plaintext to a ciphertext slice
	cipherText := make([]byte, len(p))
	e.cbc.CryptBlocks(cipherText, p)

	//append the new ciphertext to the output waiting to be read
	e.outputoverflow = append(e.outputoverflow, cipherText...)
	return len(p), nil
}

// Read implements io.Reader and returns ciphertext that has been encrypted.
// Data is available on Read() after plaintext has been written to Write().
// If no ciphertext is available, a zero-byte slice is returned and error
// is nil. Error will return io.EOF after the Close() method has been called
// and no more data is available to read.
//
// The encryptor must hold on to at least 16 bytes of plaintext so that there's
// enough plaintext to add padding when Close() is called.
func (e *AESCBCEncryptor) Read(p []byte) (n int, err error) {
	if e.isClosed && len(e.outputoverflow) == 0 {
		return 0, io.EOF
	}

	if len(p) >= len(e.outputoverflow) {
		//We can send all of our data to the caller
		n = copy(p, e.outputoverflow)
		e.outputoverflow = e.outputoverflow[:0]
		return n, nil
	} else {
		//We can only return some of our waiting data
		n = copy(p, e.outputoverflow)
		e.outputoverflow = e.outputoverflow[n:]
		return n, nil
	}
}

// Close is used to signal no more data will be written to the Encryptor. After
// Close() is called, PKCS7 padding is added to the plaintext to aid in proper
// decryption and the padded data is added to the ciphertext that is available
// on the Read() method.
//
// At least one more call to Read() mustbe peformed after calling Close() to
// ensure all ciphertext has been read.
func (e *AESCBCEncryptor) Close() {
	//We need to pad the last block and encrypt it
	p := Pkcs7Pad(e.inputoverflow, e.cbc.BlockSize())
	lastBlock := make([]byte, len(p))
	e.cbc.CryptBlocks(lastBlock, p)
	e.outputoverflow = append(e.outputoverflow, lastBlock...)
	e.isClosed = true
}

// Copy encrypts the data read from the io.Reader and writes it
// to io.Writer. As part of the encryption process, the AES initialization vector
// (IV) is prepended to the ciphertext so that it can be recovered from the data
// stream by the decryptor.
//
// The read buffer size is taken from the CopyReadBufferSizeHint member variable
func (e *AESCBCEncryptor) Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	shouldClose := false
	written = int64(0)
	inputBuf := make([]byte, e.CopyBufferSize)

	//Write the IV to the output stream
	dst.Write(e.IV)
	written += int64(len(e.IV))

	//Read until we get an EOF
	for {
		//Read from the source file
		n, err := src.Read(inputBuf)
		if err == io.EOF {
			shouldClose = true
		} else {
			if err != nil {
				return written, err
			}
		}

		//Write plaintext to the encryptor
		e.Write(inputBuf[:n])

		//Read ciphertext from the encryptor
		n, _ = e.Read(inputBuf)

		//Write ciphertext to the destination file
		n, err = dst.Write(inputBuf[:n])
		written += int64(n)
		if err != nil {
			return written, err
		}

		if shouldClose {
			e.Close()
			//Read any remaining ciphertext
			for {
				n, _ = e.Read(inputBuf)
				if n == 0 {
					break
				}
				n, err = dst.Write(inputBuf[:n])
				if err != nil {
					return written, err
				}
				written += int64(n)
			}
			break
		}
	}
	return written, nil
}
