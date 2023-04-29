//Package aescbc provides higher-level functions to encrypt and decrypt data
//with AES in CBC mode. An encryptor and decryptor are included, both of which
//implement the io.ReadWriter interface.

package aescbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// The Decryptor type is used to decrypt data in AES-CBC to
// plaintext.
//
// This type should be created by NewDecryptor() rather than by directly
// instantiating the type in your code.

type AESCBCDecryptor struct {
	iv             []byte
	aesKey         []byte
	CopyBufferSize int64
	inputoverflow  []byte
	outputoverflow []byte
	cipher         cipher.Block
	cbc            cipher.BlockMode
	isClosed       bool
}

// NewDecrypytor returns a Decryptor instance with properly initialized member variables.
// The AESKey and IV must be supplied and must be the same key and IV
// used to encrypt the data.

func NewAESCBCDecryptor(aesKey []byte, iv []byte) (*AESCBCDecryptor, error) {
	var err error
	var e AESCBCDecryptor

	if len(aesKey) != 32 {
		return nil, errors.New("aes key must be 32 bytes long")
	}
	e.aesKey = aesKey

	if len(iv) != 16 {
		return nil, errors.New("IV must be 16 bytes long")
	}
	e.iv = iv

	//input overflow is used when Write() gives us a partial
	//AES block. The remaining bytes, to be used in the next
	//block, are stored here
	//input overflow should never exceed the AES block size
	e.inputoverflow = make([]byte, 0)

	//Generate an AES cipher in CBC mode
	e.cipher, err = aes.NewCipher(e.aesKey)
	if err != nil {
		return nil, err
	}

	e.cbc = cipher.NewCBCDecrypter(e.cipher, e.iv)

	e.outputoverflow = make([]byte, 0)

	//Provide a default copy block size of 5MB
	e.CopyBufferSize = 5 * 1024 * 1024

	e.isClosed = false
	return &e, nil
}

// BytesAvailable returns the number of unread plaintext bytes available
// to read.
//
// DEVELOPER NOTE: Due to padding of the last block, it is impossible to know
// how much data is available to read. Therfore this function has been commented
// out while a solution is contemplated.
// func (e *AESCBCDecryptor) BytesAvailable() int {
// 	return len(e.outputoverflow)
// }

// Write implements io.Writer and accepts ciphertext to be decrypted. After writing
// ciphertext to Write(), plaintext will become available on the Read() method.
//
// The Close() method should be called after the last plaintext has been written
// to Write().
func (e *AESCBCDecryptor) Write(p []byte) (n int, err error) {
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
	if len(p)%e.cbc.BlockSize() != 0 {
		//Take advantage of integer division here to calculate sizes
		numFullBlocks := len(p) / e.cbc.BlockSize()
		sizeFullBlocks := numFullBlocks * e.cbc.BlockSize()
		extraBytes := len(p) - sizeFullBlocks

		e.inputoverflow = make([]byte, extraBytes)
		e.inputoverflow = p[len(p)-extraBytes:]
		p = p[:sizeFullBlocks]
	} else {
		if len(e.inputoverflow) > 0 {
			e.inputoverflow = make([]byte, 0)
		}
	}

	plaintext := make([]byte, len(p))
	e.cbc.CryptBlocks(plaintext, p)

	e.outputoverflow = append(e.outputoverflow, plaintext...)
	return len(p), nil
}

// Read implements io.Reader and returns plaintext that has been decrypted.
// Data is available on Read() after ciphertext has been written to Write().
//
// The last 16 bytes of plaintext data are retainted internally until Close()
// is called, so that Close() can strip off the PKCS7 padding. The remaining
// plaintext becomes available to Read() after Close() is called. No more data
// may be written after Close() is called.
//
// If no plaintext is available, a zero-byte slice is returned and error
// is nil. Error will return io.EOF after the Close() method has been called
// and no more data is available to read.
func (e *AESCBCDecryptor) Read(p []byte) (n int, err error) {
	if len(e.outputoverflow) == 0 && e.isClosed {
		return 0, io.EOF
	}

	//We need to retain the last 16 bytes of the output, so that we
	//can remove padding when the decryptor is closed.
	bytesToRetain := 16
	if e.isClosed {
		bytesToRetain = 0
	}

	if len(p) >= len(e.outputoverflow)-bytesToRetain {
		//We can send all of our data to the caller
		n = copy(p, e.outputoverflow[:len(e.outputoverflow)-bytesToRetain])
		e.outputoverflow = e.outputoverflow[len(e.outputoverflow)-bytesToRetain:]
		return n, nil
	} else {
		//We can only return some of our waiting data
		n = copy(p, e.outputoverflow)
		e.outputoverflow = e.outputoverflow[n:]
		return n, nil
	}
}

// Close is used to signal no more data will be written to the Decryptor. After
// Close() is called, PKCS7 padding is removed from the buffered plaintext
// so that it will not be returned to the caller.
//
// At least one more call to Read() must be performed after calling Close() to
// ensure all plaintext has been read.
func (e *AESCBCDecryptor) Close() error {
	if len(e.outputoverflow) < 16 {
		return errors.New("not enough bytes in read buffer to strip PKCS7 padding")
	}

	p, err := Pkcs7Unpad(e.outputoverflow)
	if err != nil {
		return err
	}

	e.outputoverflow = p
	e.isClosed = true
	return nil
}

// Copy encrypts the data read from the io.Reader and writes it
// to io.Writer. As part of the encryption process, the AES initialization vector
// (IV) is prepended to the ciphertext so that it can be recovered from the data
// stream by the decryptor.
//
// When using Copy(), the IV in the AESCBCDecryptor is overwritten with the first
// 16 bytes of the source Reader.
//
// The read buffer size is taken from the CopyReadBufferSizeHint member variable
func (e *AESCBCDecryptor) Copy(dst io.Writer, src io.Reader) (read int64, err error) {
	shouldClose := false
	read = int64(0)
	inputBuf := make([]byte, e.CopyBufferSize)

	//Read the IV from the output stream
	src.Read(e.iv)
	read += int64(len(e.iv))

	//Read until we get an EOF
	for {
		//Read from the source file
		n, err := src.Read(inputBuf)
		if err == io.EOF {
			shouldClose = true
		} else {
			if err != nil {
				return read, err
			}
		}

		//Write cipertext to the decryptor
		e.Write(inputBuf[:n])

		//Read plaintext from the decryptor
		e.Read(inputBuf)

		//Write plaintext to the destination file
		n, err = dst.Write(inputBuf[:n])
		if err != nil {
			return read, err
		}
		read += int64(n)

		if shouldClose {
			e.Close()
			//Read any remaining ciphertext
			for {
				n, _ = e.Read(inputBuf)
				if n == 0 {
					break
				}
				read += int64(n)

				_, err = dst.Write(inputBuf[:n])
				if err != nil {
					return read, err
				}
			}
			break
		}
	}
	return read, nil
}
