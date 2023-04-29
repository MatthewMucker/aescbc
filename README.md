# aescbc
A library for encrypting/decrypting data streams with AES-CBC in the Go programming language

## TL;DR
So you want to encrypt a file with AES without reading the manual. Probably not the best idea, but here you go:

```
src, _ := os.Open("SourceFile.txt")
dst, _ := os.Create("EncryptedFile.aes")

enc, _ := NewAESCBCEncryptor()
enc.Copy(dst, src)

aesKey := enc.AESKey
iv := enc.IV

dst.Close()
src.Close()
```

and to decrypt:

```
src, _ := os.Open("EncryptedFile.aes")
dst, _ := os.Create("DecryptedFile.txt")

dec, _ := NewAESCBCDecryptor(aesKey, iv)
dec.Copy(dst, src)

dst.Close()
src.Close()
```

# Introduction
This README is a condensed version of an article I published on Medium at https://medium.com/p/db961e0626cc. For more context, please see that article.

The aescbc library provides high-level wrappers that implement the Reader and Writer interfaces to encrypt and decrypt data.