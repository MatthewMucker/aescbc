# aescbc
A library for encrypting/decrypting data streams with AES-CBC in the Go programming language.

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

### Disclaimer
As I stated in my linked article, cryptography is hard. There are many, many ways of doing crypto wrong, even in ways that appear right. Modern cryptography is a specialized branch of mathematics, and there are academics who study and practice crypto for a living.

I am not one of those people. I have no specialized knowledge or training in cryptography, and nothing in this article should lead you to believe otherwise. It’s entirely possible that everything I’ve shown here is one of those “looks right, but is actually wrong” instances. The cryptographic algorithm and mode are only a small part of any cryptographic application, and factors beyond the selection of an algorithm and mode (Where is the ciphertext stored? Who has access to it? How are keys distributed to participants of the system? etc.) are important to the security of any cryptosystem. If your application has real-world dependencies on strong cryptographic practices, you ABSOLUTELY MUST retain the advice of someone with training and experience in these matters and not place your trust in some random guy on the internet who happened to write an article.