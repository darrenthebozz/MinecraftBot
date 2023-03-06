//#define NDEBUG
#ifndef CRYPT_H
#define CRYPT_H
#include <array>
#include <iostream>
#include <zlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <assert.h>

class Encryption
{
    std::array<u_char, 128 / 8> key;
    std::array<u_char, EVP_MAX_IV_LENGTH> iv;

protected:
    Encryption(void *key, void *iv)
    {
    }

public:
    struct Error {
        enum e{
            None,
            BUFFER_TOO_SMALL,
        };
    };
    virtual int Encrypt(u_char *, size_t, size_t) = 0;
    virtual int Decrypt(u_char *, size_t, size_t) = 0;
    class AES128CFB8;
};

class Encryption::AES128CFB8 : public Encryption
{
    EVP_CIPHER_CTX *ctxEnc;
    EVP_CIPHER_CTX *ctxDec;

public:
    std::array<u_char, 128 / 8> key = {0};
    std::array<u_char, 16> iv = {0};
    
    AES128CFB8(u_char *key, u_char *iv, size_t bufLen, size_t dataLen) : Encryption(key, iv)
    {
        ctxEnc = EVP_CIPHER_CTX_new();
        ctxDec = EVP_CIPHER_CTX_new();
        memcpy(this->iv.data(), iv, this->iv.size());
        memcpy(this->key.data(), iv, this->key.size());
    }
    ~AES128CFB8()
    {
        EVP_CIPHER_CTX_free(ctxEnc);
        EVP_CIPHER_CTX_free(ctxDec);
    }
    int Encrypt(u_char *buf, size_t bufLen, size_t dataLen) override final
    {
        assert(EVP_EncryptInit_ex(ctxEnc, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) == 1);
        if(bufLen < dataLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()))
            return Error::BUFFER_TOO_SMALL;
        int outl;
        assert(EVP_EncryptUpdate(ctxEnc, buf, &outl, buf, dataLen) == 1);
        assert(EVP_EncryptFinal_ex(ctxEnc, &buf[outl], &outl) == 1);
        return Error::None;
    }
    int Decrypt(u_char *buf, size_t bufLen, size_t dataLen) override final
    {
        assert(EVP_DecryptInit_ex(ctxDec, EVP_aes_128_cfb8(), NULL, key.data(), iv.data()) == 1);
        if(bufLen < dataLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()))
            return Error::BUFFER_TOO_SMALL;

        int outl;
        assert(EVP_DecryptUpdate(ctxDec, buf, &outl, buf, dataLen) == 1);
        assert(EVP_DecryptFinal_ex(ctxDec, &buf[outl], &outl) == 1);
        return Error::None;
    }
};
#endif
