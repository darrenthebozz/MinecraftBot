#ifndef COMP_H
#define COMP_H
#include <iostream>
#include <array>
#include <vector>

#include <assert.h>
#include <string.h>
#include <zlib.h>

#define StaticCompressBound(size) size + (size >> 12) + (size >> 14) + (size >> 25) + 13

class Compression
{
protected:
    Compression() {}

public:
    struct Error
    {
        enum e
        {
            None,
            BUFFER_TOO_SMALL,
            MEM_ERROR,
            DATA_ERROR,
        };
    };

    virtual int compress(u_char *, ulong, size_t) = 0;
    virtual int uncompress(u_char *, ulong, size_t) = 0;
    struct ZLIB;
};

struct Compression::ZLIB : Compression
{
    int compress(u_char *buf, ulong bufLen, const ulong dataLen) override final
    {
        // compress doesn't like src and dest being the same sadly
        Bytef tempBuf[bufLen];
        int ret = ::compress(reinterpret_cast<Bytef *>(tempBuf), &bufLen, reinterpret_cast<Bytef *>(buf), dataLen);

        if (ret == Z_BUF_ERROR)
            return -Error::BUFFER_TOO_SMALL;
        if (ret == Z_MEM_ERROR)
            return -Error::MEM_ERROR;
        if (ret == Z_DATA_ERROR)
            return -Error::DATA_ERROR;
        memcpy(buf, tempBuf, bufLen);
        return bufLen;
    }
    int uncompress(u_char *buf, ulong bufLen, ulong dataLen) override final
    {
        Bytef tempBuf[bufLen];
        int ret = ::uncompress(reinterpret_cast<Bytef *>(tempBuf), &bufLen, reinterpret_cast<Bytef *>(buf), dataLen);

        if (ret == Z_BUF_ERROR)
            return Error::BUFFER_TOO_SMALL;
        if (ret == Z_MEM_ERROR)
            return Error::MEM_ERROR;
        if (ret == Z_DATA_ERROR)
            return Error::DATA_ERROR;
        memcpy(buf, tempBuf, bufLen);
        return Error::None;
    }
};

#endif