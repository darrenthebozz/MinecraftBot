#include <array>

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>

class VarInt
{
    std::array<char, 5> buffer;
    unsigned char m_size = 0;
    int m_integer;

    static constexpr unsigned char segmentBit = 0x7F;
    static constexpr unsigned char continueBit = 0x80;
public:
    VarInt(const char *src, size_t srcLen)
    {
        //if (srcLen > buffer.size())
          //  srcLen = buffer.size();

        int integer = 0;
        unsigned char i = 0;
        do
        {
            if (i >= srcLen)
            {
                assert(1);
                m_size = 0;
                return;
            }

            integer |= (src[i] & segmentBit) << i * 7;
        } while ((src[i++] & continueBit) != 0);
        m_integer = integer;
        m_size = i;

        memcpy(buffer.data(), src, m_size);
    }
    VarInt(int integer)
    {
        m_integer = integer;

        unsigned u_integer = integer;
        unsigned char i = 0;
        while ((u_integer & ~segmentBit) != 0)
        {
            assert(i != buffer.size());
            buffer.data()[i] = ((u_integer & segmentBit) | continueBit);
            u_integer >>= 7; // arithmetic unsigned right shift
            i++;
        }
        buffer.data()[i] = u_integer;
        m_size = i + 1;
    }
    VarInt()
    {
    }

    //gives the size of data. If there is an error it is set to 0
    int size() const
    {
        return m_size;
    }
    const char *data() const
    {
        return buffer.data();
    }
    int toInt() const
    {
        return m_integer;
    }
};
/*
class VarInt {
private:
    std::array<char, 5> buffer;
public:
    static constexpr unsigned char segmentBit = 0x7F;
    static constexpr unsigned char continueBit = 0x80;
    VarInt(int32_t integer)
    {
        unsigned char i = 0;
        while ((integer & ~segmentBit) != 0)
        {
            buffer.data()[i] = ((integer & segmentBit) | continueBit);
            integer >>= 7; // arithmetic unsigned right shift
            i++;
        }
        buffer.data()[i] = integer;
    }
    VarInt(const char* src, size_t srcLen)
    {
        unsigned char i = 0;
        do
        {
            if(i > buffer.size() || i > srcLen) {
                assert(0);
                return;
            }
        } while((buffer.data()[i++] & continueBit) != 0);

        memcpy(buffer.data(), src, i);
    }
    int value()
    {
        int integer = 0;
        unsigned char i = 0;
        do
        {
            integer |= (buffer[i] & segmentBit) << i * 7;
        } while((buffer[i++] & continueBit) != 0);
        return integer;
    }
    unsigned char size()
    {
        unsigned char i = 0;
        while((buffer.data()[i++] & continueBit) != 0);
        return i + 1;
    }
    const std::array<char, 5>* data()
    {
        return &buffer;
    }
};
*/