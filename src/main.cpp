#include <functional>
#include <iostream>
#include <vector>
#include <algorithm>
#include <typeinfo>
#include <limits>
#include <cstdint>

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <zlib.h>
#include <pthread.h>
#include <json/json.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#include "varint.hpp"
#include "https.hpp"
#include "crypt.hpp"
#include "comp.hpp"

// #define DEBUG

off_t inline filesize(int fd)
{
    struct stat buf;
    fstat(fd, &buf);
    return buf.st_size;
}

namespace Minecraft
{
    class Bot
    {
    public:
        typedef void (Minecraft::Bot::*Action)();
        typedef std::array<char, 16> UUID;

        // private:
        int sockfd;
        size_t recvPos = 0;
        std::array<char, 2097151> comBuf;
        size_t sendPos = comBuf.size() - 1;

        Action functions[256] = {0};
        bool _active = true;
        bool connectionEncrypted = false;

        EVP_CIPHER_CTX *ctxEnc = nullptr;
        EVP_CIPHER_CTX *ctxDec = nullptr;

        inline bool Recv()
        { // Got data? = true
            int ret;
            if (_active)
            {
                ioctl(sockfd, SIOCINQ, &ret);

                if (ret > 0)
                {
                    // memset(comBuf.data(), '\0', comBuf.size());
                    recvPos = 0;
                    size_t i = 0;
                    VarInt packetLength;
                    do
                    {
                        assert(i != 5);
                        if ((ret = recv(sockfd, &comBuf.data()[i], 1, MSG_WAITALL)) == 0)
                        {
                            Disconnect();
                            Reconnect();
                            return false;
                        }
                        assert(ret > 0);
                        if (connectionEncrypted)
                        {
                            int outl;
                            assert(EVP_DecryptUpdate(ctxDec, (u_char *)&comBuf[i], &outl, (u_char *)&comBuf[i], 1) == 1);
                        }
                        packetLength = VarInt(comBuf.data(), i + 1);
                        i++;
                    } while (packetLength.size() == 0);

                    assert(packetLength.toInt() <= comBuf.size());
                    assert(packetLength.toInt() != 0);

                    if ((ret = recv(sockfd, comBuf.data(), packetLength.toInt(), MSG_WAITALL)) == 0) // Overwrite packetLength data within buffer.
                    {
                        Disconnect();
                        Reconnect();
                        return false;
                    }

                    // assert(ret == packetLength);
                    if (connectionEncrypted)
                    {
                        int outl;
                        assert(EVP_DecryptUpdate(ctxDec, (u_char *)comBuf.data(), &outl, (u_char *)&comBuf, packetLength.toInt()) == 1);
                        assert(EVP_DecryptFinal_ex(ctxDec, (u_char *)&comBuf.data()[outl], &outl) == 1);
                    }
                    if (compressionThreshold >= 0)
                    {
                        Compression::ZLIB zlib;
                        VarInt dataLength(comBuf.data(), packetLength.toInt());
                        assert(dataLength.size() != 0);
                        recvPos += dataLength.size();
                        int errcode = 0;
                        if (dataLength.toInt() != 0)
                            if ((errcode = zlib.uncompress((u_char *)&comBuf[recvPos], comBuf.size(), packetLength.toInt() - recvPos)) != Compression::ZLIB::Error::None)
                            {
                                std::cout << "error: " << errcode << "\n";
                            }
                    }
                    return true;
                }
            }
            return false;
        }

    public:
        struct Vec2
        {
            float x, y;
        };
        struct Vec3
        {
            float x, y, z;
        };
        struct Entitys
        {
        };
        struct Blocks
        {
        };
        struct ClientBoundID
        {
            enum e
            {
                SetCompression = 0x03,
                KeepAlive = 0x21,
                Quit = 0x1A,
                UpdateHealth = 0x52,
                UpdatePosition = 0x38,
                LoginSuccess = 0x02,
                EncryptionRequest = 0x01,
                PlayerInfo = 0x36,
            };
        };
        struct ServerBoundID
        {
            enum e
            {
            };
        };
        enum struct State
        {
            Handshake,
            Status,
            Login,
            Play,
        };
        std::vector<Entitys> entitys;
        std::vector<Blocks> blocks;
        Vec3 position;
        std::string address;
        uint16_t port;
        std::string username;
        int compressionThreshold = -1;
        UUID uuid;
        float yaw;   // % 360
        float pitch; // % 360

        Bot(std::string username, std::string address, const uint16_t port)
        {
            this->address = address;
            this->port = port;
            this->username = username;

            SetState(State::Handshake);
#ifdef DEBUG
            std::cout << "Connecting\n";
#endif
            Reconnect();
        }
        void SetState(State state)
        {
            memset(functions, 0, sizeof(functions) / sizeof(functions[0]));
            switch (state)
            {
            case State::Handshake:
                functions[ClientBoundID::Quit] = &Bot::Quit;
                break;
            case State::Login:
                // functions[0x00] = &Bot::Quit;
                functions[ClientBoundID::EncryptionRequest] = &Bot::EncryptionRequest;
                functions[ClientBoundID::PlayerInfo] = &Bot::PlayerInfo;
                functions[ClientBoundID::SetCompression] = &Bot::SetCompression;
                functions[ClientBoundID::LoginSuccess] = &Bot::LoginSuccess;
                break;
            case State::Play:
                functions[ClientBoundID::KeepAlive] = &Bot::KeepAlive;
                functions[ClientBoundID::UpdateHealth] = &Bot::UpdateHealth;
                functions[ClientBoundID::UpdatePosition] = &Bot::UpdatePosition;
                functions[ClientBoundID::Quit] = &Bot::Quit;
                functions[ClientBoundID::PlayerInfo] = &Bot::PlayerInfo;
                functions[0x0F] = &Bot::Chat;
                break;
            }
        }
        inline void CallByID(int id)
        {
            if (id >= 0 && id < sizeof(functions) / sizeof(functions[0]))
            {
                if (functions[id] != nullptr)
                {
                    (this->*functions[id])();
                }
            }
        }
        inline void Disconnect()
        {
#ifdef DEBUG
            std::cout << "Disconnected\n";
#endif
            close(sockfd);
            _active = false;
        }
        void Reconnect()
        {
            _active = true;
            compressionThreshold = -1;

            if (connectionEncrypted)
            {
                EVP_CIPHER_CTX_free(ctxEnc);
                EVP_CIPHER_CTX_free(ctxDec);
            }

            connectionEncrypted = false;

            struct sockaddr_in Serv_addr;

            if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
            {
                memset(&Serv_addr, '0', sizeof(Serv_addr));
                Serv_addr.sin_family = AF_INET;
                Serv_addr.sin_port = htons(port);

                if (inet_pton(AF_INET, address.c_str(), &Serv_addr.sin_addr) > 0)
                    if (connect(sockfd, (struct sockaddr *)&Serv_addr, sizeof(Serv_addr)) == 0)
                    {
                        HandShake();
                        return; // Connected
                    }
            }
#ifdef DEBUG
            std::cout << "Couldn't connect\n";
#endif
            Disconnect();
            // throw std::runtime_error("Failed to connect");
        }
        size_t SendDataLength() // Buffer_Size_Max starts on 1 this is an array that starts on 0 so -1
        {
            return (comBuf.size() - 1) - sendPos;
        }
        void Send()
        {
            if (_active)
            {
                if (compressionThreshold < 0)
                {
                    VarInt dataLength(SendDataLength());
                    int dataLengthSize = dataLength.size();
                    sendPos -= dataLengthSize;
                    memcpy(&comBuf[sendPos], dataLength.data(), dataLengthSize);
                }
                else
                {
                    if (SendDataLength() >= compressionThreshold)
                    {
                        unsigned long destLength = comBuf.size();
                        Compression::ZLIB zlib;
                        zlib.compress((u_char *)&comBuf[sendPos], sizeof(comBuf), SendDataLength());
                        // sendPos = 0;
                        VarInt DataLength(SendDataLength());
                        sendPos -= DataLength.size();
                        memcpy(&comBuf[sendPos], DataLength.data(), DataLength.size());
                        VarInt compressedLength(destLength);
                        sendPos -= compressedLength.size();
                        memcpy(&comBuf[sendPos], compressedLength.data(), compressedLength.size());
                    }
                    else
                    {
                        VarInt DataLength(0);
                        sendPos -= DataLength.size();
                        memcpy(&comBuf[sendPos], DataLength.data(), DataLength.size());
                        VarInt compressedLength((comBuf.size() - 1) - sendPos);
                        sendPos -= compressedLength.size();
                        memcpy(&comBuf[sendPos], compressedLength.data(), compressedLength.size());
                    }
                }
                int outl;
                if (connectionEncrypted)
                {
                    //`throw;
                    assert(EVP_EncryptUpdate(ctxEnc, (u_char *)&comBuf[sendPos], &outl, (u_char *)&comBuf[sendPos], SendDataLength()) == 1);
                }
                send(sockfd, &comBuf[sendPos], SendDataLength(), 0);
            }
            sendPos = comBuf.size() - 1;
        }
        virtual bool Update()
        {
            if (Recv())
            {
                VarInt varint(&comBuf[recvPos], comBuf.size());
                recvPos += varint.size();
                int packet_id = varint.toInt();
#ifdef DEBUG
                printf("[0x%X]\n", packet_id);
#endif
                CallByID(packet_id);
            }
            return _active;
        }
        template <typename T>
        T Withdraw()
        {
            T type;

#if __BYTE_ORDER == __LITTLE_ENDIAN
            std::reverse_copy(&comBuf[recvPos], &comBuf[recvPos + sizeof(T)], reinterpret_cast<char *>(&type));
#else
            memcpy((char *)&type, &_buffer[Recv_Position], sizeof(T));
#endif
            recvPos += sizeof(T);

            return type;
        }
        void Withdraw(char *dest, size_t size)
        {
            memcpy(dest, &comBuf[recvPos], size);
            recvPos += size;
        }
        void Append(const void *src, size_t len)
        {
            sendPos -= len;
            memcpy(&comBuf[sendPos], src, len);
        }
        void Append(const VarInt &varint)
        {
            Append(varint.data(), varint.size());
        }
        void Append(const std::string &str)
        {
            Append(str.data(), str.length());
            Append(VarInt(str.length()));
        }
        template <typename T>
        void Append(const T &type)
        {
            sendPos -= sizeof(T);
#if __BYTE_ORDER == __LITTLE_ENDIAN
            // copy's a type in reverse to &Buffer[Send_Position]
            std::reverse_copy(reinterpret_cast<const char *>(&type), reinterpret_cast<const char *>(&type) + sizeof(T), &comBuf[sendPos]);
#else
            memcpy(&Buffer[sendPos], (char *)&type, sizeof(T));
#endif
        }
        void Chat();
        // ClientBound
        virtual void KeepAlive();
        virtual void Quit();
        virtual void UpdateHealth();
        virtual void UpdatePosition();
        virtual void SetCompression();
        virtual void LoginSuccess();
        virtual void EncryptionRequest();
        virtual void PlayerInfo();
        // ServerBound
        virtual void HandShake();
        std::string realUUID;
        std::string playerName;
    };
    template <>
    VarInt Bot::Withdraw<VarInt>()
    {
        VarInt varint(&comBuf.data()[recvPos], comBuf.size());
        recvPos += varint.size();
        return varint;
    }
    template <>
    std::string Bot::Withdraw<std::string>()
    {
        VarInt varint(&comBuf.data()[recvPos], comBuf.size());

        recvPos += varint.size();

        std::string str(&comBuf.data()[recvPos], varint.toInt());

        recvPos += varint.toInt();

        return str;
    }
    // ClientBound
    void Bot::KeepAlive()
    {
        long keep_alive_id = Withdraw<long>();

        Append(keep_alive_id);
        Append(VarInt(0x0F));
        Send();
    }
    void Bot::Quit()
    {
#ifdef DEBUG
        std::string disconnectReason = Withdraw<std::string>();
        std::cout << disconnectReason << "\n";
#endif
        Disconnect();

        connectionEncrypted = false;
        compressionThreshold = -1;
    }
    void Bot::UpdateHealth()
    {
        float health = Withdraw<float>();
#ifdef DEBUG
        printf("Health=%2.6f\n", health);
#endif
        if (health <= 0.0)
        {
            Append(VarInt(0));
            Append(VarInt(0x04));
            Send();
        }
    }
    void Bot::UpdatePosition()
    {
        double x = Withdraw<double>();
        double y = Withdraw<double>();
        double z = Withdraw<double>();
        float yaw = Withdraw<float>();
        float pitch = Withdraw<float>();
        char flags = Withdraw<char>();
        int teleport_id = Withdraw<VarInt>().toInt();
        bool dismount_vehicle = Withdraw<bool>();

        if (flags & 0x01) // 0x01 = relative X
            this->position.x += x;
        else
            this->position.x = x;

        if (flags & 0x02) // 0x01 = relative Y
            this->position.y += y;
        else
            this->position.y = y;

        if (flags & 0x04) // 0x01 = relative Z
            this->position.z += z;
        else
            this->position.z = z;

        if (flags & 0x08)
            this->yaw += yaw; // 0x01 = relative Y Rotation
        else
            this->yaw = yaw;

        if (flags & 0x10)
            this->pitch += pitch; // 0x01 = relative X Rotation
        else
            this->pitch = pitch;
#ifdef DEBUG
        std::cout << "X=" << this->position.x << " "
                  << "Y=" << this->position.y << " "
                  << "Z=" << this->position.z << "\n";
#endif
        Append(VarInt(teleport_id));
        Append(VarInt(0x00));
        Send();
    }
    void Bot::SetCompression()
    {
#ifdef DEBUG
        std::cout << "Enabling Compression\n";
#endif
        compressionThreshold = Withdraw<VarInt>().toInt();
    }
    void Bot::EncryptionRequest()
    {
#ifdef DEBUG
        std::cout << "Enabling Encryption\n";
#endif
        // data would get destroyed on send
        int sIDSize = Withdraw<VarInt>().toInt();
        std::vector<char> sID(sIDSize);
        Withdraw(sID.data(), sIDSize);

        int pubkeySize = Withdraw<VarInt>().toInt();
        std::vector<char> pubkey(pubkeySize);
        Withdraw(pubkey.data(), pubkeySize);

        int verifyTokenSize = Withdraw<VarInt>().toInt();
        std::vector<char> verifyToken(verifyTokenSize);
        Withdraw(verifyToken.data(), verifyTokenSize);

        std::array<unsigned char, 128 / 8> sharedSecret;

        const RAND_METHOD *rand = RAND_get_rand_method();
        int ret = RAND_priv_bytes(reinterpret_cast<u_char *>(sharedSecret.data()), sharedSecret.size());
        assert(ret != -1);

        u_char tmpBuf[SHA_DIGEST_LENGTH];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, sID.data(), sIDSize);
        SHA1_Update(&ctx, sharedSecret.data(), sharedSecret.size());
        SHA1_Update(&ctx, pubkey.data(), pubkeySize);
        SHA1_Final(tmpBuf, &ctx);
        BIGNUM *bn = BN_bin2bn(tmpBuf, SHA_DIGEST_LENGTH, nullptr);
        std::string HashStr;
        if (BN_is_bit_set(bn, 159)) // This represents big endian where the signed byte is at the end
        {
            BN_bn2bin(bn, tmpBuf); // moves data from bn to tmpBuf
            for (u_char &byte : tmpBuf)
                byte = ~byte;
            BN_bin2bn(tmpBuf, SHA_DIGEST_LENGTH, bn); // back into bn
            BN_add_word(bn, 1);                       // never understood this...
            HashStr += '-';
        }
        HashStr += BN_bn2hex(bn);
        for (auto &c : HashStr) // lowers every character based off set locale. using auto as type can change
            c = std::tolower(c);
        std::string deviceCode;
        bool toredo = false;
    redo:
        [&]() { // Talk with our product to allow access to their microsoft info
            FILE *fp;
            if ((fp = fopen("../token.bin", "r")) == nullptr || toredo)
            {
                HTTPS https("login.microsoftonline.com", 443);
                std::string Body(
                    "client_id=c9a2756c-5088-4171-993d-4e4b28ab14d3"
                    "&scope=XboxLive.signin XboxLive.offline_access");

                https.Send("POST https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode HTTP/1.1\r\n"
                           "Host: login.microsoftonline.com\r\n"
                           "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                           "Content-Length: " +
                           std::to_string(Body.length()) + "\r\n"
                                                           "\r\n" +
                           Body);
                while (https.Body() == std::string() && https.Update())
                    ;

                Json::Value root;
                Json::Reader reader;
                reader.parse(https.Body(), root);
                const std::string verification_uri = root["verification_uri"].asString();
                deviceCode = root["device_code"].asString();
                const std::string user_code = root["user_code"].asString();
                std::cout << "Please enter code to authenticate: " << user_code << "\n";
                system(std::string("firefox " + verification_uri).c_str());
            }
            else
            {
                fclose(fp);
            }
        }();
        std::string accessToken;
        [&]() { // Talk with microsoft to login
            FILE *fp;
            if ((fp = fopen("../token.bin", "r")) == nullptr || toredo == true)
            {
                do
                {
                    HTTPS https("login.microsoftonline.com", 443);

                    std::string Body(
                        "grant_type=urn:ietf:params:oauth:grant-type:device_code"
                        "&client_id=c9a2756c-5088-4171-993d-4e4b28ab14d3"
                        "&device_code=" +
                        deviceCode);

                    https.Send("POST https://login.microsoftonline.com/consumers/oauth2/v2.0/token HTTP/1.1\r\n"
                               "Host: login.microsoftonline.com\r\n"

                               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                               "Content-Length: " +
                               std::to_string(Body.length()) + "\r\n"
                                                               "\r\n" +
                               Body);
                    while (https.Body() == std::string() && https.Update())
                        ;

                    Json::Value root;
                    Json::Reader reader;
                    if (!reader.parse(https.Body(), root))
                        ;
                    // throw std::string("Invalid JSON");
                    accessToken = root["access_token"].asString();
                    sleep(1);
                } while (accessToken == std::string());
                FILE *fp = fopen("../token.bin", "w");
                if (fp != nullptr)
                {
                    size_t size = accessToken.size();
                    fwrite(&size, sizeof(size_t), sizeof(char), fp);
                    fwrite(accessToken.c_str(), accessToken.size(), sizeof(char), fp);
                    fclose(fp);
                }
            }
            else
            {
                size_t size;
                fread(&size, sizeof(size_t), sizeof(char), fp);
                char *buf = new char[size];
                std::cout << size << "\n";
                sleep(1);
                fread(buf, size, sizeof(char), fp);
                accessToken = std::string(buf, size);
                fclose(fp);
                free(buf);
            }
        }();
        std::string uhsStr;
        std::string tokenStr;
        [&]() { // Talk with xbox live to login
            HTTPS https("user.auth.xboxlive.com", 443);

            std::string Body(
                "{"
                "\"Properties\": {"
                "\"AuthMethod\": \"RPS\","
                "\"SiteName\": \"user.auth.xboxlive.com\","
                "\"RpsTicket\": \"d=" +
                accessToken + "\"" // your access token from the previous step here
                              "},"
                              "\"RelyingParty\": \"http://auth.xboxlive.com\","
                              "\"TokenType\": \"JWT\""
                              "}");

            https.Send("POST https://user.auth.xboxlive.com/user/authenticate HTTP/1.1\r\n"
                       "Host: user.auth.xboxlive.com\r\n"
                       "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: " +
                       std::to_string(Body.length()) + "\r\n"
                                                       "\r\n" +
                       Body);
            while (https.Body() == std::string() && https.Update())
                ;

            Json::Value root;
            Json::Reader reader;
            reader.parse(https.Body(), root);
            tokenStr = root["Token"].asString();
            uhsStr = root["DisplayClaims"]["xui"][0]["uhs"].asString();
        }();
        if (uhsStr == std::string())
        {
            toredo = true;
            goto redo;
        }
        assert(tokenStr != std::string());
        std::string xblToken;
        [&]() { // Talk with xbox live to get auth token
            HTTPS https("xsts.auth.xboxlive.com", 443);

            std::string Body(
                "{"
                "\"Properties\": {"
                "\"SandboxId\": \"RETAIL\","
                "\"UserTokens\": ["
                "\"" +
                tokenStr + "\""
                           "]"
                           "},"

                           "\"RelyingParty\": \"rp://api.minecraftservices.com/\","
                           "\"TokenType\" : \"JWT\""
                           "}");

            https.Send("POST https://xsts.auth.xboxlive.com/xsts/authorize HTTP/1.1\r\n"
                       "Host: xsts.auth.xboxlive.com\r\n"
                       "Content-Type: application/json\r\n"
                       "Accept: application/json\r\n"
                       "Content-Length: " +
                       std::to_string(Body.length()) + "\r\n"
                                                       "\r\n" +
                       Body);
            while (https.Body() == std::string() && https.Update())
                ;

            Json::Value root;
            Json::Reader reader;
            reader.parse(https.Body(), root);
            xblToken = root["Token"].asString();
        }();
        assert(xblToken != std::string());
        std::string minecraftAccessToken;
        [&]() { // Talk to minecraft to login
            HTTPS https("api.minecraftservices.com", 443);

            std::string Body(
                "{"
                "\"identityToken\": \"XBL3.0 x=" +
                uhsStr + ";" + xblToken + "\""
                                          "}");

            https.Send("POST https://api.minecraftservices.com/authentication/login_with_xbox HTTP/1.1\r\n"
                       "Host: api.minecraftservices.com\r\n"
                       "Content-Type: application/json\r\n"
                       "Accept: application/json\r\n"
                       "Content-Length: " +
                       std::to_string(Body.length()) + "\r\n"
                                                       "\r\n" +
                       Body);
            while (https.Body() == std::string() && https.Update())
                ;

            Json::Value root;
            Json::Reader reader;
            reader.parse(https.Body(), root);
            minecraftAccessToken = root["access_token"].asString();
        }();
        assert(minecraftAccessToken != std::string());
        [&]() { // Talk to minecraft to get player info
            HTTPS https("api.minecraftservices.com", 443);

            std::string Body;

            https.Send("GET https://api.minecraftservices.com/minecraft/profile HTTP/1.1\r\n"
                       "Host: api.minecraftservices.com\r\n"
                       "Content-Type: application/json\r\n"
                       "Accept: application/json\r\n"
                       "Authorization: Bearer " +
                       minecraftAccessToken + "\r\n"
                                              "Content-Length: " +
                       std::to_string(Body.length()) + "\r\n"
                                                       "\r\n" +
                       Body);
            while (https.Body() == std::string() && https.Update())
                ;

            Json::Value root;
            Json::Reader reader;
            reader.parse(https.Body(), root);
            realUUID = root["id"].asString();
            playerName = root["name"].asString();
        }();
        [&]() { // Talk to Mojang servers to confirm authentication with server
            HTTPS https("sessionserver.mojang.com", 443);
            std::string Body(
                "{"
                "\"accessToken\": \"" +
                minecraftAccessToken + "\","
                                       "\"selectedProfile\": \"" +
                realUUID + "\","
                           "\"serverId\": \"" +
                HashStr + "\""
                          "}");
            https.Send("POST https://sessionserver.mojang.com/session/minecraft/join HTTP/1.1\r\n"
                       "Content-Type: application/json\r\n"
                       "Accept: application/json\r\n"
                       "Host: sessionserver.mojang.com\r\n"
                       "Content-Length: " +
                       std::to_string(Body.length()) + "\r\n"
                                                       "\r\n" +
                       Body);

            while (https.Update() && https.Header() == std::string())
                ;
            std::cout << "realUUID: " << realUUID << "\n";
            std::cout << "accessToken: " << accessToken << "\n";
            std::cout << "ServerID: " << HashStr << "\n";
            // assert(0);
        }();
        // server sends us their public key to encrypt our messages in.
        // we send them our public key so they can encrypt their messages.
        // incoming messages are then decrypted using our private key.EVP_aes_256_cfb8
        auto encrypt = [](const unsigned char *pk, size_t pk_length, const unsigned char *data, size_t data_length)
        {
            RSA *rsa = d2i_RSA_PUBKEY(NULL, &pk, pk_length);
            assert(rsa != nullptr);
            std::vector<unsigned char> out(RSA_size(rsa));
            int ret = RSA_public_encrypt(data_length, data, out.data(), rsa, RSA_PKCS1_PADDING);
            return out;
        };
        std::vector<unsigned char> sharedSecretEnc = encrypt((unsigned char *)pubkey.data(), pubkeySize, sharedSecret.data(), sharedSecret.size());
        std::vector<unsigned char> verifyTokenEnc = encrypt((unsigned char *)pubkey.data(), pubkeySize, (unsigned char *)verifyToken.data(), verifyTokenSize);
        assert(verifyTokenEnc.size() == 128);
        assert(sharedSecretEnc.size() == 128);
        Append(verifyTokenEnc.data(), verifyTokenEnc.size());
        Append(VarInt(128));
        Append(sharedSecretEnc.data(), sharedSecretEnc.size());
        Append(VarInt(128));
        Append(VarInt(0x01));
        Send();
        ctxEnc = EVP_CIPHER_CTX_new();
        ctxDec = EVP_CIPHER_CTX_new();

        assert(EVP_EncryptInit_ex(ctxEnc, EVP_aes_128_cfb8(), NULL, sharedSecret.data(), sharedSecret.data()) == 1);
        assert(EVP_DecryptInit_ex(ctxDec, EVP_aes_128_cfb8(), NULL, sharedSecret.data(), sharedSecret.data()) == 1);
        connectionEncrypted = true;
    }

    void Bot::Chat()
    {
        std::string chat_json = Withdraw<std::string>();
        char position = Withdraw<char>();
        if (position != 0)
            return;
        std::string translate;
        {
            Json::Value root;
            Json::Reader reader;
            reader.parse(chat_json, root);
            translate = root["translate"].asString();
        }
        std::string text;
        {
            Json::Value root;
            Json::Reader reader;
            reader.parse(chat_json, root);
            text = root["with"][1].asString();
        }
        if (text == std::string("Kill"))
        {
            exit(0);
        }
        else if (text == std::string("Move"))
        {
            Append<bool>(1);
            Append<double>(this->position.z += 1);
            Append<double>(this->position.y += 1);
            Append<double>(this->position.x += 1);
            Append(VarInt(0x11));
            Send();
        }
        else if (text == std::string())
        {
            std::cout << chat_json << "\n";
        }
        else
        {
            std::cout << text << "\n";
        }
    }
    // ServerBound
    void Bot::HandShake()
    {
        SetState(State::Login);
        Append(VarInt((int)State::Login));
        Append(port);
        Append(address);
        Append(VarInt(756));
        Append(VarInt(0x00));
        Send();
        Append(username);
        Append(VarInt(0x00));
        Send();
    }
    void Bot::LoginSuccess()
    {
        uuid = Withdraw<UUID>();
        username = Withdraw<std::string>();
        SetState(State::Play);
    }
    void Bot::PlayerInfo()
    {
        SetState(State::Play);
    }
} // namespace Minecraft
struct Test : public Minecraft::Bot
{
    static pthread_mutex_t mutex;
    static size_t getnum()
    {
        static size_t i = 0;
        pthread_mutex_lock(&mutex);
        size_t j = i++;
        pthread_mutex_unlock(&mutex);
        return j;
    }
    Test() : Bot("Bot" + std::to_string(getnum()), "127.0.0.1", 25565) {} //"BOT" + std::to_string(getnum()), "127.0.0.1", 25565) {}

    bool Update() override
    {
        return Bot::Update();
    }
    void Quit() override
    {
        Disconnect();
        Reconnect();
    }
};
pthread_mutex_t Test::mutex = []()
{
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, nullptr);
    return mutex;
}();
void *worker(void *)
{
    Test tests[64 / 4];
    while (true)
        for (Test &test : tests)
            test.Update();
}
// ulimit unlimited is 2mb
int main()
{ // Tests
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    std::setvbuf(stdout, NULL, _IONBF, 0);
    {
        // assert(std::string("-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1") == Minecraft::Bot::SHA1_Hash("jeb_"));
        // assert(std::string("4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48") == Minecraft::Bot::SHA1_Hash("Notch"));
        assert(VarInt(1).toInt() == 1);
        assert(VarInt(5).size() == 1);
        assert(VarInt(VarInt(5).data(), VarInt(5).size()).toInt() == 5);
        assert(VarInt(VarInt(5).data(), VarInt(5).size()).size() == 1);
        assert(VarInt(5).size() == VarInt(5).size());
        assert(VarInt(756).toInt() == 756);
        assert(VarInt(0).toInt() == 0);

        assert(std::numeric_limits<float>::is_iec559 == true);
        assert(std::numeric_limits<float>::has_infinity == true);
    }
#ifdef DEBUG
    std::cout << "Started\n";
#endif
    pthread_t dummy;
    pthread_create(&dummy, NULL, worker, NULL);
    pthread_create(&dummy, NULL, worker, NULL);
    pthread_create(&dummy, NULL, worker, NULL);

    // if (pthread_create(&dummy, NULL, worker, NULL) != 0);
    // throw std::runtime_error("thread error");
    // if (pthread_create(&dummy, NULL, worker, NULL) != 0);
    // throw std::runtime_error("thread error");
    // if (pthread_create(&dummy, NULL, worker, NULL) != 0);
    // throw std::runtime_error("thread error");

    worker(nullptr);
}
// ulimit -s 128000