#include <stdexcept>
#include <vector>
#include <iostream>
#include <regex>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <assert.h>

class HTTPS
{
public:
    bool _active = false;
    std::string _recv_buf;
    std::string _body;
    std::string _header;

public:
    SSL *ssl = nullptr;

    HTTPS(std::string url, unsigned short port)
    {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        //if (sockfd < 0)
        //    throw std::runtime_error("create socket failed");

        std::regex reg(".+(?=/|$)");

        std::smatch match;

        std::regex_search(url, match, reg);//if (!std::regex_search(url, match, reg))
        //    throw std::runtime_error("Invalid URL");

        struct hostent *server;
        server = gethostbyname(match.str().c_str());
        //if ((server = gethostbyname(match.str().c_str())) == nullptr)
        //    throw std::runtime_error("Couldn't get hostname");

        struct sockaddr_in serv_addr;
        bzero((char *)&serv_addr, sizeof(serv_addr));
        bcopy((char *)server->h_addr,
              (char *)&serv_addr.sin_addr.s_addr,
              server->h_length);
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0);
            //throw;

        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();

        const SSL_METHOD *meth = TLS_method();
        SSL_CTX *ctx = SSL_CTX_new(meth);

        if ((ssl = SSL_new(ctx)) == nullptr);
            //throw std::runtime_error("Couldn't create SSL_new");

        SSL_set_fd(ssl, sockfd);
        int ssl_socket = SSL_get_fd(ssl);

        int ret;
        while ((ret = SSL_connect(ssl)) <= 0)
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                ERR_clear_error();
            else
            {
                _active = false;
                return;
            }
        }
        _active = true;
    }
    ~HTTPS()
    {
        // memory leaks oh well...
    }
    bool Update()
    {
        if (_active == false)
            return false;

        const size_t bufChunk = 4096;
        char buf[bufChunk];

        int len;
        if ((len = SSL_read(ssl, buf, bufChunk)) < 0)
        {
            assert(SSL_get_error(ssl, len) == SSL_ERROR_WANT_READ);
            ERR_clear_error();
        }
        else if (len == 0)
        {
            _active = false;
            if (_body == std::string())
                _body = _recv_buf.substr(_header.length() + strlen("\r\n\r\n"));

            return true;
        }
        else
        {
            _recv_buf += std::string(buf, len);
        }
        if (_header == std::string())
        {
            std::smatch match;

            if (std::regex_search(_recv_buf, match, std::regex("(.|\r|\n)*?(?=\r\n\r\n)")))
                _header = match.str();
        }
        else if (_body == std::string())
        {
            std::string TranEncodeEnd = "0\r\n\r\n";
            std::string contLenStr = HeaderSearch("Content-Length");
            if (HeaderSearch("Transfer-Encoding") == std::string("chunked") && strcmp(&_recv_buf.end()[-TranEncodeEnd.length()], TranEncodeEnd.c_str()) == 0)
            {
                std::smatch match;
                if (std::regex_search(_recv_buf, match, std::regex("\\d+\r\n")))
                {
                    // std::string Bodyfi = match.str()
                }

                _body = _recv_buf.substr(_header.length() + strlen("\r\n\r\n"), _recv_buf.length() - _header.length() - strlen("\r\n\r\n") - TranEncodeEnd.length());
            }
            else if (contLenStr != std::string() && std::stoi(contLenStr) >= _recv_buf.length() - _header.length() - strlen("\r\n\r\n"))
            {
                _body = _recv_buf.substr(_header.length() + strlen("\r\n\r\n"));
                if (std::stoi(contLenStr) == 0)
                    _active = false;
            }
        }

        return _active;
    }
    void Send(std::string str)
    {
        int len;

        if ((len = SSL_write(ssl, str.c_str(), str.length() * sizeof(char))) < 0)
        {
            assert(SSL_get_error(ssl, len) == SSL_ERROR_WANT_READ);
            ERR_clear_error();
        }
        else if (len == 0)
            _active = false;
    }
    std::string HeaderSearch(std::string item)
    {
        item += ": ";

        size_t pos;
        if ((pos = _recv_buf.find(item)) == std::string::npos)
            return std::string();
        size_t str_size;
        if ((str_size = _recv_buf.find("\r\n", pos)) == std::string::npos)
            return std::string();
        str_size -= pos + item.length();

        return std::string(&_recv_buf.c_str()[pos + item.length()], str_size);
    }
    std::string Header()
    {
        return _header;
    }
    std::string Body()
    {
        return _body;
    }
};
