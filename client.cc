#include <iostream>
#include <thread>
#include <string>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

class ChatClient {
private:
    int clientSocket;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx;
    std::atomic<bool> running;
    const char* SERVER_IP = "127.0.0.1";
    const int PORT = 12345;
    std::string username;

    void initializeSSL() {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        const SSL_METHOD* method = TLS_client_method();
        SSL_CTX* rawCtx = SSL_CTX_new(method);
        
        if (!rawCtx) {
            throw std::runtime_error("SSL context creation failed");
        }

        ctx = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(rawCtx, SSL_CTX_free);
    }

    void receiveMessages() {
        char buffer[1024];
        while (running) {
            try {
                std::memset(buffer, 0, sizeof(buffer));
                int bytesReceived = SSL_read(ssl.get(), buffer, sizeof(buffer) - 1);
                
                if (bytesReceived <= 0) {
                    int error = SSL_get_error(ssl.get(), bytesReceived);
                    if (error == SSL_ERROR_ZERO_RETURN) {
                        std::cout << "Server closed connection" << std::endl;
                    } else {
                        std::cout << "Connection error" << std::endl;
                    }
                    running = false;
                    break;
                }

                if (buffer[0] != '\0') {  // Ignore heartbeat messages
                    std::cout << buffer << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Receive error: " << e.what() << std::endl;
                running = false;
                break;
            }
        }
    }

    bool authenticate() {
        try {
            std::string command;
            std::cout << "Enter 'LOGIN' or 'REGISTER': ";
            std::getline(std::cin, command);
    
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::string password;
            std::cout << "Password: ";
            std::getline(std::cin, password);
    
            std::string credentials = command + " " + username + " " + password;
            if (SSL_write(ssl.get(), credentials.c_str(), credentials.length()) <= 0) {
                throw std::runtime_error("Failed to send credentials");
            }
    
            char response[1024] = {0};
            int bytesRead = SSL_read(ssl.get(), response, sizeof(response) - 1);
            if (bytesRead <= 0) {
                throw std::runtime_error("Failed to receive authentication response");
            }
    
            std::string authResponse(response);
            std::cout << authResponse << std::endl;
    
            if (command == "REGISTER" || authResponse.find("failed") != std::string::npos) {
                return authenticate(); // Recursively try again
            }
    
            return authResponse.find("successful") != std::string::npos;
        } catch (const std::exception& e) {
            std::cerr << "Authentication error: " << e.what() << std::endl;
            return false;
        }
    }

public:
    ChatClient() 
        : clientSocket(-1)
        , ssl(nullptr, SSL_free)
        , ctx(nullptr, SSL_CTX_free)
        , running(true) {
        try {
            initializeSSL();
        } catch (const std::exception& e) {
            std::cerr << "Initialization error: " << e.what() << std::endl;
            throw;
        }
    }

    bool connect() {
        try {
            clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket < 0) {
                throw std::runtime_error("Socket creation failed");
            }

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(PORT);
            serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

            if (::connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                throw std::runtime_error("Connection failed");
            }

            SSL* rawSsl = SSL_new(ctx.get());
            if (!rawSsl) {
                throw std::runtime_error("SSL creation failed");
            }

            ssl = std::unique_ptr<SSL, decltype(&SSL_free)>(rawSsl, SSL_free);
            SSL_set_fd(ssl.get(), clientSocket);

            if (SSL_connect(ssl.get()) <= 0) {
                throw std::runtime_error("SSL connection failed");
            }

            std::cout << "Connected to server" << std::endl;

            if (!authenticate()) {
                throw std::runtime_error("Authentication failed");
            }

            return true;
        } catch (const std::exception& e) {
            std::cerr << "Connection error: " << e.what() << std::endl;
            if (clientSocket != -1) {
                close(clientSocket);
            }
            return false;
        }
    }

    void run() {
        try {
            std::thread receiveThread(&ChatClient::receiveMessages, this);
            receiveThread.detach();

            std::cout << "\nAvailable commands:\n"
                      << "/list - Show connected users\n"
                      << "/msg <user> <message> - Send private message\n"
                      << "/help - Show this help message\n"
                      << "/exit - Disconnect from server\n\n";

            std::string message;
            while (running) {
                std::getline(std::cin, message);
                if (message == "/exit") {
                    running = false;
                    break;
                }

                if (SSL_write(ssl.get(), message.c_str(), message.length()) <= 0) {
                    std::cerr << "Failed to send message" << std::endl;
                    running = false;
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Runtime error: " << e.what() << std::endl;
        }
    }

    ~ChatClient() {
        running = false;
        if (clientSocket != -1) {
            close(clientSocket);
        }
        EVP_cleanup();
    }
};

int main() {
    try {
        ChatClient client;
        if (!client.connect()) {
            return 1;
        }
        client.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
