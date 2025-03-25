#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <string>
#include <sstream>
#include <atomic>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include "user.h"
#include "logger.h"
#include "message.h"
#include "rate_limiter.h"
#include "user_manager.h"

class ChatServer {
private:
  int serverSocket;
  UserMap users;
  std::mutex usersMutex;
  std::atomic<bool> running;
  const int PORT = 12345;
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx;
  Logger& logger = Logger::getInstance();
  RateLimiter rateLimiter;
  UserManager userManager;

  void initializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* rawCtx = SSL_CTX_new(method);
    
    if (!rawCtx) {
        logger.log("Error creating SSL context");
        throw std::runtime_error("SSL context creation failed");
      }

    ctx = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(rawCtx, SSL_CTX_free);

    if (SSL_CTX_use_certificate_file(ctx.get(), "server.crt", SSL_FILETYPE_PEM) <= 0) {
        logger.log("Error loading certificate");
        throw std::runtime_error("Certificate loading failed");
      }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server.key", SSL_FILETYPE_PEM) <= 0) {
        logger.log("Error loading private key");
        throw std::runtime_error("Private key loading failed");
      }
  }

  bool authenticateUser(int clientSocket, SSL* ssl) {
    try {
        char buffer[1024] = {0};
        int readResult = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (readResult <= 0) {
            logger.log("Authentication read failed");
            return false;
          }

        std::string credentials(buffer);
        std::istringstream iss(credentials);
        std::string command, username, password;
        iss >> command >> username >> password;

        if (command == "REGISTER") {
            if (userManager.createUser(username, password)) {
                std::string success = "Registration successful";
                SSL_write(ssl, success.c_str(), success.length());
                logger.log("New user registered: " + username);
                return false;
              }
            else {
                std::string failure = "Username already exists";
                SSL_write(ssl, failure.c_str(), failure.length());
                return false;
              }
          }
        else if (command == "LOGIN")
          if (userManager.validateUser(username, password)) {
              std::lock_guard<std::mutex> lock(usersMutex);
              users[clientSocket].username = username;
              users[clientSocket].isAuthenticated = true;
              users[clientSocket].ssl = ssl;
              
              std::string success = "Authentication successful";
              SSL_write(ssl, success.c_str(), success.length());
              logger.log("User " + username + " authenticated successfully");
              return true;
            }

        std::string failure = "Authentication failed";
        SSL_write(ssl, failure.c_str(), failure.length());
        return false;
      }
    catch (const std::exception& e) {
        logger.log("Authentication error: " + std::string(e.what()));
        return false;
      }
  }

  void handleClient(int clientSocket, SSL* ssl) {
    try {
        if (!authenticateUser(clientSocket, ssl)) {
            disconnectClient(clientSocket);
            return;
          }

        char buffer[1024];
        while (running) {
            std::memset(buffer, 0, sizeof(buffer));
            int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);

            if (bytesRead <= 0) {
                if (SSL_get_error(ssl, bytesRead) == SSL_ERROR_ZERO_RETURN)
                    logger.log("Client disconnected gracefully");
                else
                    logger.log("SSL read error");
                break;
              }

            std::string message(buffer);
            if (message[0] == '/')
                handleCommand(message, clientSocket);
            else
              if (!rateLimiter.shouldLimit(users[clientSocket].username))
                  broadcastMessage(users[clientSocket].username + ": " + message, clientSocket);
          }
      }
    catch (const std::exception& e) {
        logger.log("Client handler error: " + std::string(e.what()));
      }
    
    disconnectClient(clientSocket);
  }

  void broadcastMessage(const std::string& message, int sender) {
    std::lock_guard<std::mutex> lock(usersMutex);
    for (const auto& [socket, user] : users) {
        if (socket != sender && user.isAuthenticated && user.ssl) {
            try {
                if (SSL_write(user.ssl, message.c_str(), message.length()) <= 0)
                  logger.log("Failed to send message to " + user.username);
              }
            catch (const std::exception& e) {
                logger.log("Broadcast error: " + std::string(e.what()));
              }
          }
      }
  }

  void disconnectClient(int clientSocket) {
    std::lock_guard<std::mutex> lock(usersMutex);
    auto it = users.find(clientSocket);
    if (it != users.end()) {
        if (it->second.ssl) {
            // SSL_shutdown(it->second.ssl);
            // SSL_free(it->second.ssl);
          }
        close(clientSocket);
        logger.log("User " + it->second.username + " disconnected");
        users.erase(it);
      }
  }

    void handleCommand(const std::string& cmd, int sender) {
      try {
          std::string response;
          if (cmd == "/list") {
              std::lock_guard<std::mutex> lock(usersMutex);
              response = "Connected users:\n";
              for (const auto& [socket, user] : users) {
                  if (user.isAuthenticated) {
                      response += user.username + "\n";
                  }
              }
          }
          else if (cmd.substr(0, 5) == "/msg ") {
              std::istringstream iss(cmd.substr(5));
              std::string recipient, message;
              iss >> recipient;
              std::getline(iss, message);
              
              std::lock_guard<std::mutex> lock(usersMutex);
              bool found = false;
              for (const auto& [socket, user] : users) {
                  if (user.isAuthenticated && user.username == recipient) {
                      std::string privateMsg = "Private from " + users[sender].username + ":" + message;
                      SSL_write(user.ssl, privateMsg.c_str(), privateMsg.length());
                      found = true;
                      break;
                  }
              }
              if (!found) {
                  response = "User " + recipient + " not found";
              }
          }
          else if (cmd == "/help") {
              response = "Available commands:\n"
                        "/list - Show connected users\n"
                        "/msg <user> <message> - Send private message\n"
                        "/help - Show this help\n"
                        "/exit - Disconnect";
          }

          if (!response.empty()) {
              SSL_write(users[sender].ssl, response.c_str(), response.length());
          }
      } catch (const std::exception& e) {
          logger.log("Command handling error: " + std::string(e.what()));
      }
  }

public:
    ChatServer() : running(true), ctx(nullptr, SSL_CTX_free) {
        try {
            initializeSSL();
        } catch (const std::exception& e) {
            logger.log("Server initialization failed: " + std::string(e.what()));
            throw;
        }
    }

    bool init() {
        try {
            serverSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (serverSocket < 0) {
                throw std::runtime_error("Socket creation failed");
            }

            int opt = 1;
            if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
                throw std::runtime_error("setsockopt failed");
            }

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(PORT);
            serverAddr.sin_addr.s_addr = INADDR_ANY;

            if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                throw std::runtime_error("Bind failed");
            }

            if (listen(serverSocket, SOMAXCONN) < 0) {
                throw std::runtime_error("Listen failed");
            }

            logger.log("Server started on port " + std::to_string(PORT));
            return true;
        } catch (const std::exception& e) {
            logger.log("Server initialization error: " + std::string(e.what()));
            return false;
        }
    }

    void run() {
        while (running) {
            try {
                sockaddr_in clientAddr{};
                socklen_t clientLen = sizeof(clientAddr);
                int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
                
                if (clientSocket < 0) {
                    logger.log("Accept failed");
                    continue;
                }

                SSL* ssl = SSL_new(ctx.get());
                if (!ssl) {
                    logger.log("SSL creation failed");
                    close(clientSocket);
                    continue;
                }

                SSL_set_fd(ssl, clientSocket);
                if (SSL_accept(ssl) <= 0) {
                    logger.log("SSL accept failed");
                    SSL_free(ssl);
                    close(clientSocket);
                    continue;
                }

                {
                    std::lock_guard<std::mutex> lock(usersMutex);
                    users[clientSocket] = User("", clientSocket);
                }

                std::thread(&ChatServer::handleClient, this, clientSocket, ssl).detach();
            } catch (const std::exception& e) {
                logger.log("Connection handling error: " + std::string(e.what()));
            }
        }
    }

    ~ChatServer() {
        running = false;
        close(serverSocket);
        EVP_cleanup();
    }
};

int main() {
  ChatServer server;
  if (!server.init())
      return 1;
  server.run();
}
