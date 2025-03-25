#pragma once

#include <string>
#include <unordered_map>

struct User {
  std::string username;
  std::string password;
  int socket;
  bool isAuthenticated;
  SSL* ssl;
  
  User(const std::string& uname = "", int sock = -1) 
    : username(uname), socket(sock), isAuthenticated(false) {}
};

using UserMap = std::unordered_map<int, User>;
