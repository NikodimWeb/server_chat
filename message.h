#pragma once

#include <string>
#include <chrono>

enum class MessageType {
  BROADCAST,
  PRIVATE,
  SYSTEM,
  HEARTBEAT
};

struct Message {
  MessageType type;
  std::string sender;
  std::string recipient;
  std::string content;
  std::chrono::system_clock::time_point timestamp;

  Message(MessageType t, const std::string& s, const std::string& c)
    : type(t), sender(s), content(c), timestamp(std::chrono::system_clock::now()) {}
};
