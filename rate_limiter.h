#pragma once

#include <chrono>
#include <unordered_map>
#include <mutex>

class RateLimiter {
private:
  struct UserRate {
    int messageCount;
    std::chrono::system_clock::time_point lastReset;
  };

  std::unordered_map<std::string, UserRate> rates;
  std::mutex mtx;
  const int MAX_MESSAGES = 10;
  const std::chrono::seconds WINDOW{5};

public:
  bool shouldLimit(const std::string& username) {
    std::lock_guard<std::mutex> lock(mtx);
    auto now = std::chrono::system_clock::now();
    auto& rate = rates[username];

    if (now - rate.lastReset > WINDOW) {
      rate.messageCount = 0;
      rate.lastReset = now;
    }

    if (rate.messageCount >= MAX_MESSAGES)
      return true;

    rate.messageCount++;
    return false;
  }
};
