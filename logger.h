#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <ctime>

class Logger {
public:
  static Logger& getInstance() {
    static Logger instance;
    return instance;
  }

  void log(const std::string& message) {
    std::lock_guard<std::mutex> lock(mtx);
    auto now = std::time(nullptr);
    auto* timeinfo = std::localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    logFile << "[" << timestamp << "] " << message << std::endl;
  }

private:
  Logger() {
    logFile.open("server.log", std::ios::app);
  }
  ~Logger() {
    if (logFile.is_open())
      logFile.close();
  }
  
  std::ofstream logFile;
  std::mutex mtx;
};
