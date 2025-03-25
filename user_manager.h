#pragma once
#include <string>
#include <memory>
#include <hiredis/hiredis.h>
#include <optional>

class UserManager {
private:
    std::unique_ptr<redisContext, void(*)(redisContext*)> redis;

public:
    UserManager() : redis(nullptr, redisFree) {
        redisContext* ctx = redisConnect("127.0.0.1", 6379);
        if (ctx == nullptr || ctx->err) {
            if (ctx) {
                throw std::runtime_error("Redis connection error: " + std::string(ctx->errstr));
            }
            throw std::runtime_error("Redis connection error: cannot allocate redis context");
        }
        redis = std::unique_ptr<redisContext, void(*)(redisContext*)>(ctx, redisFree);
    }

    bool createUser(const std::string& username, const std::string& password) {
        redisReply* reply = (redisReply*)redisCommand(redis.get(), 
            "HSETNX users %s %s", username.c_str(), password.c_str());
        
        if (!reply) {
            return false;
        }
        
        bool success = (reply->integer == 1);
        freeReplyObject(reply);
        return success;
    }

    bool validateUser(const std::string& username, const std::string& password) {
        redisReply* reply = (redisReply*)redisCommand(redis.get(), 
            "HGET users %s", username.c_str());
        
        if (!reply) {
            return false;
        }

        bool valid = (reply->type == REDIS_REPLY_STRING && 
                     std::string(reply->str) == password);
        freeReplyObject(reply);
        return valid;
    }
};