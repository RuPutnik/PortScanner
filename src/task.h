#pragma once

#include <QHashFunctions>

#include <cinttypes>

struct Task
{
    uint32_t ip;
    uint16_t port;
    bool finished;

    bool operator == (const Task& task) const
    {
        return ip == task.ip && port == task.port;
    }
};

inline uint64_t qHash(const Task& task, std::size_t seed = 0){
    return qHashMulti(seed, task.ip, task.port);
}
