#ifndef TASK_H
#define TASK_H

#include <cinttypes>

struct Task
{
    uint32_t ip;
    uint16_t port;
    bool finished;
};

#endif // TASK_H
