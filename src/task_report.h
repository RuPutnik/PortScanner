#ifndef TASK_REPORT_H
#define TASK_REPORT_H

#include <cinttypes>

struct TaskReport
{
    enum class Status
    {
        Open,
        Closed,
        Filtered,
        NoData
    };

    uint32_t ip;
    uint16_t port;
    Status status;
};

#endif // TASK_REPORT_H
