#pragma once

#include <chrono>

using namespace std::chrono_literals;

class SettingsScanner
{
public:
    SettingsScanner(int amountAttempt_, uint32_t timeIntervalSendSynMs_, uint32_t timeIntervalAttemptMs_,
                    uint16_t srcPort_, uint32_t ackNumber_, uint16_t windowSize_,
                    uint16_t urgent_, uint16_t mss_, bool sackPermitted_);

    int getAmountAttempt() const;
    uint32_t getTimeIntervalSendSyn() const;
    uint32_t getTimeIntervalAttempt() const;

    uint16_t getSrcPort() const;
    uint32_t getAckNumber() const;
    uint16_t getWindowSize() const;
    uint16_t getUrgent() const;
    uint16_t getMss() const;
    bool isSackPermitted() const;

private:
    int amountAttempt = 3; // Сколько раз сканер будет проходить по списку задач в попытке выполнить их
    uint32_t timeIntervalSendSynMs = 50; //Интервал времени между отправками SYN пакетов в соответстви с заданиями
    uint32_t timeIntervalAttemptMs = 5000; //Интервал между попытками прохода по списку заданий

    uint16_t srcPort;
    uint32_t ackNumber;
    uint16_t windowSize;
    uint16_t urgent;
    uint16_t mss;
    bool sackPermitted;

};

