#pragma once

#include <chrono>

using namespace std::chrono_literals;

class SettingsScanner
{
public:
    static SettingsScanner getSettings();

    int getAmountAttempt() const;
    uint32_t getTimeIntervalSendSyn() const;
    uint32_t getTimeIntervalAttempt() const;

private:
    SettingsScanner();

    int amountAttempt = 3; // Сколько раз сканер будет проходить по списку задач в попытке выполнить их
    uint32_t timeIntervalSendSynMs = 50; //Интервал времени между отправками SYN пакетов в соответстви с заданиями
    uint32_t timeIntervalAttemptMs = 5000; //Интервал между попытками прохода по списку заданий
};

