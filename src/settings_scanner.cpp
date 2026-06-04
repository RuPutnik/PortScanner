#include "settings_scanner.h"

SettingsScanner::SettingsScanner(int amountAttempt_, uint32_t timeIntervalSendSynMs_, uint32_t timeIntervalAttemptMs_,
                                 uint16_t srcPort_, uint32_t ackNumber_, uint16_t windowSize_,
                                 uint16_t urgent_, uint16_t mss_, bool sackPermitted_):
    amountAttempt{amountAttempt_},
    timeIntervalSendSynMs{timeIntervalSendSynMs_},
    timeIntervalAttemptMs{timeIntervalAttemptMs_},
    srcPort{srcPort_}, ackNumber{ackNumber_}, windowSize{windowSize_},
    urgent{urgent_}, mss{mss_}, sackPermitted{sackPermitted_}
{}

uint32_t SettingsScanner::getTimeIntervalAttempt() const
{
    return timeIntervalAttemptMs;
}

uint16_t SettingsScanner::getSrcPort() const
{
    return srcPort;
}

uint32_t SettingsScanner::getAckNumber() const
{
    return ackNumber;
}

uint16_t SettingsScanner::getWindowSize() const
{
    return windowSize;
}

uint16_t SettingsScanner::getUrgent() const
{
    return urgent;
}

uint16_t SettingsScanner::getMss() const
{
    return mss;
}

bool SettingsScanner::isSackPermitted() const
{
    return sackPermitted;
}

uint32_t SettingsScanner::getTimeIntervalSendSyn() const
{
    return timeIntervalSendSynMs;
}

int SettingsScanner::getAmountAttempt() const
{
    return amountAttempt;
}
