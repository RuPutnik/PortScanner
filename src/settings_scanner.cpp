#include "settings_scanner.h"

SettingsScanner SettingsScanner::getSettings()
{
    static SettingsScanner settings;

    return settings;
}

SettingsScanner::SettingsScanner()
{

}

uint32_t SettingsScanner::getTimeIntervalAttempt() const
{
    return timeIntervalAttemptMs;
}

uint32_t SettingsScanner::getTimeIntervalSendSyn() const
{
    return timeIntervalSendSynMs;
}

int SettingsScanner::getAmountAttempt() const
{
    return amountAttempt;
}
