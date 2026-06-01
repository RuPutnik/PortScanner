#include "scanner_window.h"

#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QRegularExpressionValidator>
#include <QRegularExpression>
#include <QFileDialog>

#include <arpa/inet.h>
#include <sr.h>
#include <tools.h>

#include "task.h"

ScannerWindow::ScannerWindow(QWidget *parent)
    : QMainWindow{parent},
    mainWidget{new QWidget},
    mainLayout{new QVBoxLayout},
    addressLayout{new QHBoxLayout},
    portLayout{new QHBoxLayout},
    writeResultControlLayout{new QHBoxLayout},
    filePathLayout{new QHBoxLayout},
    controlLayout{new QHBoxLayout},
    addressLebel{new QLabel{"IPv4 адреса"}},
    addressEdit{new QLineEdit},
    portLabel{new QLabel{"Порты"}},
    portEdit{new QLineEdit},
    chooseWriteResultLocation{new QLabel{"Куда выводить результаты"}},
    writeToWindowCBox{new QCheckBox{"В окно"}},
    writeToFileCBox{new QCheckBox{"В файл"}},
    filePathLabel{new QLabel{"Путь к файлу"}},
    filePathEdit{new QLineEdit},
    chooseFilePathButton{new QPushButton{"Выбрать файл"}},
    resultScanningEdit{new QTextEdit},
    startButton{new QPushButton{"Начать сканирование"}},
    stopButton{new QPushButton{"Остановить"}}
{
    addressLayout->addWidget(addressLebel);
    addressLayout->addWidget(addressEdit);

    portLayout->addWidget(portLabel);
    portLayout->addWidget(portEdit);

    writeResultControlLayout->addWidget(chooseWriteResultLocation);
    writeResultControlLayout->addWidget(writeToWindowCBox);
    writeResultControlLayout->addWidget(writeToFileCBox);

    filePathLayout->addWidget(filePathLabel);
    filePathLayout->addWidget(filePathEdit);
    filePathLayout->addWidget(chooseFilePathButton);

    controlLayout->addWidget(startButton);
    controlLayout->addWidget(stopButton);

    mainLayout->addLayout(addressLayout);
    mainLayout->addLayout(portLayout);
    mainLayout->addLayout(writeResultControlLayout);
    mainLayout->addLayout(filePathLayout);
    mainLayout->addWidget(resultScanningEdit);
    mainLayout->addLayout(controlLayout);

    mainWidget->setLayout(mainLayout);
    setCentralWidget(mainWidget);

    addressLayout->setSpacing(15);
    portLayout->setSpacing(15);
    writeResultControlLayout->setSpacing(15);
    filePathLayout->setSpacing(15);
    controlLayout->setSpacing(15);

    mainLayout->setSpacing(15);

    writeToWindowCBox->setCheckState(Qt::CheckState::Checked);

    portEdit->setValidator(new QRegularExpressionValidator{QRegularExpression("[0-9,\\-]*"), this});

    setWindowTitle("Сканер портов");

    resize(500, 600);

    connect(startButton, &QPushButton::clicked, this, &ScannerWindow::startScanning);
    connect(stopButton, &QPushButton::clicked, this, &ScannerWindow::stopScanning);
    connect(chooseFilePathButton, &QPushButton::clicked, this, &ScannerWindow::shooseFile);
}

void ScannerWindow::startScanning()
{
    resultScanningEdit->append("Начало процесса сканирования...");
    const auto tasks = formTasks();
    qDebug() << "Start";
}

void ScannerWindow::shooseFile()
{
    const QString fileAbsPath = QFileDialog::getSaveFileName(this, "Выберите файл для записи резулдьтатов сканирования", "/");

    if(!fileAbsPath.isEmpty()){
        filePathEdit->setText(fileAbsPath);
    }
}

QVector<Task> ScannerWindow::formTasks() const
{
    resultScanningEdit->append("Формирование заданий...");
    if(addressEdit->text().isEmpty() || portEdit->text().isEmpty()){
        resultScanningEdit->append("Не задано ни одного адреса или порта");
        return {};
    }

    QStringList addressesParts = addressEdit->text().split(",");

    QVector<uint32_t> ipV4addresses;

    for(const auto& currHost : addressesParts)
    {
        if(!currHost.contains("-"))
        {
            ipV4addresses.append(textAddressToInt(currHost));
            continue;
        }

        const QStringList bordersHostInterval = currHost.split("-");
        if(bordersHostInterval.first().startsWith("www.") || bordersHostInterval.last().startsWith("www.")){
            resultScanningEdit->append("В диапазонах адресов запрещено указывать доменные имена");
            continue;
        }

        uint32_t startInterval = textAddressToInt(bordersHostInterval.first()).first();
        const uint32_t endInterval = textAddressToInt(bordersHostInterval.last()).first();

        if(startInterval > endInterval){
            resultScanningEdit->append("Начало диапазона адресов больше конца диапазона");
            continue;
        }

        for(;startInterval <= endInterval; startInterval++){
            ipV4addresses.append(startInterval);
        }
    }

    const QStringList portsParts = portEdit->text().split(",");
    QVector<uint16_t> ports;

    for(const auto& currPort : portsParts)
    {
        if(currPort.contains("-"))
        {
            if(currPort.toULong() > UINT16_MAX){
                resultScanningEdit->append("В качестве порта задано слишком большое значение");
                continue;
            }

            ports.append(currPort.toUShort());
            continue;
        }

        const QStringList bordersPortInterval = currPort.split("-");
        uint16_t startInterval = bordersPortInterval.first().toUShort();
        const uint16_t endInterval = bordersPortInterval.last().toUShort();

        if(startInterval > endInterval){
            resultScanningEdit->append("Начало диапазона портов больше конца диапазона");
            continue;
        }

        if(endInterval > UINT16_MAX){
            resultScanningEdit->append("В интервале портов задано слишком большое значение");
            continue;
        }

        for(;startInterval <= endInterval; startInterval++){
            ports.append(startInterval);
        }
    }

    QVector<Task> tasksAnalyze;

    for(const auto& currIp : ipV4addresses)
    {
        for(const auto& currPort : ports)
        {
            tasksAnalyze.append(Task{currIp, currPort, false});
        }
    }

    return tasksAnalyze;
}

QVector<uint32_t> ScannerWindow::textAddressToInt(const QString& address) const
{
    QVector<uint32_t> numberAddresses;

    if(address.startsWith("www."))
    {
        const auto textAddresses = network::resolveHostname(address.toStdString());
        for(const auto& currTextAddress : textAddresses){
            uint32_t currAddress = 0;
            inet_pton(AF_INET, currTextAddress.data(), &currAddress);

            numberAddresses.append(ntohl(currAddress));
        }
    }
    else
    {
        uint32_t currAddress = 0;
        const auto stdTextAddress = address.toStdString();
        inet_pton(AF_INET, stdTextAddress.data(), &currAddress);

        numberAddresses.append(ntohl(currAddress));
    }

    return numberAddresses;
}

void ScannerWindow::stopScanning()
{
    qDebug() << "Stop";
}

void ScannerWindow::closeEvent(QCloseEvent* event)
{

}
