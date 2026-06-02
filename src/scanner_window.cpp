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
#include <QThread>

#include <arpa/inet.h>
#include <sr.h>
#include <tools.h>

#include "task.h"
#include "sender_syn_pack.h"
#include "scanner_logger.h"

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
    stopButton{new QPushButton{"Остановить"}},
    senderThread{new QThread{this}}
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
    installLogger();

    ScannerLogger::logging("Начало процесса сканирования...");
    const auto tasks = formTasks();

    senderPack = new SenderSynPack{tasks, this};

    //TODO Тут настраиваем и запускаем потоки...
}

void ScannerWindow::shooseFile()
{
    const QString fileAbsPath = QFileDialog::getSaveFileName(this, "Выберите файл для записи резулдьтатов сканирования", "/");

    if(!fileAbsPath.isEmpty()){
        filePathEdit->setText(fileAbsPath);
    }
}

QSet<Task> ScannerWindow::formTasks() const
{
    ScannerLogger::logging("Формирование заданий...");
    if(addressEdit->text().isEmpty() || portEdit->text().isEmpty()){
        ScannerLogger::logging("Не задано ни одного адреса или порта");
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
            ScannerLogger::logging("В диапазонах адресов запрещено указывать доменные имена");
            continue;
        }

        uint32_t startInterval = textAddressToInt(bordersHostInterval.first()).first();
        const uint32_t endInterval = textAddressToInt(bordersHostInterval.last()).first();

        if(startInterval > endInterval){
            ScannerLogger::logging("Начало диапазона адресов больше конца диапазона");
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
                ScannerLogger::logging("В качестве порта задано слишком большое значение");
                continue;
            }

            ports.append(currPort.toUShort());
            continue;
        }

        const QStringList bordersPortInterval = currPort.split("-");
        uint16_t startInterval = bordersPortInterval.first().toUShort();
        const uint16_t endInterval = bordersPortInterval.last().toUShort();

        if(startInterval > endInterval){
            ScannerLogger::logging("Начало диапазона портов больше конца диапазона");
            continue;
        }

        if(bordersPortInterval.last().toULong() > UINT16_MAX){
            ScannerLogger::logging("В интервале портов задано слишком большое значение");
            continue;
        }

        for(;startInterval <= endInterval; startInterval++){
            ports.append(startInterval);
        }
    }

    QSet<Task> tasksAnalyze;

    for(const auto& currIp : ipV4addresses)
    {
        for(const auto& currPort : ports)
        {
            tasksAnalyze.insert(Task{currIp, currPort, false});
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
        if(textAddresses.empty()){
            ScannerLogger::logging(QString{"Доменное имя %1 не удалось разрешить в IpV4 и было пропущено"}.arg(address));
            return {};
        }

        for(const auto& currTextAddress : textAddresses)
        {
            if(const uint32_t currAddress = network::textIpV4ToUint(currTextAddress); currAddress != 0){
                numberAddresses.append(currAddress);
            }
        }
    }
    else
    {
        const uint32_t currAddress = network::textIpV4ToUint(address.toStdString());
        if(currAddress == 0){
            ScannerLogger::logging(QString{"IpV4 адрес %1 имеет некорректный формат и будет пропущен"}.arg(address));
            return {};
        }

        numberAddresses.append(currAddress);
    }

    return numberAddresses;
}

void ScannerWindow::installLogger() const
{
    ScannerLogger::LocationLogging location;

    if(writeToWindowCBox->isChecked() && writeToFileCBox->isChecked()){
        location = ScannerLogger::LocationLogging::BOTH;
    }
    else if(writeToWindowCBox->isChecked() && !writeToFileCBox->isChecked()){
        location = ScannerLogger::LocationLogging::WINDOW;
    }
    else{
        location = ScannerLogger::LocationLogging::FILE;
    }

    ScannerLogger::initLogger(location, filePathEdit->text(), resultScanningEdit);
}

void ScannerWindow::stopScanning()
{
    qDebug() << "Stop";
}

void ScannerWindow::closeEvent(QCloseEvent* event)
{

}
