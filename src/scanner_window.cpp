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

#include <sr.h>
#include <tools.h>

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
    qDebug() << "Start";
}

void ScannerWindow::shooseFile()
{
    const QString fileAbsPath = QFileDialog::getSaveFileName(this, "Выберите файл для записи резулдьтатов сканирования", "/");

    if(!fileAbsPath.isEmpty()){
        filePathEdit->setText(fileAbsPath);
    }
}

void ScannerWindow::stopScanning()
{
    qDebug() << "Stop";
}

void ScannerWindow::closeEvent(QCloseEvent* event)
{

}
