#pragma once

#include <QMainWindow>

class QThread;
class QLabel;
class QCheckBox;
class QHBoxLayout;
class QVBoxLayout;
class QPushButton;
class QTextEdit;
class QLineEdit;

class Task;
class SenderSynPack;

class ScannerWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit ScannerWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void startScanning();
    void stopScanning();
    void shooseFile();

private:
    QSet<Task> formTasks() const;
    QVector<uint32_t> textAddressToInt(const QString& address) const;

    QWidget* mainWidget;
    QVBoxLayout* mainLayout;
    QHBoxLayout* addressLayout;
    QHBoxLayout* portLayout;
    QHBoxLayout* writeResultControlLayout;
    QHBoxLayout* filePathLayout;
    QHBoxLayout* controlLayout;

    QLabel* addressLebel;
    QLineEdit* addressEdit;
    QLabel* portLabel;
    QLineEdit* portEdit;
    QLabel* chooseWriteResultLocation;
    QCheckBox* writeToWindowCBox;
    QCheckBox* writeToFileCBox;
    QLabel* filePathLabel;
    QLineEdit* filePathEdit;
    QPushButton* chooseFilePathButton;
    QTextEdit* resultScanningEdit;
    QPushButton* startButton;
    QPushButton* stopButton;

};


