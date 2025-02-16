#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QApplication>
#include <QListView>
#include <QStringListModel>
#include <QSocketNotifier>
#include <QMainWindow>
#include<QFile>
#include<QTextEdit>
#include<unistd.h>
#include<QMessageBox>
#include<QDialog>
#include<QVBoxLayout>
#include <unistd.h>
#include<QStringListModel>
#include <unistd.h>
#include <fcntl.h>
#include <QSocketNotifier>
#include<QStandardItemModel>
#include<QPlainTextEdit>
QT_BEGIN_NAMESPACE
namespace Ui { class safe_guard; }
QT_END_NAMESPACE
class OutputRedirector : public QObject
{
    Q_OBJECT
public:
    explicit OutputRedirector(QStringListModel *model, QObject *parent = nullptr);
    ~OutputRedirector();

private slots:
    void readOutput();

private:
    int pipefd[2];
    QSocketNotifier *notifier;
    QStringListModel *model;

};
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::safe_guard *ui;
    QStringListModel *model;
    OutputRedirector *outputRedirector;
};


#endif // MAINWINDOW_H
