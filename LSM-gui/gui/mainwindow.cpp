#include "mainwindow.h"
#include "ui_mainwindow.h"
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
#include<QDir>
#include<QLineEdit>
#include<QListWidget>

void read_command(std::string str);
void get_current_date(char *buffer, size_t buffer_size);
bool to_view;
extern std::string log_path;
extern bool log_path_updata;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::safe_guard)
{
    ui->setupUi(this);
    model = new QStringListModel(this);
    setWindowTitle("safe guard");
   printf("start\n");
outputRedirector = new OutputRedirector(model, this);
    ui->view->setModel(model);

    ui->view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->view->setWordWrap(true);
 //   ui->view->setWrapping(true);
 //   fflush(stdout);
    connect(ui->pb, &QPushButton::clicked, this, [=]() {

   QString filePath = "configure/configure.json";

    // 创建非模态对话框（在堆上分配，并在关闭时自动删除）
    QDialog *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle("编辑 JSON 文件");
    dialog->resize(600, 400);

    // 创建文本编辑器，并将字体调大
    QTextEdit *textEdit = new QTextEdit(dialog);
    QFont font = textEdit->font();
    font.setPointSize(font.pointSize() + 2);  // 增大字体大小
    textEdit->setFont(font);

    // 加载文件内容到文本编辑器中
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        textEdit->setText(file.readAll());
        file.close();
    } else {
        QMessageBox::warning(dialog, "错误", "无法打开文件进行读取！");
        return;
    }

    // 创建“保存”和“取消”按钮
    QPushButton *saveButton = new QPushButton("保存", dialog);
    QPushButton *cancelButton = new QPushButton("取消", dialog);

    // 设置布局
    QVBoxLayout *mainLayout = new QVBoxLayout(dialog);
    mainLayout->addWidget(textEdit);

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(cancelButton);
    mainLayout->addLayout(buttonLayout);

    // 保存按钮点击后直接保存文件并关闭对话框（不弹出额外提示）
    connect(saveButton, &QPushButton::clicked, [=]() {
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << textEdit->toPlainText();
            file.close();
            dialog->close();  // 保存成功后关闭对话框
        } else {
            QMessageBox::warning(dialog, "错误", "无法打开文件进行写入！");
        }
    });

    // 取消按钮直接关闭对话框
    connect(cancelButton, &QPushButton::clicked, dialog, &QDialog::close);

    // 显示非模态对话框，主窗口仍可操作
    dialog->show();

    });
    connect(ui->pb_1,&QPushButton::clicked,this,[=](){
        read_command("updata\n");
    });
    connect(ui->pb_2,&QPushButton::clicked,this,[=](){
         read_command("clear\n");
    });
    connect(ui->pb_3,&QPushButton::clicked,this,[=](){
        QFile file("readme");
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "无法打开文件！");
            return;
        }

        // 读取文件内容
        QTextStream stream(&file);
        QString content = stream.readAll();
        file.close();

        // 创建非模态对话框
        QDialog *fileDialog = new QDialog(this);
        fileDialog->setWindowTitle("readme");
        fileDialog->setAttribute(Qt::WA_DeleteOnClose); // 关闭时自动释放内存

        // 使用布局管理器
        QVBoxLayout *layout = new QVBoxLayout(fileDialog);

        // 创建只读文本编辑框
        QTextEdit *textEdit = new QTextEdit;
        textEdit->setReadOnly(true);
        textEdit->setPlainText(content);
        textEdit->setStyleSheet("QTextEdit { background-color: #f0f0f0; }");

        // 将控件加入布局
        layout->addWidget(textEdit);

        // 设置对话框尺寸
        fileDialog->resize(600, 400);

        // 显示非模态对话框，主窗口仍可操作
        fileDialog->show();
    });
    connect(ui->pb_4,&QPushButton::clicked,this,[=](){
        QDir dir("log");
        if (!dir.exists()) {
            QMessageBox::warning(this, "错误", "目录 log/ 不存在！");
            return;
        }

        // 创建显示文件列表的非模态对话框
        QDialog *dirDialog = new QDialog(this);
        dirDialog->setWindowTitle("日志文件列表");
        dirDialog->setAttribute(Qt::WA_DeleteOnClose);
        dirDialog->resize(400, 300);

        QVBoxLayout *layout = new QVBoxLayout(dirDialog);

        // 使用 QListWidget 显示目录下的文件
        QListWidget *fileListWidget = new QListWidget(dirDialog);
        layout->addWidget(fileListWidget);

        // 获取 log/ 目录下所有的文件（不包含子目录）
        QFileInfoList fileList = dir.entryInfoList(QDir::Files);
        for (const QFileInfo &fileInfo : fileList) {
            QListWidgetItem *item = new QListWidgetItem(fileInfo.fileName(), fileListWidget);
            // 将完整路径存储在 item 的 UserRole 数据中
            item->setData(Qt::UserRole, fileInfo.absoluteFilePath());
        }

        // 双击文件项时，打开只读文件显示窗口
        connect(fileListWidget, &QListWidget::itemDoubleClicked, [=](QListWidgetItem *item) {
            QString filePath = item->data(Qt::UserRole).toString();

            QFile file(filePath);
            if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QMessageBox::warning(dirDialog, "错误", "无法打开文件：" + filePath);
                return;
            }

            QTextStream stream(&file);
            QString content = stream.readAll();
            file.close();

            // 创建显示文件内容的非模态对话框
            QDialog *fileDialog = new QDialog(this);
            fileDialog->setWindowTitle(item->text());
            fileDialog->setAttribute(Qt::WA_DeleteOnClose);
            fileDialog->resize(600, 400);

            QVBoxLayout *fileLayout = new QVBoxLayout(fileDialog);
            QTextEdit *textEdit = new QTextEdit(fileDialog);
            textEdit->setReadOnly(true);
            textEdit->setPlainText(content);
            fileLayout->addWidget(textEdit);

            fileDialog->show();
        });

        dirDialog->show();
    });
    to_view=true;
    ui->action_1->setChecked(true);
    connect(ui->action_1,&QAction::toggled,this,[=](){
        to_view=!to_view;
    });
connect(ui->action_2, &QAction::triggered, this, [=]() {
    // 创建对话框
    QDialog *inputDialog = new QDialog(this);
    inputDialog->setWindowTitle("输入path");
    inputDialog->setAttribute(Qt::WA_DeleteOnClose);

    // 设置对话框布局
    QVBoxLayout *layout = new QVBoxLayout(inputDialog);

    // 创建一个 QLineEdit 用于输入字符串
    QLineEdit *inputLineEdit = new QLineEdit(inputDialog);
    layout->addWidget(inputLineEdit);

    // 创建确认和退出按钮
    QPushButton *confirmButton = new QPushButton("确认", inputDialog);
    QPushButton *cancelButton = new QPushButton("退出", inputDialog);

    // 按钮布局
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(confirmButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    // 确认按钮点击事件
    connect(confirmButton, &QPushButton::clicked, [=]() {
        QString inputText = inputLineEdit->text();
     //   qDebug() << "输入的字符串：" << inputText;  // 打印输入的字符串
        if(inputText[0]!='/')
        log_path="log/"+inputText.toStdString();
        else log_path=inputText.toStdString();
        log_path_updata=true;
        inputDialog->accept();  // 关闭对话框
    });

    // 退出按钮点击事件
    connect(cancelButton, &QPushButton::clicked, inputDialog, &QDialog::reject);  // 关闭对话框

    // 显示对话框
    inputDialog->exec();
});
}

MainWindow::~MainWindow()
{
     QApplication::quit();
    delete ui;

}
OutputRedirector::OutputRedirector(QStringListModel *model, QObject *parent)
    : QObject(parent), model(model)
{
    // 创建管道
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }

    // 将管道读端设置为非阻塞模式
    int flags = fcntl(pipefd[0], F_GETFL);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    // 将 stdout 重定向到管道写端
    dup2(pipefd[1], STDOUT_FILENO);

    // 利用 QSocketNotifier 监听管道读端的可读事件
    notifier = new QSocketNotifier(pipefd[0], QSocketNotifier::Read, this);
    connect(notifier, &QSocketNotifier::activated, this, &OutputRedirector::readOutput);
}

OutputRedirector::~OutputRedirector()
{
    close(pipefd[0]);
    close(pipefd[1]);
}

void OutputRedirector::readOutput()
{
    char buffer[1024];
    ssize_t n = read(pipefd[0], buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        QString output = QString::fromLocal8Bit(buffer);

       //  按行拆分输出内容（注意可能存在多行输出）
        QStringList lines = output.split("\n", Qt::SkipEmptyParts);

       //  将新内容追加到模型中
        QStringList currentList = model->stringList();
        currentList.append(lines);
        model->setStringList(currentList);
    }
}

