#include "mainwindow.h"
#include<thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <QApplication>
#include<unistd.h>
int start();
int main(int argc, char *argv[])
{
        chdir("../");
    QApplication a(argc, argv);

    MainWindow w;
     QObject::connect(&w, &QMainWindow::destroyed, &a, &QApplication::quit);
    if(start()<0){
         printf("start err\n");
         exit(-1);
    }
   // printf("start\n");
    w.show();

    return a.exec();
}
