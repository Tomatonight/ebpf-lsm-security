/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.7.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QListView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_safe_guard
{
public:
    QAction *action_1;
    QAction *action_2;
    QWidget *centralwidget;
    QPushButton *pb;
    QPushButton *pb_1;
    QPushButton *pb_2;
    QPushButton *pb_3;
    QPushButton *pb_4;
    QListView *view;
    QMenuBar *menuBar;
    QMenu *menu;

    void setupUi(QMainWindow *safe_guard)
    {
        if (safe_guard->objectName().isEmpty())
            safe_guard->setObjectName("safe_guard");
        safe_guard->resize(761, 600);
        safe_guard->setStyleSheet(QString::fromUtf8("background-color:rgb(246, 245, 244);"));
        action_1 = new QAction(safe_guard);
        action_1->setObjectName("action_1");
        action_1->setCheckable(true);
        action_2 = new QAction(safe_guard);
        action_2->setObjectName("action_2");
        centralwidget = new QWidget(safe_guard);
        centralwidget->setObjectName("centralwidget");
        centralwidget->setStyleSheet(QString::fromUtf8(""));
        pb = new QPushButton(centralwidget);
        pb->setObjectName("pb");
        pb->setGeometry(QRect(70, 60, 131, 61));
        pb->setStyleSheet(QString::fromUtf8("background-color:rgb(192, 191, 188);\n"
"border-radius: 10px;"));
        pb_1 = new QPushButton(centralwidget);
        pb_1->setObjectName("pb_1");
        pb_1->setGeometry(QRect(290, 60, 131, 61));
        pb_1->setStyleSheet(QString::fromUtf8("background-color:rgb(192, 191, 188);\n"
"border-radius: 10px;"));
        pb_2 = new QPushButton(centralwidget);
        pb_2->setObjectName("pb_2");
        pb_2->setGeometry(QRect(510, 60, 131, 61));
        pb_2->setStyleSheet(QString::fromUtf8("background-color:rgb(192, 191, 188);\n"
"border-radius: 10px;"));
        pb_3 = new QPushButton(centralwidget);
        pb_3->setObjectName("pb_3");
        pb_3->setGeometry(QRect(70, 180, 131, 61));
        pb_3->setStyleSheet(QString::fromUtf8("background-color:rgb(192, 191, 188);\n"
"border-radius: 10px;"));
        pb_4 = new QPushButton(centralwidget);
        pb_4->setObjectName("pb_4");
        pb_4->setGeometry(QRect(290, 180, 131, 61));
        pb_4->setStyleSheet(QString::fromUtf8("background-color:rgb(192, 191, 188);\n"
"border-radius: 10px;"));
        view = new QListView(centralwidget);
        view->setObjectName("view");
        view->setGeometry(QRect(10, 270, 741, 291));
        view->setStyleSheet(QString::fromUtf8("background-color:rgb(255, 255, 255);\n"
"border: 1px solid black"));
        safe_guard->setCentralWidget(centralwidget);
        menuBar = new QMenuBar(safe_guard);
        menuBar->setObjectName("menuBar");
        menuBar->setGeometry(QRect(0, 0, 761, 27));
        menu = new QMenu(menuBar);
        menu->setObjectName("menu");
        safe_guard->setMenuBar(menuBar);

        menuBar->addAction(menu->menuAction());
        menu->addAction(action_1);
        menu->addAction(action_2);

        retranslateUi(safe_guard);

        QMetaObject::connectSlotsByName(safe_guard);
    } // setupUi

    void retranslateUi(QMainWindow *safe_guard)
    {
        safe_guard->setWindowTitle(QCoreApplication::translate("safe_guard", "MainWindow", nullptr));
        action_1->setText(QCoreApplication::translate("safe_guard", "\346\230\276\347\244\272\346\213\246\346\210\252", nullptr));
        action_2->setText(QCoreApplication::translate("safe_guard", "\344\277\256\346\224\271\346\227\245\345\277\227\350\267\257\345\276\204", nullptr));
        pb->setText(QCoreApplication::translate("safe_guard", "\346\237\245\347\234\213\345\275\223\345\211\215\350\247\204\345\210\231", nullptr));
        pb_1->setText(QCoreApplication::translate("safe_guard", "\346\233\264\346\226\260\350\247\204\345\210\231", nullptr));
        pb_2->setText(QCoreApplication::translate("safe_guard", "\346\270\205\347\251\272\350\247\204\345\210\231", nullptr));
        pb_3->setText(QCoreApplication::translate("safe_guard", "\344\275\277\347\224\250\350\257\264\346\230\216", nullptr));
        pb_4->setText(QCoreApplication::translate("safe_guard", "\346\237\245\347\234\213\346\227\245\345\277\227", nullptr));
        menu->setTitle(QCoreApplication::translate("safe_guard", "\350\256\276\347\275\256", nullptr));
    } // retranslateUi

};

namespace Ui {
    class safe_guard: public Ui_safe_guard {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
