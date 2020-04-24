#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_btn_Browse_clicked();

    void on_btn_Gen_clicked();

    void on_btn_encrypt_clicked();

    void on_btn_decrypt_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
