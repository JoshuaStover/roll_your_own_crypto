#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <time.h>
#include <sstream>
#include <vector>
#include <iomanip>
#include <fstream>
#include <QMessageBox>



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow() {
    delete ui;
}

// Simple bitwise right rotation for 32-bit unsigned values
uint32_t bitwise_right(uint32_t number, uint32_t amount) {
    return (number >> (amount % 32)) | (number << (32 - (amount % 32)));
}

// Simple bitwise left rotation for 32-bit unsigned values
uint32_t bitwise_left(uint32_t number, uint32_t amount) {
    return (number << (amount % 32)) | (number >> (32 - (amount % 32)));
}

// Primary digest function, generates what will be the hashed value
uint32_t * digest(std::vector<uint32_t> & converted_pass, uint32_t * result, uint16_t arr_len) {
    for (uint16_t i = 0; i < arr_len / 16; i++) {
        // Loop though each group of 512 bits, compounding changes with each round
        result[0] += bitwise_left(result[0], converted_pass.at(16 * i)) * converted_pass.at(16 * i);
        result[1] += (converted_pass.at((16 * i) + 1) ^ result[0]) * result[0];
        result[2] += (result[0] & converted_pass.at((16 * i) + 2)) + result[1];
        result[3] += ((result[1] ^ result[2]) | converted_pass.at((16 * i) + 3)) - result[2];
        result[4] += bitwise_left(result[3] & converted_pass.at((16 * i) + 4), result[4]) + result[3];
        result[5] += bitwise_right(converted_pass.at((16 * i) + 5), result[4]) + result[4];
        result[6] += (!converted_pass.at((16 * i) + 6) ^ result[5]) * result[5];
        result[7] += bitwise_right(result[6] ^ result[5], converted_pass.at((16 * i) + 7)) + result[6];
        result[8] += bitwise_left(result[5] + converted_pass.at((16 * i) + 8), result[3]) - result[7];
        result[9] += (converted_pass.at((16 * i) + 9) ^ !result[7]) * result[8];
        result[10] += ((result[7] + converted_pass.at((16 * i) + 10)) - result[8]) & result[9];
        result[11] += bitwise_right(converted_pass.at((16 * i) + 11), result[3]) + result[10];
        result[12] += (converted_pass.at((16 * i) + 12) + result[2]) * result[11];
        result[13] += (converted_pass.at((16 * i) + 13) & result[1]) - !result[12];
        result[14] += (result[12] ^ result[0]) + converted_pass.at((16 * i) + 14);
        result[15] += (result[13] - converted_pass.at((16 * i) + 15)) * (result[14] ^ result[12]);
    }
    return result;
}

// Generates the array of integers representing the user's password with salting
void salted_conversion(std::string user_pass, std::vector<uint32_t> & converted_pass, uint16_t vec_size) {
    for (uint16_t i = 0; i < vec_size; i++) {
        time_t CURRENT_TIME = time(nullptr);
        converted_pass.at(i) =
        bitwise_left((static_cast<uint32_t>(user_pass[4 * i]) << (CURRENT_TIME % 11)) + (static_cast<uint32_t>(user_pass[(4 * i) + 2]) << (CURRENT_TIME % 19)), 24)
        + bitwise_left((static_cast<uint32_t>(user_pass[(4 * i) + 1]) << (CURRENT_TIME % 13)) + (static_cast<uint32_t>(user_pass[(4 * i) + 3]) << (CURRENT_TIME % 17)), 16)
        + bitwise_left((static_cast<uint32_t>(user_pass[(4 * i) + 3]) << (CURRENT_TIME % 17)) + (static_cast<uint32_t>(user_pass[4 * i]) << (CURRENT_TIME % 11)), 8)
        + ((static_cast<uint32_t>(user_pass[(4 * i) + 2])) << (CURRENT_TIME % 19)) + ((static_cast<uint32_t>(user_pass[(4 * i) + 1])) << (CURRENT_TIME % 13));
    }
}

// Generates the array of integers representing the user's password without salting
void unsalted_conversion(std::string user_pass, std::vector<uint32_t> & converted_pass, uint16_t arr_size) {
    for (uint16_t i = 0; i < arr_size; i++) {
        converted_pass.at(i) =
        bitwise_left((static_cast<uint32_t>(user_pass[4 * i]) <<  11) + (static_cast<uint32_t>(user_pass[(4 * i) + 2]) << 7), 24)
        + bitwise_left((static_cast<uint32_t>(user_pass[(4 * i) + 1]) << 13) + (static_cast<uint32_t>(user_pass[(4 * i) + 3]) << 11), 16)
        + bitwise_left((static_cast<uint32_t>(user_pass[(4 * i) + 3]) << 17) + (static_cast<uint32_t>(user_pass[4 * i]) << 13), 8)
        + ((static_cast<uint32_t>(user_pass[(4 * i) + 2]) << 19) + (static_cast<uint32_t>(user_pass[(4 * i) + 1]) << 17));
    }
}

std::string get512(uint32_t * digest) {
    std::stringstream ss;
    for (uint16_t i = 0; i < 16; i++) {ss << std::setfill('0') << std::setw(8) << std::right << std::hex << digest[i];}
    return ss.str();
}

std::string get256(uint32_t * digest) {
    uint32_t to_256[8] = {
            digest[0] + digest[8],
            digest[1] + digest[9],
            digest[2] + digest[10],
            digest[3] + digest[11],
            digest[4] + digest[12],
            digest[5] + digest[13],
            digest[6] + digest[14],
            digest[7] + digest[15]
        };
        std::stringstream ss;
        for (uint16_t i = 0; i < 8; i++) {ss << std::setfill('0') << std::setw(8) << std::right << std::hex << to_256[i];}
        return ss.str();
}

std::string get128(uint32_t * digest) {
    uint32_t to_128[4] = {
            (digest[0] & digest[8]) + (digest[4] ^ digest[12]),
            (digest[1] + digest[9]) * (digest[5] - digest[13]),
            (digest[2] ^ digest[10]) + (digest[6] & digest[14]),
            (digest[3] - digest[11]) * (digest[7] + digest[15])
        };
        std::stringstream ss;
        for (uint16_t i = 0; i < 4; i++) {ss << std::setfill('0') << std::setw(8) << std::right << std::hex << to_128[i];}
        return ss.str();
}

void pass_to_vec(std::string key, std::vector<uint8_t> & key_vector) {
    for (uint16_t i = 0; i < key.length() / 2; i++) {
        key_vector.at(i) = static_cast<uint8_t>(stoi(key.substr(2 * i, 2), nullptr, 16));
    }
}

void to_int_vec(std::vector<char> & input, std::vector<uint8_t> & output, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        output.at(i) = static_cast<uint8_t>(input.at(i));
    }
}

void file_enc_dec(std::vector<uint8_t> & file_contents, std::string key, std::string path, uint32_t len) {
    std::vector<uint8_t> key_vec(key.length() / 2);
        pass_to_vec(key, key_vec);

        for (uint32_t i = 0; i < len - ((key.length() / 2) - 1); i++) {
            for (uint16_t j = 0; j < key.length() / 2; j++) {
                file_contents.at(i + j) ^= key_vec.at(j);
            }
        }

        std::ofstream file_out(path.c_str(), std::ofstream::binary|std::ofstream::trunc);
        for (uint32_t i = 0; i < len; i++) {
            file_out << static_cast<char>(file_contents.at(i));
        }
        file_out.close();
        QMessageBox complete;
        complete.setText("Encryption/Decryption Complete");
        complete.exec();
}

void MainWindow::on_btn_Browse_clicked() {
    QString path = QFileDialog::getOpenFileName(this, "Select file to encrypt or decrypt", "/");
    ui->txt_path->setText(path);
}

void MainWindow::on_btn_Gen_clicked() {
    QString pass_input = ui->txt_password->text();
    std::string pass = pass_input.toUtf8().constData();
    std::string result = "";
    if (pass != "") {
        uint16_t key_size = 0;
        bool salt = ui->cbx_IsSalted->isChecked();
        if (ui->rdo_size128->isChecked()) {key_size = 1;}
        if (ui->rdo_size256->isChecked()) {key_size = 2;}
        if (ui->rdo_size512->isChecked()) {key_size = 3;}

        // Constants for message digest algorithm. Taken from the decimal portion of pi in chunks that are no greater than 2^32.
        uint32_t constants[16] = {
            1415926535, 897932384, 4264338327, 2884197169, 3993751058, 2097494459, 2307816406, 2862089986,
            2803482534, 2117067982, 1480865132, 823066470, 3844609550, 582231725, 3594081284, 811174502
        };

        // Append original string length to the input string as a 32-bit number
        pass.append(std::to_string(static_cast<uint32_t>(pass.length())));

        // Buffer the string so that its length is a multiple of 64
        while (pass.length() % 64 != 0) {pass.append("0");}

        // create array of size 1/4 the buffered password's length
        uint16_t vector_size = static_cast<uint16_t>(pass.length() / 4);
        std::vector<uint32_t> pass_as_ints(vector_size);

        salt ? salted_conversion(pass, pass_as_ints, vector_size) : unsalted_conversion(pass, pass_as_ints, vector_size);

        switch (key_size) {
            case 1:
                result = get128(digest(pass_as_ints, constants, vector_size));
                break;
            case 2:
                result = get256(digest(pass_as_ints, constants, vector_size));
                break;
            case 3:
                result = get512(digest(pass_as_ints, constants, vector_size));
                break;
        }
    }
    QString result_output = QString::fromStdString(result);
    ui->txt_key->setText(result_output);
}

void MainWindow::on_btn_enc_dec_clicked() {
    std::string key = ui->txt_key->text().toStdString();
    std::string path = ui->txt_path->text().toStdString();

    if ((key.length() > 0) && (path != " ")) {
        std::ifstream file_in(path.c_str(), std::ifstream::binary|std::ifstream::ate);
        std::streampos size = file_in.tellg();

        std::vector<char> file_content(static_cast<uint32_t>(size));
        std::vector<uint8_t> file_content_as_ints(static_cast<uint32_t>(size));

        file_in.seekg(0, std::ifstream::beg);
           for (uint32_t i = 0; i < static_cast<uint32_t>(size); i++) {
               file_in.read(&file_content.at(i), 1);
           }
        file_in.close();

        to_int_vec(file_content, file_content_as_ints, static_cast<uint32_t>(size));

        file_enc_dec(file_content_as_ints, key, path, static_cast<uint32_t>(size));
    }
}
