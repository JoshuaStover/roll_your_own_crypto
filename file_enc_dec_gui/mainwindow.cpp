#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <time.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <QDebug>



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
uint32_t * digest(uint32_t * converted_pass, uint32_t * output_arr, uint16_t arr_len) {
    for (uint16_t i = 0; i < arr_len / 16; i++) {
            output_arr[0] += bitwise_left(output_arr[0], converted_pass[16 * i]) * converted_pass[16 * i];
            output_arr[1] += (converted_pass[(16 * i) + 1] ^ output_arr[0]) * output_arr[0];
            output_arr[2] += (output_arr[0] & converted_pass[(16 * i) + 2]) + output_arr[1];
            output_arr[3] += ((output_arr[1] ^ output_arr[2]) | converted_pass[(16 * i) + 3]) - output_arr[2];
            output_arr[4] += bitwise_left(output_arr[3] & converted_pass[(16 * i) + 4], output_arr[4]) + output_arr[3];
            output_arr[5] += bitwise_right(converted_pass[(16 * i) + 5], output_arr[4]) + output_arr[4];
            output_arr[6] += (!converted_pass[(16 * i) + 6] ^ output_arr[5]) * output_arr[5];
            output_arr[7] += bitwise_right(output_arr[6] ^ output_arr[5], converted_pass[(16 * i) + 7]) + output_arr[6];
            output_arr[8] += bitwise_left(output_arr[5] + converted_pass[(16 * i) + 8], output_arr[3]) - output_arr[7];
            output_arr[9] += (converted_pass[(16 * i) + 9] ^ !output_arr[7]) * output_arr[8];
            output_arr[10] += ((output_arr[7] + converted_pass[(16 * i) + 10]) - output_arr[8]) & output_arr[9];
            output_arr[11] += bitwise_right(converted_pass[(16 * i) + 11], output_arr[3]) + output_arr[10];
            output_arr[12] += (converted_pass[(16 * i) + 12] + output_arr[2]) * output_arr[11];
            output_arr[13] += (converted_pass[(16 * i) + 13] & output_arr[1]) - !output_arr[12];
            output_arr[14] += (output_arr[12] ^ output_arr[0]) + converted_pass[(16 * i) + 14];
            output_arr[15] += (output_arr[13] - converted_pass[(16 * i) + 15]) * (output_arr[14] ^ output_arr[12]);
        }
        return output_arr;
}

// Generates the array of integers representing the user's password with salting
uint32_t * salted_conversion(std::string user_pass, uint32_t * converted_pass, uint16_t arr_size) {
    for (uint16_t i = 0; i < arr_size; i++) {
        time_t CURRENT_TIME = time(nullptr);
        converted_pass[i] =
            bitwise_left(((uint32_t)user_pass[4 * i] << (CURRENT_TIME % 11)) + ((uint32_t)user_pass[(4 * i) + 2] << (CURRENT_TIME % 19)), 24)
            + bitwise_left(((uint32_t)user_pass[(4 * i) + 1] << (CURRENT_TIME % 13)) + ((uint32_t)user_pass[(4 * i) + 3] << (CURRENT_TIME % 17)), 16)
            + bitwise_left(((uint32_t)user_pass[(4 * i) + 3] << (CURRENT_TIME % 17)) + ((uint32_t)user_pass[4 * i] << (CURRENT_TIME % 11)), 8)
            + (((uint32_t)user_pass[(4 * i) + 2] << (CURRENT_TIME % 19)) + ((uint32_t)user_pass[(4 * i) + 1] << (CURRENT_TIME % 13)));
        }
    return converted_pass;
}

// Generates the array of integers representing the user's password without salting
uint32_t * unsalted_conversion(std::string user_pass, uint32_t * converted_pass, uint16_t arr_size) {
    for (uint16_t i = 0; i < arr_size; i++) {
        converted_pass[i] =
        bitwise_left(((uint32_t)user_pass[4 * i] <<  11) + ((uint32_t)user_pass[(4 * i) + 2] << 7), 24)
        + bitwise_left(((uint32_t)user_pass[(4 * i) + 1] << 13) + ((uint32_t)user_pass[(4 * i) + 3] << 11), 16)
        + bitwise_left(((uint32_t)user_pass[(4 * i) + 3] << 17) + ((uint32_t)user_pass[4 * i] << 13), 8)
        + (((uint32_t)user_pass[(4 * i) + 2] << 19) + ((uint32_t)user_pass[(4 * i) + 1] << 17));
    }
    return converted_pass;
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

void pass_to_arr(std::string key, uint8_t* out_arr) {
    for (uint16_t i = 0; i < key.length() / 2; i++) {
        out_arr[i] = (uint8_t)stoi(key.substr(2 * i, 2), nullptr, 16);
    }
}

void to_int_arr(char* in_arr, uint8_t* out_arr, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        out_arr[i] = (uint8_t)in_arr[i];
    }
}

void to_char_arr(uint8_t* in_arr, char* out_arr, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        out_arr[i] = (char)in_arr[i];
    }
}

void file_enc(uint8_t* plaintext, std::streampos len, std::string key, std::string path) {
    uint8_t key_arr[key.length() / 2];
    pass_to_arr(key, key_arr);

    for (uint32_t i = 0; i < (uint32_t)len - ((key.length() / 2) - 1); i++) {
        for (uint16_t j = 0; j < key.length() / 2; j++) {
            plaintext[i + j] ^= key_arr[j];
        }
    }

    std::ofstream encrypted(path.c_str(), std::ofstream::binary|std::ofstream::trunc);
    for (uint32_t i = 0; i < (uint32_t)len; i++) {
        encrypted << (char)plaintext[i];
    }
    encrypted.close();
}

void file_dec(uint8_t* ciphertext, std::streampos len, std::string key, std::string path) {
    uint8_t key_arr[key.length() / 2];
    pass_to_arr(key, key_arr);

    for (uint32_t i = (uint32_t)len - (key.length() / 2); i < std::numeric_limits<uint32_t>::max(); i--) {
        for (uint16_t j = 0; j < key.length() / 2; j++) {
            ciphertext[i + j] ^= key_arr[j];
        }
    }

    std::ofstream decrypted(path.c_str(), std::ofstream::binary|std::ofstream::trunc);
    for (uint32_t i = 0; i < (uint32_t)len; i++) {
        decrypted << (char)ciphertext[i];
    }
    decrypted.close();
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
        pass.append(std::to_string((uint32_t)pass.length()));

        // Buffer the string so that its length is a multiple of 64
        while (pass.length() % 64 != 0) {pass.append("0");}

        // create array of size 1/4 the buffered password's length
        uint16_t array_size = pass.length() / 4;
        uint32_t pass_as_ints[array_size];

        salt ? salted_conversion(pass, pass_as_ints, array_size) : unsalted_conversion(pass, pass_as_ints, array_size);

        switch (key_size) {
            case 1:
                result = get128(digest(pass_as_ints, constants, array_size));
                break;
            case 2:
                result = get256(digest(pass_as_ints, constants, array_size));
                break;
            case 3:
                result = get512(digest(pass_as_ints, constants, array_size));
                break;
        }
    }
    QString result_output = QString::fromStdString(result);
    ui->txt_key->setText(result_output);
}

void MainWindow::on_btn_encrypt_clicked() {
    std::string key = ui->txt_key->text().toStdString();
    std::string path = ui->txt_path->text().toStdString();

    if ((key.length() > 0) && (path != " ")) {
        std::ifstream to_enc(path.c_str(), std::ifstream::binary|std::ifstream::ate);
        std::streampos size = to_enc.tellg();
        char enc_copy[(uint32_t)size];
        uint8_t enc_as_ints[(uint32_t)size];
        to_enc.seekg(0, std::ifstream::beg);
        to_enc.read(enc_copy, size);
        to_enc.close();

        to_int_arr(enc_copy, enc_as_ints, (uint32_t)size);

        file_enc(enc_as_ints, size, key, path);
    }
}

void MainWindow::on_btn_decrypt_clicked() {
    std::string key = ui->txt_key->text().toStdString();
    std::string path = ui->txt_path->text().toStdString();
    if ((key.length() > 0) && (path != " ")) {
        std::ifstream to_dec(path.c_str(), std::ifstream::binary|std::ifstream::ate);
        std::streampos size = to_dec.tellg();
        char dec_copy[(uint32_t)size];
        uint8_t dec_as_ints[(uint32_t)size];
        to_dec.seekg(0, std::ifstream::beg);
        to_dec.read(dec_copy, size);
        to_dec.close();

        to_int_arr(dec_copy, dec_as_ints, (uint32_t)size);

        file_dec(dec_as_ints, size, key, path);
    }
}
