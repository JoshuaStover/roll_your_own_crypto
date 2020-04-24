#include <iostream>
#include <fstream>
#include <limits>

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

void write_file(uint8_t* processed_file, std::streampos len, std::string path){
    std::ofstream file_out(path.c_str(), std::ofstream::binary|std::ofstream::trunc);
    for (uint32_t i = 0; i < (uint32_t)len; i++) {
        file_out << (char)processed_file[i];
    }
    file_out.close();
}

void file_enc(uint8_t* plaintext, std::streampos len, std::string key, std::string path) {
    uint8_t key_arr[key.length() / 2];
    pass_to_arr(key, key_arr);

    for (uint32_t i = 0; i < (uint32_t)len - ((key.length() / 2) - 1); i++) {
        for (uint16_t j = 0; j < key.length() / 2; j++) {
            plaintext[i + j] ^= key_arr[j];
        }
    }

    write_file(plaintext, len, path);
    std::cout << "File successfully encrypted." << std::endl;
}

void file_dec(uint8_t* ciphertext, std::streampos len, std::string key, std::string path) {
    uint8_t key_arr[key.length() / 2];
    pass_to_arr(key, key_arr);

    for (uint32_t i = (uint32_t)len - (key.length() / 2); i < std::numeric_limits<uint32_t>::max(); i--) {
        for (uint16_t j = 0; j < key.length() / 2; j++) {
            ciphertext[i + j] ^= key_arr[j];
        }
    }

    write_file(ciphertext, len, path);
    std::cout << "File successfully decrypted." << std::endl;
}

int main(int argc, char* argv[]) {
    std::string path;
    std::string key;
    std::string enc_dec_choice;

    if (argc >=3) {
        path = argv[1];
        key = argv[2];
    }
    else {
        std::cout << "Please enter the path to the file you wish to manipulate: " << std::endl;
        std::cin >> path;
        std::cout << "Please enter the password generated in hash.cpp: " << std::endl;
        std::cin >> key;
    }
    
    std::ifstream file_in(path.c_str(), std::ifstream::binary|std::ifstream::ate);
    std::streampos size = file_in.tellg();

    char file_copy[(uint32_t)size];
    uint8_t as_ints[(uint32_t)size];

    file_in.seekg(0, std::ifstream::beg);
    while (!file_in.eof()) {file_in.read(file_copy, 1);}
    file_in.close();

    to_int_arr(file_copy, as_ints, (uint32_t)size);
    
    std::cout << "Would you like to encrypt or decrypt? (E/D): ";
    while(true) {
        std::cin >> enc_dec_choice;
        if (enc_dec_choice[0] == 'e' || enc_dec_choice[0] == 'E') {
            file_enc(as_ints, size, key, path);
            break;
        }
        else if (enc_dec_choice[0] == 'd' || enc_dec_choice[0] == 'D') {
            file_dec(as_ints, size, key, path);
            break;
            }
        else {std::cout << "Invalid input, please try again." << std::endl;}
    }

    return 0;
}