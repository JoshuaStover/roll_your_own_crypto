#include <iostream>
#include <fstream>
#include <vector>

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

void enc_dec_vec(std::vector<uint8_t> & file_contents, std::string key, std::string path, uint32_t len) {
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
    std::cout << "Encryption/Decryption successful." << std::endl;
}

int main(int argc, char* argv[]) {
    std::string path;
    std::string key;

    if (argc >=3) {
        path = argv[1];
        key = argv[2];
    }
    else {
        std::cout << "Enter the path to the file you wish to manipulate: " << std::endl;
        std::cin >> path;
        std::cout << "Enter the key you generated in hash.cpp: " << std::endl;
        std::cin >> key;
    }
    
    std::ifstream file_in(path.c_str(), std::ifstream::binary|std::ifstream::ate);
    std::streampos size = file_in.tellg();

    std::vector<char> fc_vec(static_cast<uint32_t>(size));
    std::vector<uint8_t> ai_vec(static_cast<uint32_t>(size));

    file_in.seekg(0, std::ifstream::beg);
    for (uint32_t i = 0; i < static_cast<uint32_t>(size); i++) {
        file_in.read(&fc_vec.at(i), 1);
    }
    file_in.close();
    
    to_int_vec(fc_vec, ai_vec, static_cast<uint32_t>(size));

    enc_dec_vec(ai_vec, key, path, static_cast<uint32_t>(size));

    return 0;
}