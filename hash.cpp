#include <iostream>
#include <iomanip>
#include <sstream>
#include <time.h>
#include <limits>
#include <vector>

// Bitwise left rotation of a given 32-bit number
uint32_t bitwise_left(uint32_t number, uint32_t amount) {
    return (number << (amount % 32)) | (number >> (32 - (amount % 32)));
}

// Bitwise right rotation of a given 32-bit number
uint32_t bitwise_right(uint32_t number, uint32_t amount) {
    return (number >> (amount % 32)) | (number << (32 - (amount % 32)));
}

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

// Generate 512-bit key from user password
std::string generate512(uint32_t * digest) {
    std::stringstream ss;
    for (uint16_t i = 0; i < 16; i++) {ss << std::setfill('0') << std::setw(8) << std::right << std::hex << digest[i];}
    return ss.str();
}

// Generate 256-bit key from user password
std::string generate256(uint32_t * digest) {
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

// Generate 128-bit key from user password
std::string generate128(uint32_t * digest) {
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

int main() {
    int16_t user_key_choice;
    std::string user_password;
    bool salted = false;
    std::string salted_choice;
    std::string user_key;

    // Constants for message digest algorithm. Taken from the decimal portion of pi in chunks that are no greater than 2^32.
    uint32_t result[16] = {
    1415926535, 897932384, 4264338327, 2884197169, 3993751058, 2097494459, 2307816406, 2862089986,
    2803482534, 2117067982, 1480865132, 823066470, 3844609550, 582231725, 3594081284, 811174502
    };

    std::cout << "Choose a key size for your password. Enter '1' for 128-bit, '2' for 256-bit, or '3' for 512-bit: ";
    while (true) {
        while (!(std::cin >> user_key_choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << std::endl << "Invalid input, please enter a number: ";
        }
        if (user_key_choice < 1 || user_key_choice > 3) {
            std::cout << "Please select either 1, 2, or 3." << std::endl;
        }
        else {break;}
    }

    std::cout << "Would you like to salt the password? (y/n): ";
    while(true) {
        std::cin >> salted_choice;
        if (salted_choice[0] == 'y' || salted_choice[0] == 'Y') {
            salted = true;
            break;
        }
        else if (salted_choice[0] == 'n' || salted_choice[0] == 'N') {break;}
        else {std::cout << "Invalid input, please try again." << std::endl;}
    }
    
    std::cout << "Enter a password to be hashed: ";
    std::cin >> user_password;

    // Append original string length to the input string as a 32-bit number
    user_password.append(std::to_string((uint32_t)user_password.length()));

    // Buffer the string so that its length is a multiple of 64
    while (user_password.length() % 64 != 0) {user_password.append("0");}
    
    // create vector of size 1/4 the buffered password's length
    uint16_t vector_size = user_password.length() / 4;
    std::vector<uint32_t> pass_as_ints(vector_size);
    

    salted ? salted_conversion(user_password, pass_as_ints, vector_size) : unsalted_conversion(user_password, pass_as_ints, vector_size);

    switch (user_key_choice) {
        case 1:
            std::cout << generate128(digest(pass_as_ints, result, vector_size)) << std::endl;
            break;
        case 2:
            std::cout << generate256(digest(pass_as_ints, result, vector_size)) << std::endl;
            break;
        case 3:
            std::cout << generate512(digest(pass_as_ints, result, vector_size)) << std::endl;
    }

    return 0;
}