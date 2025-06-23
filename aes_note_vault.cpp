
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <string>
#include <sstream>

const std::string FILENAME = "notes.db";

// Convert password to a 32-byte key using SHA-256
std::vector<unsigned char> deriveKeyFromPassword(const std::string& password) {
    std::vector<unsigned char> key(32);
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), key.data());
    return key;
}

std::vector<unsigned char> generateRandomBytes(int length) {
    std::vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        std::cerr << "RAND_bytes failed." << std::endl;
        exit(EXIT_FAILURE);
    }
    return bytes;
}

std::vector<unsigned char> encryptText(const std::string& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) exit(EXIT_FAILURE);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, total_len = 0;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    total_len += len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &len);
    total_len += len;

    ciphertext.resize(total_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::string decryptText(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) exit(EXIT_FAILURE);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, total_len = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    total_len += len;

    EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &len);
    total_len += len;

    plaintext.resize(total_len);
    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

void saveNote(const std::vector<unsigned char>& iv,
              const std::vector<unsigned char>& ciphertext) {
    std::ofstream file(FILENAME, std::ios::app | std::ios::binary);
    int iv_size = iv.size();
    int ct_size = ciphertext.size();

    file.write(reinterpret_cast<char*>(&iv_size), sizeof(iv_size));
    file.write(reinterpret_cast<const char*>(iv.data()), iv_size);

    file.write(reinterpret_cast<char*>(&ct_size), sizeof(ct_size));
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ct_size);
}

void readNotes(const std::vector<unsigned char>& key) {
    std::ifstream file(FILENAME, std::ios::binary);
    if (!file) {
        std::cout << "No saved notes found.\n";
        return;
    }

    while (file.peek() != EOF) {
        int iv_size, ct_size;
        file.read(reinterpret_cast<char*>(&iv_size), sizeof(iv_size));
        std::vector<unsigned char> iv(iv_size);
        file.read(reinterpret_cast<char*>(iv.data()), iv_size);

        file.read(reinterpret_cast<char*>(&ct_size), sizeof(ct_size));
        std::vector<unsigned char> ciphertext(ct_size);
        file.read(reinterpret_cast<char*>(ciphertext.data()), ct_size);

        try {
            std::string note = decryptText(ciphertext, key, iv);
            std::cout << "\n🔓 Note: " << note << "\n";
        } catch (...) {
            std::cout << "\n⚠️ Skipped an invalid or mismatched note.\n";
        }
    }
}

int main() {
    std::string password;
    std::cout << "Enter password to secure your notes: ";
    std::getline(std::cin, password);
    std::vector<unsigned char> key = deriveKeyFromPassword(password);

    while (true) {
        std::cout << "\nMenu:\n1. Add Note\n2. View Notes\n3. Exit\nChoose: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore(); // flush newline

        if (choice == 1) {
            std::string note;
            std::cout << "Enter your secret note:\n> ";
            std::getline(std::cin, note);
            std::vector<unsigned char> iv = generateRandomBytes(16);
            std::vector<unsigned char> ct = encryptText(note, key, iv);
            saveNote(iv, ct);
            std::cout << "✅ Note encrypted and saved.\n";
        } else if (choice == 2) {
            std::cout << "\n🔍 Decrypting your notes...\n";
            readNotes(key);
        } else if (choice == 3) {
            std::cout << "👋 Exiting.\n";
            break;
        } else {
            std::cout << "⚠️ Invalid option.\n";
        }
    }

    return 0;
}
