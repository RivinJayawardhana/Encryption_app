#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

const std::string FILENAME = "note.sec";

void handleErrors() {
    std::cerr << "OpenSSL error occurred.\n";
    exit(EXIT_FAILURE);
}

std::vector<unsigned char> generateRandomBytes(int length) {
    std::vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        handleErrors();
    }
    return bytes;
}

std::vector<unsigned char> encryptNote(const std::string& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        handleErrors();

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1)
        handleErrors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::string decryptNote(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        handleErrors();

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        handleErrors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return std::string(plaintext.begin(), plaintext.end());
}

bool saveToFile(const std::string& filename, const std::vector<unsigned char>& data,
                const std::vector<unsigned char>& iv) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;

    file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool loadFromFile(const std::string& filename, std::vector<unsigned char>& data,
                  std::vector<unsigned char>& iv) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    iv.resize(16);
    file.read(reinterpret_cast<char*>(iv.data()), 16);
    if (file.gcount() != 16) return false;

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
    if (buffer.empty()) return false;

    data = buffer;
    return true;
}

int main() {
    std::vector<unsigned char> key = generateRandomBytes(32);  // AES-256 = 32 bytes
    int choice;

    while (true) {
        std::cout << "\nMenu:\n";
        std::cout << "1. Add Note\n2. View Note\n3. Exit\nChoose: ";
        std::cin >> choice;
        std::cin.ignore();  // Clear newline

        if (choice == 1) {
            std::string note;
            std::cout << "Enter your secret note:\n> ";
            std::getline(std::cin, note);

            std::vector<unsigned char> iv = generateRandomBytes(16);
            std::vector<unsigned char> ciphertext = encryptNote(note, key, iv);

            if (saveToFile(FILENAME, ciphertext, iv)) {
                std::cout << "✅ Note saved securely.\n";
            } else {
                std::cout << "❌ Failed to save note.\n";
            }

        } else if (choice == 2) {
            std::vector<unsigned char> ciphertext, iv;

            if (!loadFromFile(FILENAME, ciphertext, iv)) {
                std::cout << "❌ No note found.\n";
            } else {
                try {
                    std::string decrypted = decryptNote(ciphertext, key, iv);
                    std::cout << "🔓 Your secret note:\n" << decrypted << std::endl;
                } catch (...) {
                    std::cout << "❌ Decryption failed. Possibly incorrect key or corrupted data.\n";
                }
            }

        } else if (choice == 3) {
            std::cout << "👋 Exiting.\n";
            break;
        } else {
            std::cout << "⚠️ Invalid choice.\n";
        }
    }

    return 0;
}
