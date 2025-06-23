#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

void handleErrors() {
    std::cerr << "An error occurred." << std::endl;
    exit(EXIT_FAILURE);
}

void encrypt_decrypt(const unsigned char* input, int input_len,
                     const unsigned char* key, const unsigned char* iv,
                     unsigned char* output, int& output_len, bool encrypt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    } else {
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    }

    int len;
    int total_len = 0;

    if (encrypt) {
        EVP_EncryptUpdate(ctx, output, &len, input, input_len);
    } else {
        EVP_DecryptUpdate(ctx, output, &len, input, input_len);
    }
    total_len += len;

    if (encrypt) {
        EVP_EncryptFinal_ex(ctx, output + len, &len);
    } else {
        EVP_DecryptFinal_ex(ctx, output + len, &len);
    }
    total_len += len;

    output_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    std::string inputText;
    std::cout << "Enter the text to encrypt: ";
    std::getline(std::cin, inputText);

    unsigned char key[32];  // AES-256 = 256-bit = 32 bytes
    unsigned char iv[16];   // 16 bytes IV for CBC

    // Generate random key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    unsigned char ciphertext[256];
    int ciphertext_len;

    // Encrypt user input
    encrypt_decrypt((unsigned char*)inputText.c_str(), inputText.length(), key, iv, ciphertext, ciphertext_len, true);

    std::cout << "\nEncrypted (hex): ";
    for (int i = 0; i < ciphertext_len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
    }
    std::cout << std::endl;

    unsigned char decryptedtext[256];
    int decryptedtext_len;

    // Decrypt the ciphertext
    encrypt_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext, decryptedtext_len, false);
    decryptedtext[decryptedtext_len] = '\0';

    std::cout << "Decrypted text: " << decryptedtext << std::endl;

    return 0;
}
