// implementation of functions.hpp
//Gabe Meros


#include "functions.hpp"
#include <iostream>
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>

void initializeDatabase() {
    // Database initialization code
    std::cout << "Initializing database..." << std::endl;

    sqlite3* db;
    int rc = sqlite3_open("/home/gabemeros/PasswordManager/merosDB.db", &db);

    if (rc) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }

    // SQL command to create the "Passwords" table
    const char* createTableQuery = "CREATE TABLE IF NOT EXISTS Passwords ("
                                  "    ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                                  "    Website TEXT NOT NULL,"
                                  "    Username TEXT NOT NULL,"
                                  "    EncryptedPassword BLOB NOT NULL"
                                  ");";

    // Execute the SQL command
    rc = sqlite3_exec(db, createTableQuery, NULL, NULL, NULL);

    if (rc != SQLITE_OK) {
        std::cerr << "Error creating table: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    std::cout << "Database initialization complete." << std::endl;

    // close database connection when finished
    sqlite3_close(db);
}

void deriveKey(const std::string& masterPassword, unsigned char* key) {
    // Implementation for key derivation using PBKDF2

    const char* salt = "your_salt";  // Replace with a secure random salt

    // Use a suitable iteration count and key length
    const int iterationCount = 10000;
    const int keyLength = 256 / 8;

    PKCS5_PBKDF2_HMAC_SHA1(
        masterPassword.c_str(), masterPassword.length(),
        reinterpret_cast<const unsigned char*>(salt), strlen(salt),
        iterationCount, keyLength, key);
}

std::string encryptData(const std::string& data, int datalength, const unsigned char* key) {
    // Implementation for encrypting data using AES
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

     // retreving data length
    int ciphertextLength = datalength + EVP_CIPHER_block_size(cipher);
    unsigned char* ciphertext = new unsigned char[ciphertextLength];

    // Generate a random IV (Initialization Vector)
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);


    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
    int ciphertextFinalLength;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &ciphertextFinalLength);

    //adding cyper and encrypted data to create encrypted password

    std::string encryptedData(reinterpret_cast<char*>(iv), EVP_CIPHER_iv_length(cipher));
    encryptedData += std::string(reinterpret_cast<char*>(ciphertext), len + ciphertextFinalLength);

    delete[] ciphertext;
    EVP_CIPHER_CTX_free(ctx);

    return encryptedData;
}


    std::string generatePassword() {
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()+=_-<>?";

    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_int_distribution<int> lengthDistribution(12,23); // random length of password

    int length = lengthDistribution(rng);
    std::uniform_int_distribution<std::string::size_type> distribution(0, characters.size() - 1);
    std::string password;
    password.reserve(length);

    for(int i=0; i < length; ++i){
        password.push_back(characters[distribution(rng)]);
    }
    return password;
    
    }
 