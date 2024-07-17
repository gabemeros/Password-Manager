//main file for password manager
//Gabe Meros



#include <iostream>
#include <string>
#include <cstring>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "functions.hpp"



// Constants
const char* DB_NAME = "merosDB.db";
const char* MASTER_KEY_FILE = "master_key.bin";
const int KEY_SIZE = 256 / 8;
const int SALT_SIZE = 16;
unsigned char encryptionKey[KEY_SIZE];

// Function prototypes
void displayMenu();
void addPassword();
void retrievePassword();

int main() {

    //seed random number gen for secure password
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Initialize SQLite database
    initializeDatabase();

    // Get master password from the user, in real world scenario, it would be more secure
    std::string masterPassword;
    std::cout << "Enter your master password: ";
    std::cin >> masterPassword;

    // Derive encryption key from master password
    unsigned char encryptionKey[KEY_SIZE];
    deriveKey(masterPassword, encryptionKey);

    // Display the main menu
    displayMenu();

    int choice;
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    while (choice != 0) {
        switch (choice) {
            case 1:
                addPassword();
                break;
            case 2:
                retrievePassword();
                break;

            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }

        displayMenu();
        std::cout << "Enter your choice (0 to exit): ";
        std::cin >> choice;
    }

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}


// Display the main menu
void displayMenu() {
    std::cout << "\n===== Password Manager Menu =====" << std::endl;
    std::cout << "1. Add a new password" << std::endl;
    std::cout << "2. Retrieve a password" << std::endl;
    std::cout << "0. Exit" << std::endl;
}

// Add a new password to the database
void addPassword() {
    std::string website, username, password, passChoice;

    std::cout << "\nEnter Website: ";
    std::cin >> website;

    std::cout << "Enter Username: ";
    std::cin >> username;

    std::cout << "Would you like to create a password or generate a random secure password? [C/G] ";
    std::cin >> passChoice;

if(passChoice == "C"){
    std::cout << "Enter Password: ";
    std::cin >> password;
}
else if (passChoice == "G"){
    std::cout << "Generating Password...";
    password = generatePassword();
    
}
    // Encrypt password
std::string encryptedPassword = encryptData(password, password.length(), encryptionKey);

    // Insert encrypted password into the database
    sqlite3* db;
    int rc = sqlite3_open(DB_NAME, &db);

    if (rc) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }

    const char* insertPasswordQuery = "INSERT INTO Passwords (Website, Username, EncryptedPassword) VALUES (?, ?, ?);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, insertPasswordQuery, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_bind_text(stmt, 1, website.c_str(), website.length(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), username.length(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, encryptedPassword.data(), encryptedPassword.length(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "Error inserting password: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    std::cout << "\nPassword successfully stored in the database." << std::endl;
}

// Retrieve a password from the database
void retrievePassword() {
    std::string website, username;

    std::cout << "\nEnter Website: ";
    std::cin >> website;

    std::cout << "Enter Username: ";
    std::cin >> username;

    // Retrieve encrypted password from the database
    sqlite3* db;
    int rc = sqlite3_open(DB_NAME, &db);

    if (rc) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }

    const char* retrievePasswordQuery = "SELECT EncryptedPassword FROM Passwords WHERE Website = ? AND Username = ?;";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, retrievePasswordQuery, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_bind_text(stmt, 1, website.c_str(), website.length(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), username.length(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        // Decrypt and display the retrieved password
        const unsigned char* encryptedPassword = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 0));
        int encryptedPasswordLength = sqlite3_column_bytes(stmt, 0);

        // Decrypt the password
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        unsigned char iv[EVP_MAX_IV_LENGTH];

        // Extract IV from the retrieved data
        std::memcpy(iv, encryptedPassword, EVP_MAX_IV_LENGTH);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, iv);

        std::string decryptedPassword;
        decryptedPassword.resize(encryptedPasswordLength - EVP_MAX_IV_LENGTH);

        int len;

        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decryptedPassword[0]), &len,
                          encryptedPassword + EVP_MAX_IV_LENGTH, encryptedPasswordLength - EVP_MAX_IV_LENGTH);

        decryptedPassword.resize(len);

        EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decryptedPassword[0] + len), &len);
        decryptedPassword += std::string(reinterpret_cast<char*>(&decryptedPassword[0]), len);

        EVP_CIPHER_CTX_free(ctx);

        std::cout << "\nRetrieved Password: " << decryptedPassword << std::endl;
    } else {
        std::cout << "\nPassword not found for the specified website and username." << std::endl;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
}
