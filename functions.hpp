// header file with prototypes
//Gabe Meros


#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <string>
#include <ctime>
#include <cstdlib>
#include <random>


void initializeDatabase();
void deriveKey(const std::string& masterPassword, unsigned char* key);
std::string encryptData(const std::string& data, int datalength, const unsigned char* key);
std::string generatePassword();



#endif