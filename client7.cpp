#include <iostream>

#include <cstdlib>

#include <unistd.h>

#include <string.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <fstream>

#include <openssl/aes.h>

#include <openssl/rand.h>



using namespace std;



#define _OPENSSL_API_COMPAT 30000



// AES encryption key and initialization vector (IV)

unsigned char aes_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};

unsigned char iv[AES_BLOCK_SIZE];



// Function to encrypt data using AES

string encryptAES(const string& plainText) {

    AES_KEY enc_key;

    AES_set_encrypt_key(aes_key, 128, &enc_key);

    string cipherText;



    int len = plainText.length();

    int padding = 0;

    if (len % AES_BLOCK_SIZE != 0) {

        padding = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);

    }



    // Pad the plaintext to make it a multiple of AES_BLOCK_SIZE

    string paddedText = plainText + string(padding, ' ');



    // Encrypt each block

    for (int i = 0; i < paddedText.length(); i += AES_BLOCK_SIZE) {

        unsigned char out[AES_BLOCK_SIZE];

        AES_encrypt(reinterpret_cast<const unsigned char*>(paddedText.c_str() + i), out, &enc_key);

        cipherText.append(reinterpret_cast<char*>(out), AES_BLOCK_SIZE);

    }



    return cipherText;

}



// Function to decrypt data using AES

string decryptAES(const string& cipherText) {

    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, 128, &dec_key);

    string plainText;



    // Decrypt each block

    for (int i = 0; i < cipherText.length(); i += AES_BLOCK_SIZE) {

        unsigned char out[AES_BLOCK_SIZE];

        AES_decrypt(reinterpret_cast<const unsigned char*>(cipherText.c_str() + i), out, &dec_key);

        plainText.append(reinterpret_cast<char*>(out), AES_BLOCK_SIZE);

    }



    // Remove padding

    size_t pos = plainText.find_last_not_of(' ');

    if (pos != string::npos) {

        plainText.erase(pos + 1);

    }



    return plainText;

}



// Function to save chat logs to a file

void saveChatLog(const string& message, const string& filename) {

    ofstream file(filename, ofstream::app); // Open the file in append mode

    if (file.is_open()) {

        file << message << endl; // Write message followed by newline

        file.close(); // Close the file

    } else {

        cerr << "Error opening file for saving chat logs." << endl;

    }

}



int main() {

    // Create a socket

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_fd == -1) {

        perror("Socket creation failed");

        exit(EXIT_FAILURE);

    }



    // Server details

    struct sockaddr_in address;

    address.sin_family = AF_INET;

    address.sin_port = htons(8080); // Example port

    address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Example address



    // Connect to the server

    if (connect(client_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {

        perror("Connect failed");

        exit(EXIT_FAILURE);

    }



    cout << "Connected to server." << endl;



    // Authentication

    bool authenticated = false;

    while (!authenticated) {

        cout << "Username: ";

        string username;

        getline(cin, username);

        send(client_fd, username.c_str(), username.size(), 0);



        cout << "Password: ";

        string password;

        getline(cin, password);

        send(client_fd, password.c_str(), password.size(), 0);



        // Wait for server's authentication response

        char auth_response[100];

        memset(auth_response, 0, sizeof(auth_response)); // Clear buffer

        read(client_fd, auth_response, sizeof(auth_response) - 1); // Ensure null-terminated



        if (strcmp(auth_response, "success\n") == 0) {

            cout << "Authentication successful!" << endl;

            authenticated = true;

        } else {

            cout << "Authentication failed. Please try again." << endl;

        }

    }



    // Communication with the server (only starts after successful authentication)

    char buffer[1024];

    bool clientRunning = true;



    while (clientRunning) {

        // Get input from the user

        cout << "Client: ";

        string message;

        getline(cin, message);

        message += "\n"; // Add newline for the server



        // Encrypt the message before sending

        string encryptedMessage = encryptAES(message);

        send(client_fd, encryptedMessage.c_str(), encryptedMessage.size(), 0);



        if (message == "quit\n") {

            clientRunning = false;

        }



        // Receive the server's response

        int bytes_read = read(client_fd, buffer, sizeof(buffer));

        if (bytes_read < 0) {

            perror("Error reading from server");

        } else if (bytes_read == 0) {

            cout << "Server disconnected" << endl;

            clientRunning = false;

        } else {

            // Decrypt the received message

            string decryptedMessage = decryptAES(string(buffer, bytes_read));



            // Display decrypted message

            cout << "Server: " << decryptedMessage;



            // Save encrypted message to file

            saveChatLog(string(buffer, bytes_read), "encrypted_chat_logs_client.txt");

        }

    }



    // Close the socket

    close(client_fd);



    return 0;

}

