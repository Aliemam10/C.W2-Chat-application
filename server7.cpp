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

void saveChatLogs(const string& chatLogs) {

    ofstream file("encrypted_chat_logs.txt", ofstream::app); // Open the file in append mode

    if (file.is_open()) {

        file << chatLogs << endl; // Write chatLogs followed by newline

        file.close(); // Close the file

    } else {

        cerr << "Error opening file for saving chat logs." << endl;

    }

}



int main() {

    // Load previous chat logs or create a new file if it doesn't exist

    string chatLogs;



    // Create a socket

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd == -1) {

        perror("Socket creation failed");

        exit(EXIT_FAILURE);

    }



    // Prepare the address structure

    struct sockaddr_in address;

    address.sin_family = AF_INET;

    address.sin_addr.s_addr = INADDR_ANY;

    address.sin_port = htons(8080); // Example port



    // Bind the socket to the address and port

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {

        perror("Bind failed");

        exit(EXIT_FAILURE);

    }



    // Listen for incoming connections

    if (listen(server_fd, 3) < 0) {

        perror("Listen failed");

        exit(EXIT_FAILURE);

    }



    // Accept a connection

    int client_fd = accept(server_fd, nullptr, nullptr);

    if (client_fd < 0) {

        perror("Accept failed");

        exit(EXIT_FAILURE);

    }



    // Authentication

    bool authenticated = false;

    while (!authenticated) {

        char username[100];

        char password[100];



        // Receive username from client

        int bytes_received = recv(client_fd, username, sizeof(username) - 1, 0);

        if (bytes_received < 0) {

            perror("Error receiving username from client");

            exit(EXIT_FAILURE);

        }

        username[bytes_received] = '\0'; // Null-terminate the received string



        // Receive password from client

        bytes_received = recv(client_fd, password, sizeof(password) - 1, 0);

        if (bytes_received < 0) {

            perror("Error receiving password from client");

            exit(EXIT_FAILURE);

        }

        password[bytes_received] = '\0'; // Null-terminate the received string



        // Check username and password

        if (strcmp(username, "user") == 0 && strcmp(password, "password") == 0) {

            const char *auth_success = "success\n";

            send(client_fd, auth_success, strlen(auth_success), 0);

            authenticated = true;

            cout << "Authentication successful!" << endl;

        } else {

            const char *auth_failure = "failure\n";

            send(client_fd, auth_failure, strlen(auth_failure), 0);

            cout << "Authentication failed. Username or password incorrect." << endl;

        }

    }



    // Handle client communication

    char buffer[1024];

    bool serverRunning = true;



    while (serverRunning) {

        // Clear the buffer

        memset(buffer, 0, sizeof(buffer));



        // Receive message from client

        int bytes_read = read(client_fd, buffer, sizeof(buffer));

        if (bytes_read < 0) {

            perror("Error reading from client");

        } else if (bytes_read == 0) {

            cout << "Client disconnected" << endl;

            serverRunning = false;

        } else {

            if (strcmp(buffer, "quit\n") == 0) {

                serverRunning = false;

            } else {

                // Display message from client

                cout << "Client: " << buffer;



                // Decrypt the received message

                string decryptedMessage = decryptAES(string(buffer, bytes_read));



                // Save encrypted message to file

                saveChatLogs(string(buffer, bytes_read));



                // Display decrypted message

                cout << "Client (Decrypted): " << decryptedMessage;



                // Send response back to client (optional)

                cout << "Server: ";

                string message;

                getline(cin, message);

                message += "\n"; // Add newline for the client



                // Encrypt the response before sending

                string encryptedResponse = encryptAES(message);

                send(client_fd, encryptedResponse.c_str(), encryptedResponse.size(), 0);



                // Save encrypted response to file

                saveChatLogs(encryptedResponse);

            }

        }

    }

    // Clean up
    close(client_fd);
    close(server_fd);
  
    return 0;
}

