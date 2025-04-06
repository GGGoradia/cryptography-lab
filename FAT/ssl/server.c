#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>  // For Sleep function

#pragma comment(lib, "ws2_32.lib")  // Link with the Winsock library

#define PORT 8080
#define MAX_BUFFER 1024

// RSA public/private key components (small values for demo)
unsigned long e = 5, d = 29, n = 91;  // Public (e, n) | Private (d, n)

// RSA Encryption: C = M^e mod n
unsigned long rsa_encrypt(unsigned long message, unsigned long exp, unsigned long mod) {
    unsigned long result = 1;
    for (unsigned long i = 0; i < exp; i++) {
        result = (result * message) % mod;
    }
    return result;
}

// XOR Encryption using Session Key
void xor_encrypt_decrypt(char* data, unsigned long session_key) {
    for (int i = 0; i < strlen(data); i++) {
        data[i] = data[i] ^ (session_key & 0xFF);
    }
}

int main() {
    WSADATA wsaData;
    SOCKET server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[MAX_BUFFER] = {0};

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        printf("Socket failed\n");
        WSACleanup();
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Listen
    if (listen(server_fd, 3) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept connection
    new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (new_socket == INVALID_SOCKET) {
        printf("Accept failed\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Step 1: Receive "Client Hello"
    recv(new_socket, buffer, sizeof(buffer), 0);
    printf("Received: %s\n", buffer);

    // Step 2: Send "Server Hello"
    send(new_socket, "Server Hello", strlen("Server Hello") + 1, 0);

    // Step 3: Send RSA Public Key
    unsigned long public_key[2] = {e, n};
    send(new_socket, (char*)public_key, sizeof(public_key), 0);
    printf("Sent RSA public key (e=%lu, n=%lu) to client.\n", e, n);

    // Step 4: Receive Encrypted Session Key
    unsigned long encrypted_session_key;
    recv(new_socket, (char*)&encrypted_session_key, sizeof(encrypted_session_key), 0);
    printf("Received Encrypted Session Key: %lu\n", encrypted_session_key);

    // Step 5: Decrypt Session Key
    unsigned long session_key = rsa_encrypt(encrypted_session_key, d, n);
    printf("Decrypted Session Key: %lu\n", session_key);

    // Step 6: Send "Handshake Finished"
    send(new_socket, "Handshake Finished", strlen("Handshake Finished") + 1, 0);

    // Step 7: Secure Message Exchange
    char server_message[MAX_BUFFER];
    printf("Enter you message: ");
    fgets(server_message,MAX_BUFFER,stdin);
    size_t len = strlen(server_message);
    if(len>0&&server_message[len-1]=='\n')
    {
        server_message[len-1]='\0';
    }
    xor_encrypt_decrypt(server_message, session_key);
    send(new_socket, server_message, strlen(server_message) + 1, 0);

    // Step 8: Receive encrypted message from client
    char client_message[MAX_BUFFER];
    recv(new_socket, client_message, sizeof(client_message), 0);
    xor_encrypt_decrypt(client_message, session_key);
    printf("Received from client: %s\n", client_message);

    // Close connection
    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();  // Clean up Winsock

    return 0;
}