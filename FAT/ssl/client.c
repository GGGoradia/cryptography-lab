#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>  // For Sleep function

#pragma comment(lib, "ws2_32.lib")  // Link with the Winsock library

#define PORT 8080
#define SERVER_IP "127.0.0.1"
#define MAX_BUFFER 1024

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
    SOCKET sock;
    struct sockaddr_in serv_addr;
    char buffer[MAX_BUFFER] = {0};
    unsigned long public_key[2];  // To store received (e, n)

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket failed\n");
        WSACleanup();
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);


    // Connect to server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Step 1: Send "Client Hello"
    send(sock, "Client Hello", strlen("Client Hello") + 1, 0);

    // Step 2: Receive "Server Hello"
    recv(sock, buffer, sizeof(buffer), 0);
    printf("Received: %s\n", buffer);

    // Step 3: Receive RSA Public Key
    recv(sock, (char*)public_key, sizeof(public_key), 0);
    printf("Received RSA Public Key (e=%lu, n=%lu)\n", public_key[0], public_key[1]);

    // Step 4: Generate Random Session Key
    unsigned long session_key = rand() % 50 + 1;
    printf("Generated Session Key: %lu\n", session_key);

    // Step 5: Encrypt Session Key using RSA
    unsigned long encrypted_session_key = rsa_encrypt(session_key, public_key[0], public_key[1]);
    printf("Encrypted Session Key: %lu\n", encrypted_session_key);

    // Send Encrypted Session Key to Server
    send(sock, (char*)&encrypted_session_key, sizeof(encrypted_session_key), 0);

    // Step 6: Receive "Handshake Finished"
    recv(sock, buffer, sizeof(buffer), 0);
    printf("Received: %s\n", buffer);

    // Step 7: Receive Encrypted Message from Server
    char server_message[MAX_BUFFER];
    recv(sock, server_message, sizeof(server_message), 0);
    xor_encrypt_decrypt(server_message, session_key);
    printf("Received from server: %s\n", server_message);

    // Step 8: Send an Encrypted Message to Server
    char client_message[MAX_BUFFER];
    printf("Enter you message: ");
    fgets(client_message,MAX_BUFFER,stdin);
    size_t len = strlen(client_message);
    if(len>0&&client_message[len-1]=='\n')
    {
        client_message[len-1]='\0';
    }
    xor_encrypt_decrypt(client_message, session_key);
    send(sock, client_message, strlen(client_message) + 1, 0);

    // Close connection
    closesocket(sock);
    WSACleanup();  // Clean up Winsock

    return 0;
}