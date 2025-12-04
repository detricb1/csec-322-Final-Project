/* finalClient.cc
 *
 * SecureCollabNotes Client
 * Refactored to match relay client structure.
 *
 * Usage: finalClient <ip> <port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>

#include "socket.h"
#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"

// --- Global Variables ---

Socket clientSocket;
unsigned long long shared_key = 0;
int current_room_id = -1;

// --- Function Prototypes ---

char *getServerInfo(int argc, char *argv[], int *port);
void connectToServer(char *server, int port);
void doHandshake();
void processMessages(); // Main application loop
void closeConnection();

// Helpers
void send_enc(Packet *p);
bool recv_enc(Packet *p);


// --- Main Function ---

int main(int argc, char *argv[]) {
    char *serverIP;
    int port;

    // 1. Get Info
    serverIP = getServerInfo(argc, argv, &port);

    // 2. Connect
    connectToServer(serverIP, port);

    // 3. Security Handshake
    doHandshake();

    // 4. Run App
    processMessages();

    // 5. Cleanup
    closeConnection();

    return 0;
}


// --- Core Functions ---

char *getServerInfo(int argc, char *argv[], int *port) {
    if (argc < 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }
    *port = atoi(argv[2]);
    return argv[1];
}

void connectToServer(char *server, int port) {
    printf("[Client] Connecting to %s:%d...\n", server, port);
    if (!clientSocket.connect(server, port)) {
        printf("Error: Could not connect to server.\n");
        exit(1);
    }
}

void doHandshake() {
    unsigned long long priv = dh_generate_private();
    unsigned long long pub = dh_compute_public(priv);

    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_DH_PUB;
    sprintf(p.message, "%llu", pub);
    
    // Send public key
    clientSocket.send(&p, sizeof(Packet));

    // Wait for response
    Packet resp;
    int n = clientSocket.recv(&resp, sizeof(Packet));
    
    if (n > 0) {
        unsigned long long server_pub = strtoull(resp.message, NULL, 10);
        shared_key = dh_compute_shared(server_pub, priv);
        printf("[Client] Secure Connection Established.\n");
    } else {
        printf("[Client] Handshake Failed.\n");
        exit(1);
    }
}

void processMessages() {
    bool running = true;
    while (running) {
        printf("\n=== Secure Notes Menu ===\n");
        if (current_room_id != -1) printf("Room: %d\n", current_room_id);
        printf("1. Create Room\n");
        printf("2. Join Room\n");
        printf("3. Post Note\n");
        printf("4. List Notes\n");
        printf("5. Exit\n");
        printf("> ");
        
        int choice;
        // Basic input check
        if (scanf("%d", &choice) != 1) {
            // clear invalid input
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        getchar(); // consume newline

        Packet req, resp;
        memset(&req, 0, sizeof(req));

        // IF/ELSE chain (No break statements used for logic flow)
        if (choice == 1) {
            req.op = OP_CREATE_ROOM;
            send_enc(&req);
            
            if (recv_enc(&resp)) {
                if (resp.op == OP_CREATE_ROOM_RESP) {
                    current_room_id = resp.room_id;
                    printf("Success! Room ID: %d, Invite Code: %d\n", resp.room_id, resp.tag);
                }
            }
        }
        else if (choice == 2) {
            printf("Enter Invite Code: ");
            int code;
            scanf("%d", &code);
            
            req.op = OP_JOIN_ROOM;
            req.tag = code;
            send_enc(&req);
            
            if (recv_enc(&resp)) {
                if (resp.op == OP_JOIN_ROOM_RESP) {
                    current_room_id = resp.room_id;
                    printf("Joined Room %d successfully.\n", resp.room_id);
                } else {
                    printf("Error: %s\n", resp.message);
                }
            }
        }
        else if (choice == 3) {
            if (current_room_id != -1) {
                printf("Enter Note: ");
                char buffer[MSG_SIZE];
                fgets(buffer, MSG_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0; 

                req.op = OP_POST_NOTE;
                req.room_id = current_room_id;
                strncpy(req.message, buffer, MSG_SIZE);
                send_enc(&req);
                printf("Note sent.\n");
            } else {
                printf("Join a room first.\n");
            }
        }
        else if (choice == 4) {
            if (current_room_id != -1) {
                req.op = OP_LIST_NOTES;
                req.room_id = current_room_id;
                send_enc(&req);

                printf("\n--- Room Notes ---\n");
                bool reading = true;
                while (reading) {
                    if (!recv_enc(&resp)) {
                        reading = false;
                    } else if (resp.tag == 0) {
                        reading = false; // End marker
                    } else {
                        printf("[%d] %s\n", resp.tag, resp.message);
                    }
                }
                printf("------------------\n");
            } else {
                printf("Join a room first.\n");
            }
        }
        else if (choice == 5) {
            running = false;
        }
    }
}

void closeConnection() {
    clientSocket.close();
    printf("Connection closed.\n");
}

// --- Helper Functions ---

void send_enc(Packet *p) {
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer(tmp.message, MSG_SIZE, shared_key);
    clientSocket.send(&tmp, sizeof(Packet));
}

bool recv_enc(Packet *p) {
    int n = clientSocket.recv(p, sizeof(Packet));
    if (n <= 0) return false;
    xor_buffer(p->message, MSG_SIZE, shared_key);
    return true;
}
