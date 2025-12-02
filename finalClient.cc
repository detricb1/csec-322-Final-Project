// finalClient.cc

/*
 * client.c
 * SecureCollabNotes Client (Modular Version)
 *
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

// Global Socket Wrapper
Socket sock;
unsigned long long shared_key = 0;
int current_room_id = -1;

// Helper: Send Encrypted
void send_enc(Packet *p) {
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer(tmp.message, MSG_SIZE, shared_key);
    sock.send(&tmp, sizeof(Packet));
}

// Helper: Receive Encrypted (Blocking)
bool recv_enc(Packet *p) {
    int n = sock.recv(p, sizeof(Packet));
    if (n <= 0) return false;
    xor_buffer(p->message, MSG_SIZE, shared_key);
    return true;
}

void do_handshake() {
    unsigned long long priv = dh_generate_private();
    unsigned long long pub = dh_compute_public(priv);

    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_DH_PUB;
    sprintf(p.message, "%llu", pub);
    
    // Send public key (unencrypted)
    sock.send(&p, sizeof(Packet));

    // Wait for server response
    Packet resp;
    int n = sock.recv(&resp, sizeof(Packet));
    if (n <= 0) {
        printf("Server disconnected during handshake.\n");
        exit(1);
    }
    
    unsigned long long server_pub = strtoull(resp.message, NULL, 10);
    shared_key = dh_compute_shared(server_pub, priv);
    
    printf("[Client] Secure Connection Established. Key: %llu\n", shared_key);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    printf("[Client] Connecting to %s:%d...\n", ip, port);

    // Connect using provided IP and Port
    if (!sock.connect(ip, port)) {
        printf("Could not connect to %s:%d\n", ip, port);
        exit(1);
    }

    // Perform DH
    do_handshake();

    int choice;
    while(1) {
        printf("\n=== Secure Notes App ===\n");
        if (current_room_id != -1) printf("Current Room: %d\n", current_room_id);
        printf("1. Create Room\n");
        printf("2. Join Room\n");
        printf("3. Post Note\n");
        printf("4. List Notes\n");
        printf("5. Exit\n");
        printf("> ");
        scanf("%d", &choice);
        getchar(); // consume newline

        Packet req, resp;
        memset(&req, 0, sizeof(req));

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
            if (current_room_id == -1) {
                printf("You must join a room first.\n");
                continue;
            }
            printf("Enter Note: ");
            char buffer[MSG_SIZE];
            fgets(buffer, MSG_SIZE, stdin);
            buffer[strcspn(buffer, "\n")] = 0; // remove newline

            req.op = OP_POST_NOTE;
            req.room_id = current_room_id;
            strncpy(req.message, buffer, MSG_SIZE);
            send_enc(&req);
            printf("Note sent.\n");
        }
        else if (choice == 4) {
            if (current_room_id == -1) {
                printf("You must join a room first.\n");
                continue;
            }
            req.op = OP_LIST_NOTES;
            req.room_id = current_room_id;
            send_enc(&req);

            printf("\n--- Room Notes ---\n");
            while(1) {
                if (!recv_enc(&resp)) break;
                if (resp.tag == 0) break; // End of list
                printf("[%d] %s\n", resp.tag, resp.message);
            }
            printf("------------------\n");
        }
        else if (choice == 5) {
            break;
        }
    }
    
    sock.close();
    return 0;
}
