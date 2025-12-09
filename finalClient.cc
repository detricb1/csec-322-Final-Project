/* finalClient.cc
 *
 * SecureCollabNotes Client
 *
 * This program is the client for a secure collaborative notes application.
 * Users can create rooms, join existing rooms with invite codes, post notes,
 * and view all notes in a room. All communication is encrypted using
 * Diffie-Hellman key exchange.
 *
 * Usage: finalClient <server-addr> <port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socket.h"
#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"

/* Function prototypes for top-down design */
char *getServerInfo(int argc, char *argv[], int *port);
void connectToServer(char *server, int port);
void doHandshake();
void processMessages();
void closeConnection();

/* Helper functions */
void sendEncrypted(Packet *p);
bool recvEncrypted(Packet *p);

/* Global variables */
Socket clientSocket;
unsigned long long sharedKey = 0;
int currentRoomId = -1;


int main(int argc, char *argv[])
{
    char *server;
    int port;

    /* Get the server address and port number from the command-line */
    server = getServerInfo(argc, argv, &port);

    /* Connect the client to the server */
    connectToServer(server, port);

    /* Perform Diffie-Hellman key exchange */
    doHandshake();

    /* Process user input and server messages */
    processMessages();

    /* Close the connection to the server and shutdown */
    closeConnection();

    return 0;
}


void connectToServer(char *server, int port)
{
    bool connected = clientSocket.connect(server, port);
    
    if (connected) {
        printf("Connected to the server.\n");
    } else {
        printf("Error: Could not connect to server.\n");
        exit(1);
    }
}


void doHandshake()
{
    /* Generate private and public keys */
    unsigned long long priv = dh_generate_private();
    unsigned long long pub = dh_compute_public(priv);

    /* Send public key to server */
    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_DH_PUB;
    sprintf(p.message, "%llu", pub);
    clientSocket.send(&p, sizeof(Packet));

    /* Receive server's public key */
    Packet resp;
    int n = clientSocket.recv(&resp, sizeof(Packet));

    if (n > 0) {
        unsigned long long server_pub = strtoull(resp.message, NULL, 10);
        sharedKey = dh_compute_shared(server_pub, priv);
        printf("Secure connection established.\n");
    } else {
        printf("Error: Handshake failed.\n");
        exit(1);
    }
}


void processMessages()
{
    bool running = true;
    
    printf("\nWelcome to SecureCollabNotes!\n");

    while (running) {
        printf("\n=== Secure Notes Menu ===\n");
        if (currentRoomId != -1) {
            printf("Current Room: %d\n", currentRoomId);
        }
        printf("1. Create Room\n");
        printf("2. Join Room\n");
        printf("3. Post Note\n");
        printf("4. List Notes\n");
        printf("5. Exit\n");
        printf("> ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            /* Clear invalid input */
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        getchar(); /* Consume newline */

        Packet req, resp;
        memset(&req, 0, sizeof(req));

        /* Handle create room */
        if (choice == 1) {
            req.op = OP_CREATE_ROOM;
            sendEncrypted(&req);

            if (recvEncrypted(&resp)) {
                if (resp.op == OP_CREATE_ROOM_RESP) {
                    currentRoomId = resp.room_id;
                    printf("Success! Room ID: %d, Invite Code: %d\n", 
                           resp.room_id, resp.tag);
                }
            }
        }
        /* Handle join room */
        else if (choice == 2) {
            printf("Enter Invite Code: ");
            int code;
            if (scanf("%d", &code) != 1) {
                printf("Error: Invalid invite code.\n");
                getchar();
                continue;
            }
            getchar(); /* Consume newline */

            req.op = OP_JOIN_ROOM;
            req.tag = code;
            sendEncrypted(&req);

            if (recvEncrypted(&resp)) {
                if (resp.op == OP_JOIN_ROOM_RESP) {
                    currentRoomId = resp.room_id;
                    printf("Joined Room %d successfully.\n", resp.room_id);
                } else if (resp.op == OP_ERROR) {
                    printf("Error: %s\n", resp.message);
                }
            }
        }
        /* Handle post note */
        else if (choice == 3) {
            if (currentRoomId != -1) {
                printf("Enter Note: ");
                char buffer[MSG_SIZE];
                fgets(buffer, MSG_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0; /* Remove newline */

                req.op = OP_POST_NOTE;
                req.room_id = currentRoomId;
                strncpy(req.message, buffer, MSG_SIZE - 1);
                sendEncrypted(&req);
                printf("Note posted.\n");
            } else {
                printf("Error: Join a room first.\n");
            }
        }
        /* Handle list notes */
        else if (choice == 4) {
            if (currentRoomId != -1) {
                req.op = OP_LIST_NOTES;
                req.room_id = currentRoomId;
                sendEncrypted(&req);

                printf("\n--- Room Notes ---\n");
                bool reading = true;
                while (reading) {
                    if (!recvEncrypted(&resp)) {
                        reading = false;
                    } else if (resp.tag == 0) {
                        reading = false; /* End marker */
                    } else {
                        printf("[%d] %s\n", resp.tag, resp.message);
                    }
                }
                printf("------------------\n");
            } else {
                printf("Error: Join a room first.\n");
            }
        }
        /* Handle exit */
        else if (choice == 5) {
            running = false;
        }
        /* Handle invalid choice */
        else {
            printf("Invalid choice. Please try again.\n");
        }
    }
}


void closeConnection()
{
    clientSocket.close();
    printf("Connection closed.\n");
}


char *getServerInfo(int argc, char *argv[], int *port)
{
    if (argc < 3) {
        fprintf(stderr, "Error: Invalid number of arguments.\n");
        fprintf(stderr, "usage: finalClient <server-addr> <port>\n");
        exit(1);
    } else {
        *port = atoi(argv[2]);
        return argv[1]; /* The server address */
    }
}


/* --- Helper Functions --- */

void sendEncrypted(Packet *p)
{
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer(tmp.message, MSG_SIZE, sharedKey);
    clientSocket.send(&tmp, sizeof(Packet));
}


bool recvEncrypted(Packet *p)
{
    int n = clientSocket.recv(p, sizeof(Packet));
    if (n <= 0) {
        return false;
    }
    xor_buffer(p->message, MSG_SIZE, sharedKey);
    return true;
}
