/* finalServer.cc
 *
 * SecureCollabNotes Server
 * 
 * This program is the server for a secure collaborative notes application.
 * It allows clients to create rooms, join rooms with invite codes, and
 * share encrypted notes within those rooms. All communication uses
 * Diffie-Hellman key exchange for security.
 *
 * Usage: finalServer [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"
#include "socket.h"
#include "selector.h"

/* Default port number for the server's listening socket */
const int DEFAULT_PORT = 30000;

/* Maximum number of concurrent client connections */
const int MAX_CLIENTS = 1024;

/* Data structure for storing notes in a room */
struct Note {
    int id;
    char ciphertext[MSG_SIZE];
    Note *next;
};

/* Data structure for storing room information */
struct Room {
    int id;
    int invite_code;
    unsigned long long room_key;
    Note *notes;
    int note_count;
    Room *next;
};

/* Data structure for tracking client connection state */
struct ClientContext {
    Socket *sock;
    unsigned long long shared_key;
    bool dh_completed;
    int current_room_id;
};

/* Function prototypes for top-down design */
void sigHandler(int sig);
int getPortNumber(int argc, char *argv[]);
void initServerSocket(int portNum);
void initSelector();
void processRequests();
void handleClientConnection();
void handleClientRequest(int fd);
void disconnectClient(int fd);

/* Helper functions for room and note management */
Room* createRoom();
Room* findRoomById(int id);
Room* findRoomByInvite(int code);
void addNote(Room *r, const char *content);
bool sendPacketEncrypted(Socket *sock, Packet *p, unsigned long long key);

/* Global variables */
ServerSocket theServer;
InputSelector inputSet;
ClientContext *clientList[MAX_CLIENTS];
Room *roomListHead = NULL;
int nextRoomId = 1;


int main(int argc, char *argv[])
{
    /* Set the Ctrl-C signal handler */
    signal(SIGINT, sigHandler);
    
    /* Seed random number generator for room invite codes */
    srand(time(NULL));
    
    /* Initialize client list */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clientList[i] = NULL;
    }

    /* Get the port number to use for the listening socket */
    int portNum = getPortNumber(argc, argv);

    /* Initialize the listening socket */
    initServerSocket(portNum);

    /* Initialize the input selector */
    initSelector();

    /* Process protocol requests */
    processRequests();

    return 0;
}


void processRequests()
{
    int *activeSet;

    while (true) {
        activeSet = inputSet.select();

        int i = 0;
        while (activeSet[i] >= 0) {
            int fd = activeSet[i];

            if (fd == theServer.fd()) {
                handleClientConnection();
            } else {
                handleClientRequest(fd);
            }
            i++;
        }
    }
}


void handleClientConnection()
{
    /* Accept the new connection */
    Socket *theClient = theServer.accept();
    
    if (theClient == NULL) {
        return;
    }

    int clientFd = theClient->fd();

    /* Validate file descriptor */
    if (clientFd >= MAX_CLIENTS || clientFd < 0) {
        printf("Connection rejected (invalid fd or max clients reached)\n");
        theClient->close();
        delete theClient;
        return;
    }

    /* Add to input selector */
    inputSet.add(clientFd);

    /* Create and initialize client context */
    ClientContext *ctx = new ClientContext();
    ctx->sock = theClient;
    ctx->dh_completed = false;
    ctx->shared_key = 0;
    ctx->current_room_id = -1;

    clientList[clientFd] = ctx;
    printf("New client connected (fd: %d)\n", clientFd);
}


void handleClientRequest(int fd)
{
    ClientContext *ctx = clientList[fd];

    if (ctx == NULL) {
        return;
    }

    Packet req;
    int n = ctx->sock->recv(&req, sizeof(Packet));

    if (n <= 0) {
        disconnectClient(fd);
        return;
    }

    /* Handle Diffie-Hellman handshake */
    if (req.op == OP_DH_PUB) {
        unsigned long long client_pub = strtoull(req.message, NULL, 10);
        unsigned long long my_priv = dh_generate_private();
        unsigned long long my_pub = dh_compute_public(my_priv);
        ctx->shared_key = dh_compute_shared(client_pub, my_priv);
        ctx->dh_completed = true;

        Packet resp;
        memset(&resp, 0, sizeof(resp));
        resp.op = OP_DH_PUB;
        sprintf(resp.message, "%llu", my_pub);

        ctx->sock->send(&resp, sizeof(Packet));
        printf("Handshake complete (fd: %d)\n", fd);
        return;
    }

    /* Ensure client has completed handshake before processing encrypted requests */
    if (!ctx->dh_completed) {
        printf("Client not authenticated (fd: %d)\n", fd);
        return;
    }

    /* Decrypt incoming message */
    xor_buffer(req.message, MSG_SIZE, ctx->shared_key);

    Packet resp;
    memset(&resp, 0, sizeof(resp));

    /* Handle create room request */
    if (req.op == OP_CREATE_ROOM) {
        Room *r = createRoom();
        ctx->current_room_id = r->id;
        resp.op = OP_CREATE_ROOM_RESP;
        resp.room_id = r->id;
        resp.tag = r->invite_code;
        snprintf(resp.message, MSG_SIZE, "Room Created");
        sendPacketEncrypted(ctx->sock, &resp, ctx->shared_key);
        printf("Room %d created (invite: %d)\n", r->id, r->invite_code);
    }
    /* Handle join room request */
    else if (req.op == OP_JOIN_ROOM) {
        Room *r = findRoomByInvite(req.tag);
        if (r != NULL) {
            ctx->current_room_id = r->id;
            resp.op = OP_JOIN_ROOM_RESP;
            resp.room_id = r->id;
            snprintf(resp.message, MSG_SIZE, "Joined Room");
        } else {
            resp.op = OP_ERROR;
            snprintf(resp.message, MSG_SIZE, "Invalid Code");
        }
        sendPacketEncrypted(ctx->sock, &resp, ctx->shared_key);
    }
    /* Handle post note request */
    else if (req.op == OP_POST_NOTE) {
        Room *r = findRoomById(ctx->current_room_id);
        if (r != NULL) {
            addNote(r, req.message);
            printf("Note posted to Room %d\n", r->id);
        }
    }
    /* Handle list notes request */
    else if (req.op == OP_LIST_NOTES) {
        Room *r = findRoomById(ctx->current_room_id);
        if (r != NULL) {
            Note *cur = r->notes;
            while (cur != NULL) {
                Packet noteP;
                memset(&noteP, 0, sizeof(noteP));
                noteP.op = OP_LIST_NOTES_RESP;
                noteP.tag = cur->id;
                memcpy(noteP.message, cur->ciphertext, MSG_SIZE);
                sendPacketEncrypted(ctx->sock, &noteP, ctx->shared_key);
                cur = cur->next;
            }
        }
        /* Send end marker */
        Packet endP;
        memset(&endP, 0, sizeof(endP));
        endP.op = OP_LIST_NOTES_RESP;
        endP.tag = 0;
        sendPacketEncrypted(ctx->sock, &endP, ctx->shared_key);
    }
}


void disconnectClient(int fd)
{
    printf("Client disconnected (fd: %d)\n", fd);
    inputSet.remove(fd);

    if (clientList[fd] != NULL) {
        clientList[fd]->sock->close();
        delete clientList[fd]->sock;
        delete clientList[fd];
        clientList[fd] = NULL;
    }
}


void initSelector()
{
    inputSet.add(theServer.fd());
}


void initServerSocket(int portNum)
{
    bool bound = theServer.bind(portNum);
    if (bound) {
        printf("Server bound to port #%d\n", portNum);
    } else {
        printf("Error: the socket could not be bound to port #%d\n", portNum);
        exit(1);
    }
}


int getPortNumber(int argc, char *argv[])
{
    if (argc > 1) {
        return atoi(argv[1]);
    } else {
        return DEFAULT_PORT;
    }
}


void sigHandler(int sig)
{
    printf("Shutting down the server.\n");
    theServer.close();
    exit(0);
}


/* --- Helper Functions --- */

bool sendPacketEncrypted(Socket *sock, Packet *p, unsigned long long key)
{
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer(tmp.message, MSG_SIZE, key);
    int n = sock->send(&tmp, sizeof(Packet));
    return n == sizeof(Packet);
}


Room* createRoom()
{
    Room *r = new Room();
    r->id = nextRoomId++;
    r->invite_code = rand() % 9000 + 1000;
    r->room_key = ((unsigned long long)rand() << 32) | rand();
    r->notes = NULL;
    r->note_count = 0;
    r->next = roomListHead;
    roomListHead = r;
    return r;
}


Room* findRoomById(int id)
{
    Room *cur = roomListHead;
    while (cur != NULL) {
        if (cur->id == id) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}


Room* findRoomByInvite(int code)
{
    Room *cur = roomListHead;
    while (cur != NULL) {
        if (cur->invite_code == code) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}


void addNote(Room *r, const char *content)
{
    Note *n = new Note();
    n->id = ++(r->note_count);
    memcpy(n->ciphertext, content, MSG_SIZE);
    n->next = r->notes;
    r->notes = n;
}
