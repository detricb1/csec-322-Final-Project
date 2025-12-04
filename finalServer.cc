/* finalServer.cc
 *
 * SecureCollabNotes Server
 * Refactored to match relay server structure.
 *
 * Usage: finalServer [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <iostream>

#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"
#include "socket.h"
#include "selector.h"

// Maximum number of concurrent connections
const int MAX_CLIENTS = 1024;
const int DEFAULT_PORT = 30000;

// --- Data Structures ---

struct Note {
    int id;
    char ciphertext[MSG_SIZE];
    Note *next;
};

struct Room {
    int id;
    int invite_code;
    unsigned long long room_key; 
    Note *notes;
    int note_count;
    Room *next;
};

struct ClientContext {
    Socket *sock;
    unsigned long long shared_key;
    bool dh_completed;
    int current_room_id; 
};

// --- Function Prototypes ---

int getPortNumber(int argc, char *argv[]);
void initServerSocket(int portNum);
void initSelector();
void processRequests();
void handleClientConnection();
void handleClientRequest(int fd);
void disconnectClient(int fd);

// Logic Helpers
Room* create_room();
Room* find_room_by_id(int id);
Room* find_room_by_invite(int code);
void add_note(Room *r, const char *content);
bool send_packet_enc(Socket *sock, Packet *p, unsigned long long key);


// --- Global Variables ---

ServerSocket theServer;
InputSelector inputSet;

ClientContext *client_list[MAX_CLIENTS]; 
Room *room_list_head = NULL;
int next_room_id = 1;


// --- Main Function ---

int main(int argc, char *argv[]) {
    srand(time(NULL));

    // 1. Get Port
    int port = getPortNumber(argc, argv);

    // 2. Initialize Server Socket
    initServerSocket(port);

    // 3. Initialize Selector
    initSelector();

    // 4. Enter Main Loop
    processRequests();

    return 0;
}


// --- Core Functions ---

int getPortNumber(int argc, char *argv[]) {
    if (argc > 1) {
        return atoi(argv[1]);
    }
    return DEFAULT_PORT;
}

void initServerSocket(int portNum) {
    if (!theServer.bind(portNum)) {
        printf("Error: Could not bind to port %d\n", portNum);
        exit(1);
    }
    printf("[Server] Listening on port %d...\n", portNum);
}

void initSelector() {
    // Hack to get FD from ServerSocket (assuming first member is int)
    int fd = *(int*)&theServer;
    inputSet.add(fd);
}

void processRequests() {
    bool running = true;
    while (running) {
        int *active_fds = inputSet.select();
        
        // If select returns NULL, we just continue
        if (active_fds != NULL) {
            int i = 0;
            // Iterate using a flag instead of break
            bool more_fds = true;
            
            while (more_fds) {
                int fd = active_fds[i];
                
                if (fd == -1) {
                    more_fds = false;
                } else {
                    // Check if it's the listener or a client
                    int listen_fd = *(int*)&theServer;
                    
                    if (fd == listen_fd) {
                        handleClientConnection();
                    } else {
                        handleClientRequest(fd);
                    }
                    i++;
                }
            }
            delete [] active_fds; // select() allocates memory
        }
    }
}

void handleClientConnection() {
    Socket *new_sock = theServer.accept();
    if (new_sock != NULL) {
        int new_fd = *(int*)new_sock;
        
        if (new_fd < MAX_CLIENTS && new_fd > 0) {
            inputSet.add(new_fd);
            
            // Allocate context
            ClientContext *ctx = new ClientContext;
            ctx->sock = new_sock;
            ctx->dh_completed = false;
            ctx->shared_key = 0;
            ctx->current_room_id = -1;
            
            client_list[new_fd] = ctx;
            printf("[Server] New connection (fd: %d)\n", new_fd);
        } else {
            printf("[Server] Connection rejected (Max clients)\n");
            new_sock->close();
            delete new_sock;
        }
    }
}

void handleClientRequest(int fd) {
    ClientContext *ctx = client_list[fd];
    
    if (ctx != NULL) {
        Packet req;
        int n = ctx->sock->recv(&req, sizeof(Packet));

        if (n <= 0) {
            disconnectClient(fd);
        } else {
            // Process Logic using If/Else chains (No Switch/Break)
            
            // --- 1. DH Handshake ---
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
                printf("[Server] Handshake fd: %d\n", fd);
            }
            // --- 2. Encrypted Operations ---
            else if (ctx->dh_completed) {
                // Decrypt
                xor_buffer(req.message, MSG_SIZE, ctx->shared_key);
                
                Packet resp;
                memset(&resp, 0, sizeof(resp));

                if (req.op == OP_CREATE_ROOM) {
                    Room *r = create_room();
                    ctx->current_room_id = r->id;
                    resp.op = OP_CREATE_ROOM_RESP;
                    resp.room_id = r->id;
                    resp.tag = r->invite_code;
                    snprintf(resp.message, MSG_SIZE, "Room Created");
                    send_packet_enc(ctx->sock, &resp, ctx->shared_key);
                    printf("[Server] Room %d created\n", r->id);
                }
                else if (req.op == OP_JOIN_ROOM) {
                    Room *r = find_room_by_invite(req.tag);
                    if (r != NULL) {
                        ctx->current_room_id = r->id;
                        resp.op = OP_JOIN_ROOM_RESP;
                        resp.room_id = r->id;
                        snprintf(resp.message, MSG_SIZE, "Joined Room");
                    } else {
                        resp.op = OP_ERROR;
                        snprintf(resp.message, MSG_SIZE, "Invalid Code");
                    }
                    send_packet_enc(ctx->sock, &resp, ctx->shared_key);
                }
                else if (req.op == OP_POST_NOTE) {
                    Room *r = find_room_by_id(ctx->current_room_id);
                    if (r != NULL) {
                        add_note(r, req.message);
                        printf("[Server] Note in Room %d\n", r->id);
                    }
                }
                else if (req.op == OP_LIST_NOTES) {
                    Room *r = find_room_by_id(ctx->current_room_id);
                    if (r != NULL) {
                        Note *cur = r->notes;
                        while (cur != NULL) {
                            Packet noteP;
                            memset(&noteP, 0, sizeof(noteP));
                            noteP.op = OP_LIST_NOTES_RESP;
                            noteP.tag = cur->id;
                            memcpy(noteP.message, cur->ciphertext, MSG_SIZE);
                            send_packet_enc(ctx->sock, &noteP, ctx->shared_key);
                            cur = cur->next;
                        }
                    }
                    Packet endP;
                    memset(&endP, 0, sizeof(endP));
                    endP.op = OP_LIST_NOTES_RESP;
                    endP.tag = 0; 
                    send_packet_enc(ctx->sock, &endP, ctx->shared_key);
                }
            }
        }
    }
}

void disconnectClient(int fd) {
    printf("[Server] Client (fd: %d) disconnected.\n", fd);
    inputSet.remove(fd);
    
    if (client_list[fd] != NULL) {
        delete client_list[fd]->sock;
        delete client_list[fd];
        client_list[fd] = NULL;
    }
}

// --- Logic Helpers ---

bool send_packet_enc(Socket *sock, Packet *p, unsigned long long key) {
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer(tmp.message, MSG_SIZE, key);
    int n = sock->send(&tmp, sizeof(Packet));
    return n == sizeof(Packet);
}

Room* create_room() {
    Room *r = new Room;
    r->id = next_room_id++;
    r->invite_code = rand() % 9000 + 1000;
    r->room_key = (unsigned long long)rand() << 32 | rand();
    r->notes = NULL;
    r->note_count = 0;
    r->next = room_list_head;
    room_list_head = r;
    return r;
}

Room* find_room_by_id(int id) {
    Room *cur = room_list_head;
    while (cur != NULL) {
        if (cur->id == id) return cur;
        cur = cur->next;
    }
    return NULL;
}

Room* find_room_by_invite(int code) {
    Room *cur = room_list_head;
    while (cur != NULL) {
        if (cur->invite_code == code) return cur;
        cur = cur->next;
    }
    return NULL;
}

void add_note(Room *r, const char *content) {
    Note *n = new Note;
    n->id = ++(r->note_count);
    n->next = r->notes; 
    memcpy(n->ciphertext, content, MSG_SIZE); 
    r->notes = n;
}
