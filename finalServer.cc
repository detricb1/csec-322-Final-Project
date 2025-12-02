// finalServer.cc

/*
 * server.c
 * SecureCollabNotes Server (Modular Version)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"
#include "socket.h"
#include "selector.h"

// Maximum number of concurrent connections we will support
#define MAX_CLIENTS 1024

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
    Room *next; // For linked list
};

struct ClientContext {
    Socket *sock;
    unsigned long long shared_key;
    bool dh_completed;
    int current_room_id; // -1 if none
};

// --- Global State ---

// Array of pointers to clients, indexed by their socket File Descriptor (fd)
ClientContext *client_list[MAX_CLIENTS]; 

// Head of the Room linked list
Room *room_list_head = NULL;
int next_room_id = 1;

// --- Helper Functions ---

// Send an encrypted packet
bool send_packet_enc(Socket *sock, Packet *p, unsigned long long key) {
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    
    // Encrypt the message part
    xor_buffer(tmp.message, MSG_SIZE, key);
    
    // Send raw bytes
    int n = sock->send(&tmp, sizeof(Packet));
    return n == sizeof(Packet);
}

// Create a new room and add to linked list
Room* create_room() {
    Room *r = new Room;
    r->id = next_room_id++;
    r->invite_code = rand() % 9000 + 1000; // 4 digit code
    r->room_key = (unsigned long long)rand() << 32 | rand();
    r->notes = NULL;
    r->note_count = 0;
    
    // Add to front of linked list
    r->next = room_list_head;
    room_list_head = r;
    
    return r;
}

// Find a room by ID
Room* find_room_by_id(int id) {
    Room *cur = room_list_head;
    while (cur != NULL) {
        if (cur->id == id) return cur;
        cur = cur->next;
    }
    return NULL;
}

// Find a room by Invite Code
Room* find_room_by_invite(int code) {
    Room *cur = room_list_head;
    while (cur != NULL) {
        if (cur->invite_code == code) return cur;
        cur = cur->next;
    }
    return NULL;
}

// Add a note to a room
void add_note(Room *r, const char *content) {
    Note *n = new Note;
    n->id = ++(r->note_count);
    n->next = r->notes; // Add to front
    memcpy(n->ciphertext, content, MSG_SIZE); 
    r->notes = n;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    srand(time(NULL));

    // Initialize client list to NULL
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_list[i] = NULL;
    }

    // 1. Setup Server Socket
    ServerSocket serverSock;
    if (!serverSock.bind(port)) {
        printf("Failed to bind to port %d\n", port);
        exit(1);
    }
    printf("[Server] Listening on port %d...\n", port);

    // Hack to get the File Descriptor (FD) from the Socket class
    // We assume the first member variable of Socket/ServerSocket is the integer FD.
    int listen_fd = *(int*)&serverSock; 

    // 2. Setup Selector
    InputSelector selector;
    selector.add(listen_fd);

    while (1) {
        // Wait for activity
        int *active_fds = selector.select();
        if (!active_fds) continue;

        // Loop through all active file descriptors
        for (int i = 0; active_fds[i] != -1; i++) {
            int fd = active_fds[i];

            // === CASE A: New Connection ===
            if (fd == listen_fd) {
                Socket *new_sock = serverSock.accept();
                if (new_sock) {
                    int new_fd = *(int*)new_sock; // Get FD of new connection
                    
                    if (new_fd < MAX_CLIENTS) {
                        selector.add(new_fd);
                        
                        // Create context
                        ClientContext *ctx = new ClientContext;
                        ctx->sock = new_sock;
                        ctx->dh_completed = false;
                        ctx->shared_key = 0;
                        ctx->current_room_id = -1;
                        
                        // Save to array
                        client_list[new_fd] = ctx;
                        
                        printf("[Server] New connection (fd: %d)\n", new_fd);
                    } else {
                        printf("[Server] Too many clients, rejecting fd %d\n", new_fd);
                        new_sock->close();
                        delete new_sock;
                    }
                }
            }
            // === CASE B: Data from Client ===
            else {
                ClientContext *ctx = client_list[fd];
                
                // Safety check
                if (ctx == NULL) {
                    selector.remove(fd);
                    continue;
                }

                Packet req;
                int n = ctx->sock->recv(&req, sizeof(Packet));

                if (n <= 0) {
                    // Disconnected
                    printf("[Server] Client (fd: %d) disconnected.\n", fd);
                    selector.remove(fd);
                    
                    // Cleanup
                    delete ctx->sock;
                    delete ctx;
                    client_list[fd] = NULL;
                } else {
                    // Logic Handler
                    
                    // 1. DH Handshake (Unencrypted)
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
                        printf("[Server] DH Handshake complete for fd %d. Key: %llu\n", fd, ctx->shared_key);
                    }
                    // 2. Encrypted Commands
                    else if (ctx->dh_completed) {
                        // Decrypt incoming message
                        xor_buffer(req.message, MSG_SIZE, ctx->shared_key);
                        
                        Packet resp;
                        memset(&resp, 0, sizeof(resp));

                        if (req.op == OP_CREATE_ROOM) {
                            Room *r = create_room();
                            ctx->current_room_id = r->id;
                            
                            resp.op = OP_CREATE_ROOM_RESP;
                            resp.room_id = r->id;
                            resp.tag = r->invite_code;
                            snprintf(resp.message, MSG_SIZE, "Room Created!");
                            
                            send_packet_enc(ctx->sock, &resp, ctx->shared_key);
                            printf("[Server] Room %d created (Invite: %d)\n", r->id, r->invite_code);
                        }
                        else if (req.op == OP_JOIN_ROOM) {
                            int code = req.tag;
                            Room *r = find_room_by_invite(code);
                            
                            if (r != NULL) {
                                ctx->current_room_id = r->id;
                                resp.op = OP_JOIN_ROOM_RESP;
                                resp.room_id = r->id;
                                snprintf(resp.message, MSG_SIZE, "Joined Room %d", r->id);
                            } else {
                                resp.op = OP_ERROR;
                                snprintf(resp.message, MSG_SIZE, "Invalid Invite Code");
                            }
                            send_packet_enc(ctx->sock, &resp, ctx->shared_key);
                        }
                        else if (req.op == OP_POST_NOTE) {
                            if (ctx->current_room_id != -1) {
                                Room *r = find_room_by_id(ctx->current_room_id);
                                if (r) {
                                    add_note(r, req.message);
                                    printf("[Server] Note posted to Room %d\n", r->id);
                                }
                            }
                        }
                        else if (req.op == OP_LIST_NOTES) {
                            if (ctx->current_room_id != -1) {
                                Room *r = find_room_by_id(ctx->current_room_id);
                                if (r) {
                                    Note *cur = r->notes;
                                    while(cur) {
                                        Packet noteP;
                                        memset(&noteP, 0, sizeof(noteP));
                                        noteP.op = OP_LIST_NOTES_RESP;
                                        noteP.tag = cur->id;
                                        memcpy(noteP.message, cur->ciphertext, MSG_SIZE);
                                        send_packet_enc(ctx->sock, &noteP, ctx->shared_key);
                                        
                                        cur = cur->next;
                                    }
                                }
                                // End marker
                                Packet endP;
                                memset(&endP, 0, sizeof(endP));
                                endP.op = OP_LIST_NOTES_RESP;
                                endP.tag = 0; // 0 ID means end
                                send_packet_enc(ctx->sock, &endP, ctx->shared_key);
                            }
                        }
                    }
                }
            }
        }
    }
}
