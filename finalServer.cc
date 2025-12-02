// finalServer.cc

/*
 * server.c
 * SecureCollabNotes Server (Modular Version)
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
    Room *next;
};

struct ClientContext {
    Socket *sock;
    unsigned long long shared_key;
    bool dh_completed;
    int current_room_id; 
};

// --- Global State ---

ClientContext *client_list[MAX_CLIENTS]; 
Room *room_list_head = NULL;
int next_room_id = 1;

// --- Helper Functions ---

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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    srand(time(NULL));

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

    // Attempt to access the internal file descriptor (Hack)
    // We assume the first int member of the class is the fd.
    int listen_fd = *(int*)&serverSock; 
    
    printf("[Server] Debug: Listen FD is %d\n", listen_fd);

    // 2. Setup Selector
    InputSelector selector;
    selector.add(listen_fd);

    while (1) {
        int *active_fds = selector.select();
        if (!active_fds) continue;

        for (int i = 0; active_fds[i] != -1; i++) {
            int fd = active_fds[i];

            // === CASE A: New Connection ===
            if (fd == listen_fd) {
                Socket *new_sock = serverSock.accept();
                if (new_sock) {
                    // Hack to get new FD
                    int new_fd = *(int*)new_sock; 
                    
                    if (new_fd < MAX_CLIENTS && new_fd > 0) {
                        selector.add(new_fd);
                        
                        ClientContext *ctx = new ClientContext;
                        ctx->sock = new_sock;
                        ctx->dh_completed = false;
                        ctx->shared_key = 0;
                        ctx->current_room_id = -1;
                        client_list[new_fd] = ctx;
                        
                        printf("[Server] New connection (fd: %d)\n", new_fd);
                    } else {
                        printf("[Server] Invalid FD or Too many clients\n");
                        new_sock->close();
                        delete new_sock;
                    }
                }
            }
            // === CASE B: Data from Client ===
            else {
                ClientContext *ctx = client_list[fd];
                if (ctx == NULL) {
                    selector.remove(fd);
                    continue;
                }

                Packet req;
                int n = ctx->sock->recv(&req, sizeof(Packet));

                if (n <= 0) {
                    printf("[Server] Client (fd: %d) disconnected.\n", fd);
                    selector.remove(fd);
                    delete ctx->sock;
                    delete ctx;
                    client_list[fd] = NULL;
                } else {
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
                        printf("[Server] DH Handshake complete for fd %d\n", fd);
                    }
                    // 2. Encrypted Commands
                    else if (ctx->dh_completed) {
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
                            printf("[Server] Room %d created\n", r->id);
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
                                if (r) add_note(r, req.message);
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
        }
    }
}
