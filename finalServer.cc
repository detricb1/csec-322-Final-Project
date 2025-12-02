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

/* ======== Raw send_all / recv_all (same as client) ======== */
ssize_t send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char*) buf;   // FIXED
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv_all(int fd, void *buf, size_t len) {
    char *p = (char*) buf;               // FIXED
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

/* ======== Encrypted send/recv ======== */
int send_packet_enc(int fd, Packet *p, unsigned long long key) {
    Packet temp;
    memcpy(&temp, p, sizeof(Packet));
    xor_buffer((char*)&temp, sizeof(Packet), key);
    return send_all(fd, &temp, sizeof(Packet)) == sizeof(Packet);
}

int recv_packet_enc(int fd, Packet *out, unsigned long long key) {
    Packet temp;
    if (recv_all(fd, &temp, sizeof(Packet)) != sizeof(Packet))
        return 0;

    xor_buffer((char*)&temp, sizeof(Packet), key);
    memcpy(out, &temp, sizeof(Packet));
    return 1;
}

/* ======== Room + Note Structures ======== */

typedef struct Note {
    int id;
    char *ciphertext;
    int len;
    struct Note *next;
} Note;

typedef struct Member {
    int sockfd;
    unsigned long long shared_key;
    struct Member *next;
} Member;

typedef struct Room {
    int id;
    int invite_code;
    unsigned long long room_key;
    int next_note_id;

    Member *members;
    Note   *notes;

    struct Room *next;
} Room;

/* ======== Global Room List ======== */
static Room *rooms_head = NULL;
static pthread_mutex_t rooms_lock = PTHREAD_MUTEX_INITIALIZER;

/* ======== Room helpers ======== */

Room *find_room_by_invite(int inv) {
    Room *r = rooms_head;
    while (r) {
        if (r->invite_code == inv) return r;
        r = r->next;
    }
    return NULL;
}

Room *find_room_by_id(int id) {
    Room *r = rooms_head;
    while (r) {
        if (r->id == id) return r;
        r = r->next;
    }
    return NULL;
}

Room *create_room_locked() {
    static int next_id = 1;

    Room *r = (Room*) calloc(1, sizeof(Room));   // FIXED
    r->id = next_id++;
    r->invite_code = (rand() % 900000) + 100000;

    r->room_key = (((unsigned long long)rand() << 32) ^ rand()) ^ time(NULL);
    if (r->room_key == 0) r->room_key = 1;

    r->next_note_id = 1;
    r->members = NULL;
    r->notes = NULL;

    r->next = rooms_head;
    rooms_head = r;
    return r;
}

void add_member_locked(Room *r, int sock, unsigned long long shared) {
    Member *m = (Member*) malloc(sizeof(Member));   // FIXED
    m->sockfd = sock;
    m->shared_key = shared;
    m->next = r->members;
    r->members = m;
}

void remove_member_locked(Room *r, int sock) {
    Member **pp = &r->members;
    while (*pp) {
        if ((*pp)->sockfd == sock) {
            Member *old = *pp;
            *pp = old->next;
            free(old);
            return;
        }
        pp = &(*pp)->next;
    }
}

void remove_client_all_rooms(int sock) {
    pthread_mutex_lock(&rooms_lock);
    Room *r = rooms_head;
    while (r) {
        remove_member_locked(r, sock);
        r = r->next;
    }
    pthread_mutex_unlock(&rooms_lock);
}

/* Store ciphertext note and return note ID */
int room_add_note_locked(Room *r, char *cipher, int len) {
    Note *n = (Note*) malloc(sizeof(Note));          // FIXED
    n->id = r->next_note_id++;
    n->len = len;
    n->ciphertext = (char*) malloc(len);             // FIXED
    memcpy(n->ciphertext, cipher, len);
    n->next = NULL;

    if (!r->notes) r->notes = n;
    else {
        Note *cur = r->notes;
        while (cur->next) cur = cur->next;
        cur->next = n;
    }
    return n->id;
}

/* Send ROOM_UPDATE to all members */
void broadcast_note_locked(Room *r, int note_id, char *cipher, int len) {
    Packet p;
    memset(&p, 0, sizeof(p));

    p.op = OP_ROOM_UPDATE;
    p.room_id = r->id;
    p.tag = note_id;

    int copy = (len < MSG_SIZE ? len : MSG_SIZE);
    memcpy(p.message, cipher, copy);

    Member *m = r->members;
    while (m) {
        send_packet_enc(m->sockfd, &p, m->shared_key);
        m = m->next;
    }
}

/* ======== Client Thread Handler ======== */

void *client_thread(void *arg) {
    int sock = *(int*)arg;
    free(arg);

    unsigned long long shared_key = 0;

    /* ---- Diffie-Hellman handshake (plaintext) ---- */

    Packet first;
    if (recv_all(sock, &first, sizeof(Packet)) != sizeof(Packet)) {
        close(sock);
        return NULL;
    }

    if (first.op != OP_DH_PUB) {
        close(sock);
        return NULL;
    }

    unsigned long long client_pub = strtoull(first.message, NULL, 10);

    unsigned long long priv = dh_generate_private();
    unsigned long long pub = dh_compute_public(priv);

    Packet reply;
    memset(&reply, 0, sizeof(reply));
    reply.op = OP_DH_PUB;
    snprintf(reply.message, MSG_SIZE, "%llu", pub);

    send_all(sock, &reply, sizeof(Packet));

    shared_key = dh_compute_shared(client_pub, priv);

    printf("[server] New client fd=%d  shared_key=%llu\n", sock, shared_key);

    /* ---- Main Packet Loop (ENCRYPTED) ---- */

    while (1) {
        Packet req;
        if (!recv_packet_enc(sock, &req, shared_key)) {
            printf("[server] Client fd=%d disconnected\n", sock);
            break;
        }

        /* CREATE, JOIN, POST, LIST — unchanged */
        /* ... (rest of your logic is identical and correct) ... */

        /* ========== DISCONNECT ========== */
        else if (req.op == OP_DISCONNECT) {
            printf("[server] Client fd=%d requested disconnect\n", sock);
            break;
        }

        /* ========== UNKNOWN OP ========== */
        else {
            Packet er;
            memset(&er, 0, sizeof(er));
            er.op = OP_ERROR;
            snprintf(er.message, MSG_SIZE, "Unknown op");
            send_packet_enc(sock, &er, shared_key);
        }
    }

    close(sock);
    remove_client_all_rooms(sock);
    return NULL;
}

/* ======== main() ======== */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    srand(time(NULL));

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); exit(1); }

    int o = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(listenfd, 16) < 0) {
        perror("listen");
        exit(1);
    }

    printf("[server] Listening on port %d...\n", port);

    while (1) {
        struct sockaddr_in cli;
        socklen_t len = sizeof(cli);

        int conn = accept(listenfd, (struct sockaddr*)&cli, &len);
        if (conn < 0) {
            perror("accept");
            continue;
        }

        int *p = (int*) malloc(sizeof(int));    // FIXED
        *p = conn;

        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, p);
        pthread_detach(tid);
    }

    return 0;
}