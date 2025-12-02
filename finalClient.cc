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
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "finalPacket.h"
#include "diffieHellman.h"
#include "xor.h"

/* ======== Raw blocking I/O ======== */

ssize_t send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char*) buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv_all(int fd, void *buf, size_t len) {
    char *p = (char*) buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

/* ======== Encrypted Packet Send/Recv ======== */

int send_packet_enc(int fd, Packet *p, unsigned long long key) {
    Packet tmp;
    memcpy(&tmp, p, sizeof(Packet));
    xor_buffer((char*)&tmp, sizeof(Packet), key);
    return send_all(fd, &tmp, sizeof(Packet)) == sizeof(Packet);
}

int recv_packet_enc(int fd, Packet *out, unsigned long long key) {
    Packet tmp;
    if (recv_all(fd, &tmp, sizeof(Packet)) != sizeof(Packet))
        return 0;
    xor_buffer((char*)&tmp, sizeof(Packet), key);
    memcpy(out, &tmp, sizeof(Packet));
    return 1;
}

/* ========== Globals ========== */

int g_sock = -1;
unsigned long long g_shared_key = 0;

/* Thread that receives async updates from server */
void *recv_thread(void *arg) {
    (void)arg;

    while (1) {
        Packet p;
        if (!recv_packet_enc(g_sock, &p, g_shared_key)) {
            printf("[client] Disconnected from server.\n");
            exit(0);
        }

        if (p.op == OP_ROOM_UPDATE) {
            printf("\n[Room %d] New Note (ID %d): %s\n> ",
                p.room_id, p.tag, p.message);
            fflush(stdout);
        }
        else if (p.op == OP_LIST_NOTES_RESP) {
            if (p.tag == 0) {
                printf("[End of Notes]\n");
            } else {
                printf("Note %d: %s\n", p.tag, p.message);
            }
        }
        else if (p.op == OP_ERROR) {
            printf("[ERROR] %s\n> ", p.message);
            fflush(stdout);
        }
        else {
            /* ignore other OPs */
        }
    }
    return NULL;
}

/* ========== Diffie-Hellman Handshake ========== */

int do_dh_handshake() {
    unsigned long long priv = dh_generate_private();
    unsigned long long pub = dh_compute_public(priv);

    /* Send client public value (plaintext) */
    Packet init;
    memset(&init, 0, sizeof(init));
    init.op = OP_DH_PUB;
    snprintf(init.message, MSG_SIZE, "%llu", pub);

    if (send_all(g_sock, &init, sizeof(init)) != sizeof(init))
        return 0;

    /* Receive server public value */
    Packet resp;
    if (recv_all(g_sock, &resp, sizeof(resp)) != sizeof(resp))
        return 0;

    if (resp.op != OP_DH_PUB)
        return 0;

    unsigned long long server_pub = strtoull(resp.message, NULL, 10);
    g_shared_key = dh_compute_shared(server_pub, priv);

    printf("[client] Shared key established: %llu\n", g_shared_key);
    return 1;
}

/* ========== Menu Helpers ========== */

void send_create_room() {
    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_CREATE_ROOM;

    send_packet_enc(g_sock, &p, g_shared_key);

    printf("Waiting for server response...\n");

    Packet resp;
    if (!recv_packet_enc(g_sock, &resp, g_shared_key)) return;

    if (resp.op == OP_CREATE_ROOM_RESP) {
        printf("\n[Room Created]\n");
        printf("Room ID: %d\n", resp.room_id);
        printf("Invite Code: %d\n", resp.tag);
        printf("Room Key: %s\n\n", resp.message);
    }
}

void send_join_room() {
    int invite;
    printf("Enter invite code: ");
    scanf("%d", &invite);
    getchar();

    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_JOIN_ROOM;
    p.tag = invite;

    send_packet_enc(g_sock, &p, g_shared_key);

    Packet r;
    if (!recv_packet_enc(g_sock, &r, g_shared_key)) return;

    if (r.op == OP_JOIN_ROOM_RESP) {
        printf("\n[Joined Room]\n");
        printf("Room ID: %d\n", r.room_id);
        printf("Invite Code: %d\n", r.tag);
        printf("Room Key: %s\n\n", r.message);
    } else if (r.op == OP_ERROR) {
        printf("[ERROR] %s\n", r.message);
    }
}

void send_post_note() {
    int room_id;
    printf("Enter room ID: ");
    scanf("%d", &room_id);
    getchar();

    char msg[MSG_SIZE];
    printf("Enter note text: ");
    fgets(msg, MSG_SIZE, stdin);
    msg[strcspn(msg, "\n")] = 0;

    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_POST_NOTE;
    p.room_id = room_id;
    strncpy(p.message, msg, MSG_SIZE);

    send_packet_enc(g_sock, &p, g_shared_key);
}

void send_list_notes() {
    int rid;
    printf("Enter room ID: ");
    scanf("%d", &rid);
    getchar();

    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_LIST_NOTES;
    p.room_id = rid;

    send_packet_enc(g_sock, &p, g_shared_key);
}

void send_disconnect() {
    Packet p;
    memset(&p, 0, sizeof(p));
    p.op = OP_DISCONNECT;
    send_packet_enc(g_sock, &p, g_shared_key);
}

/* ========== MAIN ========== */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock < 0) { perror("socket"); exit(1); }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(g_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    printf("[client] Connected to %s:%d\n", ip, port);

    if (!do_dh_handshake()) {
        printf("[client] DH handshake failed.\n");
        exit(1);
    }

    /* Start receiver thread */
    pthread_t tid;
    pthread_create(&tid, NULL, recv_thread, NULL);
    pthread_detach(tid);

    /* Main menu loop */
    while (1) {
        printf("\n===== Secure Notes Menu =====\n");
        printf("1) Create Room\n");
        printf("2) Join Room\n");
        printf("3) Post Note\n");
        printf("4) List Notes\n");
        printf("5) Quit\n");
        printf("> ");

        int choice;
        scanf("%d", &choice);
        getchar();

        if (choice == 1) send_create_room();
        else if (choice == 2) send_join_room();
        else if (choice == 3) send_post_note();
        else if (choice == 4) send_list_notes();
        else if (choice == 5) {
            send_disconnect();
            close(g_sock);
            exit(0);
        }
        else {
            printf("Invalid option.\n");
        }
    }

    return 0;
}