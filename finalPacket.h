// Final Project Header File


#ifndef FINALPACKET_H
#define FINALPACKET_H

#include <stdint.h>

#define MSG_SIZE 256

/* Operation codes */
enum {
    OP_DH_PUB = 1,

    OP_CREATE_ROOM = 10,
    OP_CREATE_ROOM_RESP = 11,

    OP_JOIN_ROOM = 12,
    OP_JOIN_ROOM_RESP = 13,

    OP_POST_NOTE = 20,
    OP_LIST_NOTES = 21,
    OP_LIST_NOTES_RESP = 22,
    OP_ROOM_UPDATE = 23,

    OP_DISCONNECT = 30,
    OP_ERROR = 40
};

/* Generic packet structure used on the wire */
typedef struct {
    int32_t op;
    int32_t room_id;
    int32_t tag;
    char message[MSG_SIZE];
} Packet;

#endif