/* finalPacket.h
 *
 * Defines the protocol packet structure used for the Secure Notes
 * application.
 */

#ifndef _FINALPACKET_H
#define _FINALPACKET_H

#include <stdint.h>

const int MSG_SIZE = 256;

/* Operation Codes */
const int OP_DH_PUB           = 1;

const int OP_CREATE_ROOM      = 10;
const int OP_CREATE_ROOM_RESP = 11;

const int OP_JOIN_ROOM        = 12;
const int OP_JOIN_ROOM_RESP   = 13;

const int OP_POST_NOTE        = 20;
const int OP_LIST_NOTES       = 21;
const int OP_LIST_NOTES_RESP  = 22;

const int OP_DISCONNECT       = 30;
const int OP_ERROR            = 40;

/* * The packet contains:
 * op:       The operation code (int)
 * room_id:  The ID of the room (int)
 * tag:      Invite code or Note ID (int)
 * message:  The payload (char array)
 */
struct Packet {
    int32_t op;
    int32_t room_id;
    int32_t tag;
    char message[MSG_SIZE];
};

#endif
