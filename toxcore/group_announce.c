/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <inttypes.h>

#include "group_announce.h"

#include "logger.h"
#include "util.h"
#include "network.h"
#include "DHT.h"

#define NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST 5 /* Announce request packet ID */
//#define NET_PACKET_ANNOUNCE_RESPONSE 6 /* Announce response packet ID */ //Not needed for now
#define NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES 7 /* Get announced nodes request packet ID */
#define NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES 8 /* Send announced nodes request packet ID */

#define TIME_STAMP_SIZE (sizeof(uint64_t))
#define REQUEST_ID_SIZE (sizeof(uint64_t))
#define GC_ANNOUNCE_EXPIRATION 3600    /* sec */

// Type + Chat_ID + IP_Port + Client_ID + Timestamp + Signature
#define GC_ANNOUNCE_REQUEST_PLAIN_SIZE (1 + EXT_PUBLIC_KEY + sizeof(IP_Port) + EXT_PUBLIC_KEY + TIME_STAMP_SIZE + SIGNATURE_SIZE)
#define GC_ANNOUNCE_REQUEST_DHT_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_ANNOUNCE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

// Type + Chat_ID + IP_Port + RequestID + Client_ID + Timestamp + Signature
#define GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE (1 + EXT_PUBLIC_KEY + EXT_PUBLIC_KEY + sizeof(IP_Port) + REQUEST_ID_SIZE + TIME_STAMP_SIZE + SIGNATURE_SIZE)
#define GC_ANNOUNCE_GETNODES_REQUEST_DHT_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

// Type + Num_Nodes + Nodes + RequestID
#define GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE (1 + sizeof(uint32_t) + sizeof(GC_Announce_Node) * MAX_SENT_ANNOUNCED_NODES + REQUEST_ID_SIZE)
#define GC_ANNOUNCE_GETNODES_RESPONSE_DHT_SIZE (1 + ENC_PUBLIC_KEY + REQUEST_ID_SIZE + crypto_box_NONCEBYTES + GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define MAX_CONCURRENT_REQUESTS     10
#define MAX_GC_ANNOUNCED_NODES      30
#define MAX_SENT_ANNOUNCED_NODES    2

typedef struct GC_Announce {
    DHT *dht;

    /* This structure is for announcing requests that we get from
     * online chat members. Timestamp is used for expiration purposes
     */
    struct GC_AnnouncedNode {
        uint8_t chat_id[EXT_PUBLIC_KEY];
        GC_Announce_Node node;
        uint64_t timestamp;
    } announcements[MAX_GC_ANNOUNCED_NODES];

    /* This structure is for our own requests, when we want to
     * find online chat members
     */
    struct GC_AnnounceRequest {
        uint8_t chat_id[EXT_PUBLIC_KEY];
        GC_Announce_Node nodes[MAX_SENT_ANNOUNCED_NODES];
        uint32_t nodes_num;
        uint64_t req_id;
        _Bool ready;
        uint64_t timestamp;

        /* This is redundant but it's the easiest way */
        uint8_t long_pk[EXT_PUBLIC_KEY];
        uint8_t long_sk[EXT_SECRET_KEY];
    } self_requests[MAX_CONCURRENT_REQUESTS];

    /* Number of current requests */
    uint32_t req_num;
} GC_Announce;

/* Handle all decrypt procedures */
int unwrap_gc_announce_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key,
                              uint8_t *public_key, uint8_t *data, uint8_t packet_type, const uint8_t *packet,
                              uint16_t length)
{
    uint16_t plain_length;

    switch (packet_type) {
        case NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST: {
            plain_length = GC_ANNOUNCE_REQUEST_PLAIN_SIZE;
            break;
        }
        case NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES: {
            plain_length = GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE;
            break;
        }
        case NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES: {
            plain_length = length - (GC_ANNOUNCE_GETNODES_RESPONSE_DHT_SIZE - GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE);
            break;
        }
        default:
            return -1;
    }

    if (id_equal(packet + 1, self_public_key))
        return -1;

    memcpy(public_key, packet + 1, ENC_PUBLIC_KEY);

    int header_len = 0;
    uint8_t nonce[crypto_box_NONCEBYTES];

    if (packet_type == NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES) {
        header_len = 1 + ENC_PUBLIC_KEY + REQUEST_ID_SIZE + crypto_box_NONCEBYTES;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + REQUEST_ID_SIZE, crypto_box_NONCEBYTES);
    } else {
        header_len = 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);
    }

    uint8_t plain[plain_length];
    int len = decrypt_data(public_key, self_secret_key, nonce, packet + header_len, length - header_len, plain);

    if (len != plain_length)
        return -1;

    if (plain[0] != packet_type)
        return -1;

    // TODO: check if this is safe
    memcpy(data, plain, plain_length);
    return plain_length;
}

/* Handle all encrypt procedures */
int wrap_gc_announce_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key, const uint8_t *recv_public_key,
                            uint8_t *packet, const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[length + crypto_box_MACBYTES];
    int len = encrypt_data(recv_public_key, send_secret_key, nonce, data, length, encrypt);

    if (len != sizeof(encrypt))
        return -1;

    packet[0] = packet_type;
    memcpy(packet + 1, send_public_key, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);

    uint32_t header_len = 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES;
    memcpy(packet + header_len, encrypt, len);

    return header_len + len;
}

/* Returns the number of sent packets */
int dispatch_packet(GC_Announce* announce, const uint8_t *target_id, const uint8_t *previous_id,
                    const uint8_t *data, uint32_t length, uint8_t packet_type, _Bool self)
{
    /* The packet is valid, find the closest nodes to send it to */
    static Node_format nodes[MAX_SENT_NODES];
    int nclosest = get_close_nodes(announce->dht, target_id, nodes, 0, 1, 1); /* TODO: dehardcode last 3 params */

    if (nclosest > MAX_SENT_ANNOUNCED_NODES)
        nclosest = MAX_SENT_ANNOUNCED_NODES;
    else if (nclosest <= 0)
        return -1;

    uint8_t *packet = NULL;

    switch (packet_type) {
        case NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST: {
            packet = malloc(GC_ANNOUNCE_REQUEST_DHT_SIZE * sizeof(uint8_t));

            if (packet == NULL)
                return -1;

            break;
        }
        case NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES: {
            packet = malloc(GC_ANNOUNCE_GETNODES_REQUEST_DHT_SIZE * sizeof(uint8_t));

            if (packet == NULL)
                return -1;

            break;
        }
        default:
            return -1;
    }

    int i, j = 0;

    for (i = 0; i < nclosest; i++) {
        if (id_closest(target_id, nodes[i].client_id, previous_id) == 1) {
            int packet_length = wrap_gc_announce_packet(announce->dht->self_public_key,
                                                        announce->dht->self_secret_key,
                                                        nodes[i].client_id, packet,
                                                        data, length, packet_type);
            if (packet_length == -1)
                continue;

            if (sendpacket(announce->dht->net, nodes[i].ip_port, packet, packet_length) != -1)
                ++j;
        }
    }

    free(packet);
    packet = NULL;

    if (j == 0 && !self && packet_type == NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST) {
        GC_Announce_Node node;
        memcpy(&node.ip_port, data + 1 + EXT_PUBLIC_KEY, sizeof(IP_Port));
        memcpy(node.client_id, data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port), EXT_PUBLIC_KEY);
        add_gc_announced_node(announce, data + 1, node, data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port) + EXT_PUBLIC_KEY);
    }

    return j;
}

int gca_send_announce_request(GC_Announce* announce, const uint8_t *self_long_pk, const uint8_t *self_long_sk,
                              const uint8_t *chat_id)
{
    DHT *dht = announce->dht;
    /* Generating an announcement */
    uint8_t data[GC_ANNOUNCE_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST;
    memcpy(data + 1, chat_id, EXT_PUBLIC_KEY);
    IP_Port ipp;

    int i;

    for (i = 0; i < LCLIENT_LIST; i++) {
        if (ipport_isset(&dht->close_clientlist[i].assoc4.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc4.ret_ip_port);
            break;
        }

        if (ipport_isset(&dht->close_clientlist[i].assoc6.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc6.ret_ip_port);
            break;
        }
    }

    if (!ipport_isset(&ipp))
        return -1;

    memcpy(data + 1 + EXT_PUBLIC_KEY, &ipp, sizeof(IP_Port));

    if (sign_data(data, 1 + EXT_PUBLIC_KEY + sizeof(IP_Port), self_long_sk, self_long_pk, data) == -1)
        return -1;

    return dispatch_packet(announce, ENC_KEY(chat_id), dht->self_public_key, data, GC_ANNOUNCE_REQUEST_PLAIN_SIZE,
                           NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, 1);
}

int handle_gc_announce_request(void * ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    fprintf(stderr, "handle_gc_announce_request\n");
    GC_Announce* announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GC_ANNOUNCE_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gc_announce_packet(dht->self_public_key, dht->self_secret_key, public_key,
                                                 data, packet[0], packet, length);

    if (plain_length != GC_ANNOUNCE_REQUEST_PLAIN_SIZE)
        return -1;

    if (crypto_sign_verify_detached(data + GC_ANNOUNCE_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    data, GC_ANNOUNCE_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(data + GC_ANNOUNCE_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE
                                            - TIME_STAMP_SIZE - EXT_PUBLIC_KEY)) != 0)
        return -1;

    fprintf(stderr, "handle_gc_announce_request done!\n");
    return dispatch_packet(announce, ENC_KEY(data+1), dht->self_public_key, data,
                           GC_ANNOUNCE_REQUEST_PLAIN_SIZE, NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, 0);
}

int gca_send_get_nodes_request(GC_Announce* announce, const uint8_t *self_long_pk, const uint8_t *self_long_sk,
                               const uint8_t *chat_id)
{
    // TODO: Check if we already have some nodes!!!
    DHT *dht = announce->dht;

    uint8_t data[GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES;
    memcpy(data + 1, chat_id, EXT_PUBLIC_KEY);

    IP_Port ipp;
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; i++) {
        if (ipport_isset(&dht->close_clientlist[i].assoc4.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc4.ret_ip_port);
            break;
        }

        if (ipport_isset(&dht->close_clientlist[i].assoc6.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc6.ret_ip_port);
            break;
        }
    }

    if (!ipport_isset(&ipp))
        return -1;

    memcpy(data + 1 + EXT_PUBLIC_KEY, &ipp, sizeof(IP_Port));
    uint64_t request_id = random_64b();
    U64_to_bytes(data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port), request_id);

    if (sign_data(data, 1 + EXT_PUBLIC_KEY + sizeof(IP_Port) + REQUEST_ID_SIZE, self_long_sk, self_long_pk, data) == -1)
        return -1;

    uint64_t timestamp;
    bytes_to_U64(&timestamp, data - SIGNATURE_SIZE - TIME_STAMP_SIZE);

    new_announce_self_request(announce, chat_id, request_id, timestamp, self_long_pk, self_long_sk);

    return dispatch_packet(announce, ENC_KEY(chat_id), dht->self_public_key, data, GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE,
                           NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, 1);
}

int handle_gc_get_announced_nodes_request(void * ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    fprintf(stderr, "handle_gc_get_announced_nodes_request\n");
    GC_Announce* announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gc_announce_packet(dht->self_public_key, dht->self_secret_key, public_key,
                                                 data, packet[0], packet, length);

    if (plain_length != GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE)
        return -1;

    if (crypto_sign_verify_detached(data + GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    data, GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(data + GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE
                                    - TIME_STAMP_SIZE - EXT_PUBLIC_KEY)) != 0)
        return -1;

    GC_Announce_Node nodes[MAX_SENT_ANNOUNCED_NODES];
    int num_nodes = get_gc_announced_nodes(announce, data + 1, nodes);

    if (num_nodes > 0) {
        uint64_t request_id;
        bytes_to_U64(&request_id, data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port));

        IP_Port ipp;
        memcpy(&ipp, data + 1 + EXT_PUBLIC_KEY, sizeof(IP_Port));

        return send_gc_get_announced_nodes_response(dht, data + 1, request_id, ipp,
                                                    ENC_KEY(data + GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE
                                                    - SIGNATURE_SIZE - TIME_STAMP_SIZE - EXT_PUBLIC_KEY),
                                                    nodes, num_nodes);
    }
    fprintf(stderr, "handle_gc_get_announced_nodes_request done!\n");
    return dispatch_packet(announce, ENC_KEY(data+1), dht->self_public_key, data,
                          GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE, NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, 0);
}

int send_gc_get_announced_nodes_response(DHT *dht, const uint8_t *chat_id, uint64_t request_id, IP_Port ipp,
                                         const uint8_t *receiver_pk, GC_Announce_Node *nodes, uint32_t num_nodes)
{
    uint8_t data[GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE];
    data[0] = NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES;
    U32_to_bytes(data + 1, num_nodes);
    memcpy(data + 1 + sizeof(uint32_t), nodes, sizeof(GC_Announce_Node)*num_nodes);
    uint32_t data_length = 1 + sizeof(uint32_t) + sizeof(GC_Announce_Node)*num_nodes + REQUEST_ID_SIZE;
    U64_to_bytes(data + data_length - REQUEST_ID_SIZE, request_id);

    uint8_t packet[GC_ANNOUNCE_GETNODES_RESPONSE_DHT_SIZE];
    int packet_length = wrap_gc_announce_packet(dht->self_public_key, dht->self_secret_key,
                                                receiver_pk, packet, data, data_length,
                                                NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES);

    if (packet_length == -1)
        return -1;

    memcpy(packet + 1 + ENC_PUBLIC_KEY + REQUEST_ID_SIZE, packet + 1 + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES
           + data_length + crypto_box_MACBYTES);
    U64_to_bytes(packet + 1 + ENC_PUBLIC_KEY, request_id);
    packet_length += REQUEST_ID_SIZE;

    return sendpacket(dht->net, ipp, packet, packet_length);
}

int handle_gc_get_announced_nodes_response(void * ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    fprintf(stderr, "handle_gc_get_announced_nodes_response\n");
    // NB: most probably we'll get nodes from different peers, so this would be called several times
    // TODO: different request_ids for the same chat_id... Probably
    GC_Announce *announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    uint64_t request_id;
    bytes_to_U64(&request_id, packet + 1 + ENC_PUBLIC_KEY);

    int plain_length = 0;
    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
        if (memcmp(&announce->self_requests[i].req_id, &request_id, REQUEST_ID_SIZE) == 0) {
            plain_length = unwrap_gc_announce_packet(ENC_KEY(announce->self_requests[i].long_pk),
                                                     ENC_KEY(announce->self_requests[i].long_sk),
                                                     public_key, data, packet[0], packet, length);
            break;
        }
    }

    if (plain_length > GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE || plain_length <= 0)
        return -1;

    uint64_t request_id_enc;
    bytes_to_U64(&request_id_enc, data + plain_length - REQUEST_ID_SIZE);

    if (memcmp(&request_id, &request_id_enc, REQUEST_ID_SIZE)!=0)
        return -1;

    GC_Announce_Node nodes[MAX_SENT_ANNOUNCED_NODES];
    uint32_t num_nodes;
    bytes_to_U32(&num_nodes, data + 1);
    memcpy(nodes, data + 1 + sizeof(uint32_t), sizeof(GC_Announce_Node) * num_nodes);

    if (i == add_requested_gc_nodes(announce, nodes, request_id, num_nodes)) {
        fprintf(stderr, "handle_gc_get_announced_nodes_response SUCCESS\n");
        return 0;
    }
    fprintf(stderr, "handle_gc_get_announced_nodes_response FAIL\n");
    return -1;
}

/* Function to get announced nodes, should be used for get_announced_nodes_response.
 * Returns announced nodes number, fills up nodes array.
 */
int get_gc_announced_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    int i, j = 0;

    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (ipport_isset(&announce->announcements[i].node.ip_port)
            && id_long_equal(announce->announcements[i].chat_id, chat_id)) {
            memcpy(nodes[j].client_id, announce->announcements[i].node.client_id, EXT_PUBLIC_KEY);
            ipport_copy(&nodes[j].ip_port, &announce->announcements[i].node.ip_port);

            if (++j == MAX_SENT_ANNOUNCED_NODES)
                return j;
        }
    }

    return j;
}

/* This function should be used when handling announce request.
 * Add announced nodes to announce->announcements.
 */
int add_gc_announced_node(GC_Announce *announce, const uint8_t *chat_id, const GC_Announce_Node node,
                          uint64_t timestamp)
{
    int i, oldest_idx = 0;
    uint64_t oldest_announce = unix_time();  // TODO: What is this used for?

    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (oldest_announce > announce->announcements[i].timestamp) {
            oldest_announce = announce->announcements[i].timestamp;
            oldest_idx = i;
        }

        if (id_long_equal(announce->announcements[i].node.client_id, node.client_id)
            && id_long_equal(announce->announcements[i].chat_id, chat_id)) {
            announce->announcements[i].timestamp = timestamp;
            ipport_copy(&announce->announcements[i].node.ip_port, &node.ip_port);
            return i;
        }

        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            memcpy(announce->announcements[i].node.client_id, node.client_id, EXT_PUBLIC_KEY);
            memcpy(announce->announcements[i].chat_id, chat_id, EXT_PUBLIC_KEY);
            ipport_copy(&announce->announcements[i].node.ip_port, &node.ip_port);
            announce->announcements[i].timestamp = timestamp;
            return i;
        }
    }

    memcpy(announce->announcements[i].node.client_id, node.client_id, EXT_PUBLIC_KEY);
    memcpy(announce->announcements[i].chat_id, chat_id, EXT_PUBLIC_KEY);
    ipport_copy(&announce->announcements[i].node.ip_port, &node.ip_port);
    announce->announcements[i].timestamp = timestamp;

    return oldest_idx;
}

/* Add new self request.
 * Returns array index.
 */
int new_announce_self_request(GC_Announce *announce, const uint8_t *chat_id, uint64_t req_id, uint64_t timestamp,
                              const uint8_t *self_long_pk, const uint8_t *self_long_sk)
{
    int i;

    for (i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
        if (announce->self_requests[i].req_id == 0) {
            announce->self_requests[i].ready = 0;
            announce->self_requests[i].req_id = req_id;
            announce->self_requests[i].timestamp = timestamp;
            memcpy(announce->self_requests[i].chat_id, chat_id, EXT_PUBLIC_KEY);
            memcpy(announce->self_requests[i].long_pk, self_long_pk, EXT_PUBLIC_KEY);
            memcpy(announce->self_requests[i].long_sk, self_long_sk, EXT_PUBLIC_KEY);
            ++announce->req_num;
            return i;
        }
    }
}

/* Get group chat online members, which you searched for with get announced nodes request */
int gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    int i, j, k = 0;

    for (i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
        if (!id_long_equal(announce->self_requests[i].chat_id, chat_id))
            continue;

        if (! (announce->self_requests[i].ready == 1 && announce->self_requests[i].req_id != 0) )
            continue;

        for (j = 0; j < MAX_SENT_ANNOUNCED_NODES; j++) {
            if (ipport_isset(&announce->self_requests[i].nodes[j].ip_port)) {
                memcpy(nodes[k].client_id, announce->self_requests[i].nodes[j].client_id, EXT_PUBLIC_KEY);
                ipport_copy(&nodes[k].ip_port, &announce->self_requests[i].nodes[j].ip_port);
                k++;
            }
        }
    }

    return k;
}

/* Add requested online chat members.
 * Returns index of self_requests array.
 */
int add_requested_gc_nodes(GC_Announce *announce, const GC_Announce_Node *node, uint64_t req_id, uint32_t nodes_num)
{
    int i;
    uint32_t j;

    for (i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
        if (memcmp(&announce->self_requests[i].req_id, &req_id, REQUEST_ID_SIZE) != 0)
            continue;

        for (j = 0; j < nodes_num; j++) {
            if (ipport_isset(&node[j].ip_port)) {
                memcpy(announce->self_requests[i].nodes[j].client_id, node[j].client_id, EXT_PUBLIC_KEY);
                ipport_copy(&announce->self_requests[i].nodes[j].ip_port, &node[j].ip_port);
            }

            announce->self_requests[i].ready = 1;
        }
    }

    return i;
}

void do_gca(GC_Announce *announce)
{
    int i;

    /* Reset ip_port for those announced nodes, which expired */
    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (is_timeout(announce->announcements[i].timestamp, GC_ANNOUNCE_EXPIRATION))
            ipport_reset(&announce->announcements[i].node.ip_port);
    }

    for (i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
        if (is_timeout(announce->self_requests[i].timestamp, GC_ANNOUNCE_EXPIRATION)
            && announce->self_requests[i].req_id != 0) {
            announce->self_requests[i].req_id = 0;
            --announce->req_num;
        }
    }
}

GC_Announce *new_gca(DHT *dht)
{
    GC_Announce *announce = calloc(1, sizeof(GC_Announce));

    if (announce == NULL)
        return NULL;

    announce->dht = dht;
    announce->req_num = 0;
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, &handle_gc_announce_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, &handle_gc_get_announced_nodes_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES, &handle_gc_get_announced_nodes_response, announce);

    return announce;
}

void kill_gca(GC_Announce *announce)
{
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES, NULL, NULL);

    free(announce);
}
