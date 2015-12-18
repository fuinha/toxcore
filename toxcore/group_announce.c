/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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
#include <stdbool.h>

#include "Messenger.h"
#include "logger.h"
#include "util.h"
#include "network.h"
#include "DHT.h"

#include "group_announce.h"
#include "group_chats.h"

#define RAND_ID_SIZE (sizeof(uint64_t))

/* type + sender_dht_pk + nonce + */
#define GCA_HEADER_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES)

/* type + ping_id */
#define GCA_PING_REQUEST_PLAIN_SIZE (1 + RAND_ID_SIZE)
#define GCA_PING_REQUEST_DHT_SIZE (GCA_HEADER_SIZE + ENC_PUBLIC_KEY + GCA_PING_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

/* type + ping_id */
#define GCA_PING_RESPONSE_PLAIN_SIZE (1 + RAND_ID_SIZE)
#define GCA_PING_RESPONSE_DHT_SIZE (GCA_HEADER_SIZE + GCA_PING_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define GCA_PING_INTERVAL 60
#define GCA_NODES_EXPIRATION (GCA_PING_INTERVAL * 3 + 10)
#define MAX_GCA_PACKET_SIZE 1024

static int print_nodes(const Node_format *nodes, unsigned int num)
{
    unsigned int i;

    for (i = 0; i < num; ++i) {
        fprintf(stderr, "Key: %s\nIP: %s\n", id_toa(nodes[i].public_key), ip_ntoa(&nodes[i].ip_port.ip));
    }
}

/* Returns true if IP_Port is set as invalid */
bool ipport_is_bad(const IP_Port *ip_port)
{
    return ip_port->ip.ip4.uint32 == GC_BAD_IP_PORT || ip_port->port == 0;
}

/* Copies your own ip_port structure to dest. (TODO: This should probably go somewhere else) */
void ipport_self_copy(const DHT *dht, IP_Port *dest)
{
    size_t i;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (ipport_isset(&dht->close_clientlist[i].assoc4.ret_ip_port)) {
            ipport_copy(dest, &dht->close_clientlist[i].assoc4.ret_ip_port);
            break;
        }

        if (ipport_isset(&dht->close_clientlist[i].assoc6.ret_ip_port)) {
            ipport_copy(dest, &dht->close_clientlist[i].assoc6.ret_ip_port);
            break;
        }
    }

    /* Fill with dummy data and indicate that this is a bad IP */
    if (!ipport_isset(dest)) {
        memset(dest, 0, sizeof(IP_Port));
        dest->ip.family = AF_INET;
        dest->ip.ip4.uint32 = GC_BAD_IP_PORT;
    }
}

/* Creates a Node_format using your own public_key and IP_Port */
void make_self_gca_node(const DHT *dht, Node_format *node, const uint8_t *public_key)
{
    ipport_self_copy(dht, &node->ip_port);
    memcpy(node->public_key, public_key, ENC_PUBLIC_KEY);
}

/* Removes plaintext header and decrypts packets.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int unwrap_gca_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key,
                             uint8_t *data, size_t data_size, uint8_t packet_type, const uint8_t *packet, uint16_t length)
{
    if (id_equal(packet + 1, self_public_key)) {
        fprintf(stderr, "Announce unwrap failed: id_equal failed\n");
        return -1;
    }

    if (public_key)
        memcpy(public_key, packet + 1, ENC_PUBLIC_KEY);

    size_t header_len = GCA_HEADER_SIZE;
    uint8_t nonce[crypto_box_NONCEBYTES];

    if (packet_type == NET_PACKET_GCA_SEND_NODES) {
        header_len += RAND_ID_SIZE;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, crypto_box_NONCEBYTES);
    } else if (packet_type == NET_PACKET_GCA_PING_REQUEST) {
        header_len += ENC_PUBLIC_KEY;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);
    } else {
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);
    }

    if (length <= header_len + crypto_box_MACBYTES) {
        fprintf(stderr, "Announce unwrap failed: Encrypted length is too small %d\n", length);
        return -1;
    }

    size_t plain_len = length - header_len - crypto_box_MACBYTES;

    if (plain_len > data_size) {
        fprintf(stderr, "Announce unwrap failed: plain len (%lu) is larger than data_len (%lu)\n", plain_len, data_size);
        return -1;
    }

    uint8_t plain[plain_len];
    int len = decrypt_data(public_key, self_secret_key, nonce, packet + header_len, length - header_len, plain);

    if (len != plain_len) {
        fprintf(stderr, "Announce unwrap failed: length is %d, type is %u\n", len, plain[0]);
        return -1;
    }

    if (plain[0] != packet_type) {
        fprintf(stderr, "Announce unwrap failed with wrong packet type %d - expected %d\n", plain[0], packet_type);
        return -1;
    }

    memcpy(data, plain, len);
    return len;
}

/* Encrypts data of length and adds a plaintext header containing the packet type,
 * public encryption key of the sender, and the nonce used to encrypt data.
 */
static int wrap_gca_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key,
                           const uint8_t *recv_public_key, uint8_t *packet, uint32_t packet_size,
                           const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (packet_size < length + GCA_HEADER_SIZE + crypto_box_MACBYTES)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[length + crypto_box_MACBYTES];
    int len = encrypt_data(recv_public_key, send_secret_key, nonce, data, length, encrypt);

    if (len != sizeof(encrypt)) {
        fprintf(stderr, "Announce encrypt failed\n");
        return -1;
    }

    packet[0] = packet_type;
    memcpy(packet + 1, send_public_key, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + GCA_HEADER_SIZE, encrypt, len);

    return GCA_HEADER_SIZE + len;
}

static void remove_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id);
static int store_gca_announcement(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *data,
                                  uint32_t data_len, bool self);

/* Sends a TCP group announce packet to MAX_GCA_SENT_NODES random TCP relays.
 *
 * Returns number of sent packets.
 */
static size_t send_gca_tcp_packet(GC_Announce *announce, const uint8_t *data, uint16_t data_len, uint8_t packet_type)
{
    if (announce->m == NULL)
        return 0;

    uint8_t packet[data_len + GCA_HEADER_SIZE + crypto_box_MACBYTES];
    Node_format nodes[MAX_GCA_SENT_NODES];
    unsigned int i, num_tcp = tcp_copy_connected_relays(announce->m->net_crypto->tcp_c, nodes, MAX_GCA_SENT_NODES);
    size_t sent = 0;

    for (i = 0; i < num_tcp && i < MAX_GCA_SENT_NODES; ++i) {
        int tcp_connections_num = get_random_tcp_substitute_conn_number(announce->m->net_crypto->tcp_c);

        if (tcp_connections_num == -1)
            continue;

        nodes[i].ip_port.ip.family = TCP_FAMILY;
        nodes[i].ip_port.ip.ip4.uint32 = tcp_connections_num;

        int packet_len = wrap_gca_packet(announce->tcp_public_key, announce->tcp_secret_key,
                                         nodes[i].public_key, packet, sizeof(packet),
                                         data, data_len, packet_type);
        if (packet_len == -1)
            continue;

        if (tcp_send_group_announce(announce->tcp_conn, tcp_connections_num, packet, packet_len,
                                    TCP_PACKET_GC_ANNOUNCE_REQUEST) != -1) {
            ++sent;
        }
    }

    fprintf(stderr, "sent: %lu\n", sent);
    return sent;
}

/* Send a node announcement packet to our close nodes or store the node if we are the closest node.
 *
 * Returns number of packets sent.
 */
static size_t send_gca_packet_announce(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *origin_pk,
                                       const uint8_t *self_pk, const uint8_t *data, uint32_t data_len, bool self)
{
    uint8_t packet[data_len + GCA_HEADER_SIZE + crypto_box_MACBYTES];
    Node_format nodes[MAX_GCA_SENT_NODES];
    uint32_t nclosest = get_close_nodes(announce->dht, chat_id, nodes, 0, 1, 1);

    /* No DHT nodes, use TCP nodes as fallback */
    if (nclosest == 0) {
        return send_gca_tcp_packet(announce, data, data_len, NET_PACKET_GCA_ANNOUNCE);
    }

    size_t i, sent = 0;

    /* Relay announce request to all nclosest nodes */
    for (i = 0; i < nclosest && i < MAX_GCA_SENT_NODES; ++i) {
        if (origin_pk && id_equal(origin_pk, nodes[i].public_key))
            continue;

        if (id_closest(chat_id, nodes[i].public_key, self_pk) != 1)
            continue;

        int packet_len = wrap_gca_packet(announce->dht->self_public_key, announce->dht->self_secret_key,
                                         nodes[i].public_key, packet, sizeof(packet), data, data_len,
                                         NET_PACKET_GCA_ANNOUNCE);
        if (packet_len == -1)
            continue;

        if (sendpacket(announce->dht->net, nodes[i].ip_port, packet, packet_len) != -1)
            ++sent;
    }

    /* Add to announcements if we're the closest node to chat_id */
    if (sent == 0) {
        if (store_gca_announcement(announce, chat_id, data, data_len, self) == 0)
            return 1;
    }

    return sent;
}

static size_t send_gca_packet_get_nodes(GC_Announce* announce, const uint8_t *chat_id, const uint8_t *origin_pk,
                                        const uint8_t *self_pk, const uint8_t *data, uint32_t data_len, bool self)
{
    Node_format nodes[MAX_SENT_NODES];
    uint32_t nclosest = get_close_nodes(announce->dht, chat_id, nodes, 0, 1, 1);

    /* No DHT nodes, use TCP nodes instead */
    if (nclosest == 0) {
        return send_gca_tcp_packet(announce, data, data_len, NET_PACKET_GCA_GET_NODES);
    }

    uint8_t packet[data_len + GCA_HEADER_SIZE + crypto_box_MACBYTES];
    uint32_t i;
    uint16_t sent = 0;

    for (i = 0; i < nclosest && i < MAX_SENT_NODES; ++i) {
        if (!self && id_closest(chat_id, nodes[i].public_key, self_pk) != 1)
            continue;

        int packet_len = wrap_gca_packet(announce->dht->self_public_key, announce->dht->self_secret_key,
                                         nodes[i].public_key, packet, sizeof(packet), data, data_len,
                                         NET_PACKET_GCA_GET_NODES);
        if (packet_len == -1)
            continue;

        if (sendpacket(announce->dht->net, nodes[i].ip_port, packet, packet_len) != -1)
            ++sent;
    }

    return sent;
}

/* Dispatches a group announcement packet.
 *
 * Returns the number of sent packets on success.
 * Returns -1 if no packets were sent.
 */
static int dispatch_packet(GC_Announce* announce, const uint8_t *chat_id, const uint8_t *origin_pk,
                           const uint8_t *self_pk, const uint8_t *data, uint32_t length, uint8_t packet_type,
                           bool self)
{
    size_t ret = 0;

    if (packet_type == NET_PACKET_GCA_ANNOUNCE) {
        ret = send_gca_packet_announce(announce, chat_id, origin_pk, self_pk, data, length, self);
    } else if (packet_type == NET_PACKET_GCA_GET_NODES) {
        ret = send_gca_packet_get_nodes(announce, chat_id, origin_pk, self_pk, data, length, self);
    }

    return (ret == 0) ? -1 : ret;
}

/* Add requested online chat members to announce->requests
 *
 * Returns index of match on success.
 * Returns -1 if no match is found for req_id.
 */
static int add_requested_gc_nodes(GC_Announce *announce, const Node_format *nodes, uint32_t nodes_num,
                                  const Node_format *tcp_nodes, unsigned int num_tcp_nodes, uint64_t req_id)
{
    size_t i, num = 0;
    uint32_t j;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id != req_id)
            continue;

        for (j = 0; j < nodes_num && j < MAX_GCA_SENT_NODES; ++j) {
            if (!ipport_isset(&nodes[j].ip_port))
                continue;

            if (!id_equal(announce->requests[i].self_public_key, nodes[j].public_key)) {
                memcpy(&announce->requests[i].nodes[num++], &nodes[j], sizeof(Node_format));
                announce->requests[i].ready = true;

                if (num_tcp_nodes && !announce->requests[i].num_tcp_nodes) {
                    announce->requests[i].num_tcp_nodes = num_tcp_nodes;
                    memcpy(announce->requests[i].tcp_nodes, tcp_nodes, num_tcp_nodes * sizeof(Node_format));
                }
            }
        }

        if (announce->requests[i].ready && announce->update_addresses)
            (*announce->update_addresses)(announce, announce->requests[i].chat_id, announce->update_addresses_obj);

        return i;
    }

    return -1;
}

static size_t add_announced_nodes_helper(GC_Announce *announce, const uint8_t *chat_id, const Node_format node,
                                         size_t idx, const uint8_t *packet_data, uint32_t length,
                                         const Node_format *tcp_nodes, unsigned int num_tcp_nodes, bool self)
{
    memcpy(&announce->announcements[idx].node, &node, sizeof(Node_format));
    memcpy(announce->announcements[idx].chat_id, chat_id, CHAT_ID_SIZE);
    announce->announcements[idx].last_rcvd_ping = unix_time();
    announce->announcements[idx].last_sent_ping = unix_time();
    announce->announcements[idx].time_added = unix_time();
    announce->announcements[idx].self = self;

    if (num_tcp_nodes) {
        num_tcp_nodes = MIN(num_tcp_nodes, MAX_GCA_TCP_NODES);
        memcpy(announce->announcements[idx].tcp_nodes, tcp_nodes, num_tcp_nodes * sizeof(Node_format));
        announce->announcements[idx].num_tcp_nodes = num_tcp_nodes;
    }

    return idx;
}

/* Add announced node to announcements. If no slots are free replace the oldest node.
 *
 * Returns index of added node.
 */
static size_t add_gc_announced_node(GC_Announce *announce, const uint8_t *chat_id, const Node_format node,
                                    const uint8_t *packet_data, uint32_t length, const Node_format *tcp_nodes,
                                    unsigned int num_tcp_nodes, bool self)
{
    size_t i, oldest_idx = 0;
    uint64_t oldest_announce = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (oldest_announce < announce->announcements[i].time_added) {
            oldest_announce = announce->announcements[i].time_added;
            oldest_idx = i;
        }

        if (id_equal(announce->announcements[i].node.public_key, node.public_key)
            && chat_id_equal(announce->announcements[i].chat_id, chat_id))
            return add_announced_nodes_helper(announce, chat_id, node, i, packet_data, length, tcp_nodes, num_tcp_nodes, self);

        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            return add_announced_nodes_helper(announce, chat_id, node, i, packet_data, length, tcp_nodes, num_tcp_nodes, self);
    }

    return add_announced_nodes_helper(announce, chat_id, node, oldest_idx, packet_data, length, tcp_nodes, num_tcp_nodes, self);
}

/* Unpacks an announcement node and stores it in our announcements.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int store_gca_announcement(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *data,
                                  uint32_t data_len, bool self)
{
    Node_format tcp_nodes[MAX_GCA_TCP_NODES];
    uint16_t node_len = 0;
    Node_format node;

    if (unpack_nodes(&node, 1, &node_len, data + 1 + CHAT_ID_SIZE, data_len - 1 - CHAT_ID_SIZE, 0) != 1) {
        return -1;
    }

    int num_tcp_nodes = unpack_nodes(tcp_nodes, MAX_GCA_TCP_NODES, 0, data + 1 + CHAT_ID_SIZE + node_len,
                                     data_len - 1 - CHAT_ID_SIZE - node_len, 1);
    if (num_tcp_nodes == -1) {
        return -1;
    }

    add_gc_announced_node(announce, chat_id, node, data, data_len, tcp_nodes, num_tcp_nodes, self);

    /* We will never need to ping or renew our own announcement */
    if (self)
        remove_gca_self_announce(announce, chat_id);

    return 0;
}

/* Gets up to MAX_GCA_SENT_NODES nodes that hold chat_id from announcements and add them to nodes array.
 * Copies up to MAX_GCA_TCP_NODES tcp nodes to tcp_nodes as well.
 *
 * Returns the number of added nodes.
 */
static uint32_t get_gc_announced_nodes(GC_Announce *announce, const uint8_t *chat_id, Node_format *nodes,
                                       Node_format *tcp_nodes, unsigned int *num_tcp_nodes)
{
    size_t i;
    uint32_t num = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (chat_id_equal(announce->announcements[i].chat_id, chat_id)) {
            memcpy(&nodes[num], &announce->announcements[i].node, sizeof(Node_format));

            if (*num_tcp_nodes == 0 && announce->announcements[i].num_tcp_nodes) {
                *num_tcp_nodes = announce->announcements[i].num_tcp_nodes;
                memcpy(tcp_nodes, announce->announcements[i].tcp_nodes, *num_tcp_nodes * sizeof(Node_format));
            }

            if (++num == MAX_GCA_SENT_NODES)
                break;
        }
    }

    return num;
}

/* Initiates requests holder for our nodes request responses for chat_id.
 * If all slots are full the oldest entry is replaced.
 */
static void init_gca_self_request(GC_Announce *announce, const uint8_t *chat_id, uint64_t req_id,
                                  const uint8_t *self_public_key, const uint8_t *self_secret_key)
{
    size_t i, idx = 0;
    uint64_t oldest_req = 0;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id == 0) {
            idx = i;
            break;
        }

        if (oldest_req < announce->requests[i].time_added) {
            oldest_req = announce->requests[i].time_added;
            idx = i;
        }
    }

    memset(&announce->requests[idx], 0, sizeof(struct GC_AnnounceRequest));
    announce->requests[idx].req_id = req_id;
    announce->requests[idx].time_added = unix_time();
    memcpy(announce->requests[idx].chat_id, chat_id, CHAT_ID_SIZE);
    memcpy(announce->requests[idx].self_public_key, self_public_key, ENC_PUBLIC_KEY);
    memcpy(announce->requests[idx].self_secret_key, self_secret_key, ENC_SECRET_KEY);
}

/* Adds our own announcement to self_announce.
 *
 * Returns array index on success.
 * Returns -1 if self_announce is full.
 */
static int add_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *self_public_key,
                                 const uint8_t *self_secret_key, const Node_format *tcp_nodes, unsigned int num_tcp_nodes)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            announce->self_announce[i].last_rcvd_ping = unix_time();
            announce->self_announce[i].is_set = true;
            memcpy(announce->self_announce[i].chat_id, chat_id, CHAT_ID_SIZE);
            memcpy(announce->self_announce[i].self_public_key, self_public_key, ENC_PUBLIC_KEY);
            memcpy(announce->self_announce[i].self_secret_key, self_secret_key, ENC_SECRET_KEY);

            if (num_tcp_nodes) {
                num_tcp_nodes = MIN(num_tcp_nodes, MAX_GCA_TCP_NODES);
                memcpy(announce->self_announce[i].tcp_nodes, tcp_nodes, num_tcp_nodes * sizeof(Node_format));
                announce->self_announce[i].num_tcp_nodes = num_tcp_nodes;
            }

            return i;
        }
    }

    return -1;
}

/* Removes all instances of chat_id from self_announce. */
static void remove_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set)
            continue;

        if (chat_id_equal(announce->self_announce[i].chat_id, chat_id))
            memset(&announce->self_announce[i], 0, sizeof(struct GC_AnnouncedSelf));
    }
}

/* Returns true if a self announce entry exists containing chat_id/self_public_key.
 * Returns false otherwise.
 */
static bool gca_self_announce_set(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *public_key)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set)
            continue;

        if (chat_id_equal(announce->self_announce[i].chat_id, chat_id)
                && id_equal(announce->self_announce[i].self_public_key, public_key)) {
            return true;
        }
    }

    return false;
}

/* Announce a new group chat.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_announce_request(GC_Announce *announce, const uint8_t *self_public_key, const uint8_t *self_secret_key,
                              const uint8_t *chat_id, const Node_format *tcp_nodes, unsigned int num_tcp_nodes)
{
    DHT *dht = announce->dht;

    if (gca_self_announce_set(announce, chat_id, self_public_key))
        return 0;

    add_gca_self_announce(announce, chat_id, self_public_key, self_secret_key, tcp_nodes, num_tcp_nodes);

    /* packet contains: type, chat_id, self_node, tcp nodes */
    uint8_t data[1 + CHAT_ID_SIZE + sizeof(Node_format) + (sizeof(Node_format) * num_tcp_nodes)];
    data[0] = NET_PACKET_GCA_ANNOUNCE;
    memcpy(data + 1, chat_id, CHAT_ID_SIZE);
    uint32_t length = 1 + CHAT_ID_SIZE;

    Node_format self_node;
    make_self_gca_node(dht, &self_node, self_public_key);

    int node_size = pack_nodes(data + length, sizeof(data) - length, &self_node, 1);
    length += node_size;

    if (node_size == -1)
        return -1;

    int tcp_nodes_size = pack_nodes(data + length, sizeof(data) - length, tcp_nodes, num_tcp_nodes);
    length += tcp_nodes_size;

    if (tcp_nodes_size == -1)
        return -1;

    if ((node_size + tcp_nodes_size) <= 0)
        return -1;

    if (length > MAX_GCA_PACKET_SIZE)
        return -1;

    return dispatch_packet(announce, chat_id, NULL, dht->self_public_key, data, length, NET_PACKET_GCA_ANNOUNCE, true);
}

/* Attempts to relay an announce request to close nodes.
 * If we are the closest node store the node in announcements (this happens in send_gca_packet_announce)
 */
int handle_gca_announce_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    GC_Announce* announce = object;
    DHT *dht = announce->dht;

    if (length <=  GCA_HEADER_SIZE + crypto_box_MACBYTES || length > MAX_GCA_PACKET_SIZE)
        return -1;

    uint16_t data_length = length - (GCA_HEADER_SIZE + crypto_box_MACBYTES);
    uint16_t d_header_len = 1 + CHAT_ID_SIZE;

    if (data_length <= d_header_len)
        return -1;

    uint8_t data[data_length];
    uint8_t origin_pk[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, origin_pk, data,
                                         sizeof(data), packet[0], packet, length);

    if (plain_length != sizeof(data)) {
        fprintf(stderr, "unwrap failed in handle_gca_announce_request (plain_length: %d, data size: %lu)\n", plain_length, sizeof(data));
        return -1;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data + 1, CHAT_ID_SIZE);

    return dispatch_packet(announce, chat_id, origin_pk, dht->self_public_key, data, plain_length,
                           NET_PACKET_GCA_ANNOUNCE, false);
}

/* Creates a DHT request for nodes that hold announcements for chat_id.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_get_nodes_request(GC_Announce* announce, const uint8_t *self_public_key, const uint8_t *self_secret_key,
                               const uint8_t *chat_id)
{
    DHT *dht = announce->dht;

    /* packet contains: type, chat_id, request_id, node */
    uint8_t data[1 + CHAT_ID_SIZE + RAND_ID_SIZE + sizeof(Node_format)];
    data[0] = NET_PACKET_GCA_GET_NODES;
    memcpy(data + 1, chat_id, CHAT_ID_SIZE);
    uint32_t length = 1 + CHAT_ID_SIZE;

    uint64_t request_id = random_64b();
    U64_to_bytes(data + length, request_id);
    length += RAND_ID_SIZE;

    Node_format self_node;
    make_self_gca_node(dht, &self_node, self_public_key);

    int node_len = pack_nodes(data + length, sizeof(data) - length, &self_node, 1);
    length += node_len;

    if (node_len <= 0) {
        fprintf(stderr, "pack_nodes failed in send_get_nodes_request\n");
        return -1;
    }

    init_gca_self_request(announce, chat_id, request_id, self_public_key, self_secret_key);

    return dispatch_packet(announce, chat_id, NULL, dht->self_public_key, data, length, NET_PACKET_GCA_GET_NODES, true);
}

/* Sends nodes that hold chat_id to node that requested them */
static int send_gca_get_nodes_response(DHT *dht, uint64_t request_id, IP_Port ipp, const uint8_t *receiver_pk,
                                       const Node_format *nodes, uint32_t num_nodes, const Node_format *tcp_nodes,
                                       unsigned int num_tcp_nodes)
{
    /* packet contains: type, num_nodes, nodes, num_tcp_nodes, tcp_nodes, request_id */
    uint8_t data[1 + (sizeof(uint32_t) * 2) + (sizeof(Node_format) * (num_nodes + num_tcp_nodes)) + RAND_ID_SIZE];
    data[0] = NET_PACKET_GCA_SEND_NODES;
    U32_to_bytes(data + 1, num_nodes);
    uint32_t plain_length = 1 + sizeof(uint32_t);

    int nodes_len = pack_nodes(data + plain_length, sizeof(data) - plain_length, nodes, num_nodes);
    plain_length += nodes_len;

    if (nodes_len <= 0) {
        fprintf(stderr, "pack_gca_nodes failed in send_gca_get_nodes_response (%d)\n", nodes_len);
        return -1;
    }

    U32_to_bytes(data + plain_length, num_tcp_nodes);
    plain_length += sizeof(uint32_t);

    int tcp_nodes_len = pack_nodes(data + plain_length, sizeof(data) - plain_length, tcp_nodes, num_tcp_nodes);

    /* Non-critical, try to work past it */
    if (tcp_nodes_len == -1) {
        fprintf(stderr, "pack_gca_nodes failed in send_gca_get_nodes_response for tcp (%d)\n", nodes_len);
        tcp_nodes_len = 0;
        U32_to_bytes(data + plain_length - sizeof(uint32_t), 0);
    }

    plain_length += tcp_nodes_len;
    U64_to_bytes(data + plain_length, request_id);
    plain_length += RAND_ID_SIZE;

    uint8_t packet[plain_length + RAND_ID_SIZE + GCA_HEADER_SIZE + crypto_box_MACBYTES];
    int packet_length = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, receiver_pk, packet,
                                        sizeof(packet), data, plain_length, NET_PACKET_GCA_SEND_NODES);
    if (packet_length == -1) {
        fprintf(stderr, "wrap failed in send_gca_get_nodes_response\n");
        return -1;
    }

    /* insert request_id into packet header after the packet type and dht_pk */
    memmove(packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, packet + 1 + ENC_PUBLIC_KEY, packet_length - 1 - ENC_PUBLIC_KEY);
    U64_to_bytes(packet + 1 + ENC_PUBLIC_KEY, request_id);
    packet_length += RAND_ID_SIZE;

    return sendpacket(dht->net, ipp, packet, packet_length);
}

int handle_gc_get_announced_nodes_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    GC_Announce *announce = object;
    DHT *dht = announce->dht;

    if (length <= GCA_HEADER_SIZE + crypto_box_MACBYTES || length > MAX_GCA_PACKET_SIZE)
        return -1;

    uint16_t data_length = length - (GCA_HEADER_SIZE + crypto_box_MACBYTES);
    uint16_t d_header_len = 1 + CHAT_ID_SIZE + RAND_ID_SIZE;

    if (data_length <= d_header_len)
        return -1;

    uint8_t data[data_length];
    uint8_t origin_pk[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, origin_pk, data,
                                         sizeof(data), packet[0], packet, length);

    if (plain_length != sizeof(data)) {
        fprintf(stderr, "unwrap failed in handle_gc_get_announced_nodes_request %d\n", plain_length);
        return -1;
    }

    Node_format node;
    if (unpack_nodes(&node, 1, 0, data + d_header_len, plain_length - d_header_len, 0) != 1) {
        fprintf(stderr, "unpack failed in handle_gc_get_announced_nodes_request\n");
        return -1;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data + 1, CHAT_ID_SIZE);

    unsigned int num_tcp_nodes = 0;
    Node_format nodes[MAX_GCA_SENT_NODES];
    Node_format tcp_nodes[MAX_GCA_TCP_NODES];
    uint32_t num_nodes = get_gc_announced_nodes(announce, chat_id, nodes, tcp_nodes, &num_tcp_nodes);

    if (num_nodes) {
        uint64_t request_id = 0;
        bytes_to_U64(&request_id, data + 1 + CHAT_ID_SIZE);
        return send_gca_get_nodes_response(dht, request_id, node.ip_port, node.public_key, nodes, num_nodes,
                                           tcp_nodes, num_tcp_nodes);
    }

    return dispatch_packet(announce, chat_id, origin_pk, dht->self_public_key, data, plain_length, NET_PACKET_GCA_GET_NODES, false);
}

int handle_gca_get_nodes_response(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    GC_Announce *announce = object;
    DHT *dht = announce->dht;

    if (length <= GCA_HEADER_SIZE + crypto_box_MACBYTES + RAND_ID_SIZE || length > MAX_GCA_PACKET_SIZE)
        return -1;

    uint16_t data_length = length - (GCA_HEADER_SIZE + crypto_box_MACBYTES + RAND_ID_SIZE);

    if (data_length <= 1 + sizeof(uint32_t) + RAND_ID_SIZE)
        return -1;

    uint8_t data[data_length];
    uint8_t public_key[ENC_PUBLIC_KEY];

    uint64_t request_id;
    bytes_to_U64(&request_id, packet + 1 + ENC_PUBLIC_KEY);

    int plain_length = 0;
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id == request_id) {
            plain_length = unwrap_gca_packet(announce->requests[i].self_public_key,
                                             announce->requests[i].self_secret_key,
                                             public_key, data, sizeof(data),
                                             packet[0], packet, length);
            break;
        }
    }

    if (plain_length != sizeof(data))
        return -1;

    uint64_t request_id_enc;
    bytes_to_U64(&request_id_enc, data + plain_length - RAND_ID_SIZE);

    if (request_id != request_id_enc)
        return -1;

    uint32_t num_nodes = 0;
    bytes_to_U32(&num_nodes, data + 1);

    /* this should never happen so assume it's malicious and ignore */
    if (num_nodes > MAX_GCA_SENT_NODES || num_nodes == 0)
        return -1;

    uint16_t nodes_size = 0;
    Node_format nodes[num_nodes];
    int num_packed = unpack_nodes(nodes, num_nodes, &nodes_size, data + 1 + sizeof(uint32_t),
                                  plain_length - 1 - sizeof(uint32_t), 0);

    if (num_packed != num_nodes) {
        fprintf(stderr, "unpack failed in handle_gca_get_nodes_response (got %d, expected %d)\n", num_packed, num_nodes);
        return -1;
    }

    uint32_t num_tcp_nodes = 0;
    bytes_to_U32(&num_tcp_nodes, data + 1 + sizeof(uint32_t) + nodes_size);

    if (num_nodes > MAX_GCA_TCP_NODES)
        return -1;

    Node_format tcp_nodes[num_tcp_nodes];
    int num_tcp_packed = unpack_nodes(tcp_nodes, num_tcp_nodes, 0, data + 1 + (sizeof(uint32_t) * 2) + nodes_size,
                                      plain_length - 1 - (sizeof(uint32_t) * 2) - nodes_size, 1);

    if (num_tcp_packed != num_tcp_nodes)
        return -1;

    if (add_requested_gc_nodes(announce, nodes, num_nodes, tcp_nodes, num_tcp_nodes, request_id) == -1)
        return -1;

    return 0;
}

/* Retrieves nodes for chat_id (nodes must already be obtained via gca_send_announce_request).
 *
 * returns the number of nodes found.
 */
size_t gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, Node_format *nodes,
                               Node_format *tcp_nodes, unsigned int *num_tcp_nodes)
{
    size_t i, j, num = 0;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (! (announce->requests[i].ready == 1 && announce->requests[i].req_id != 0) )
            continue;

        if (!chat_id_equal(announce->requests[i].chat_id, chat_id))
            continue;

        for (j = 0; j < MAX_GCA_SENT_NODES; ++j) {
            if (ipport_isset(&announce->requests[i].nodes[j].ip_port)) {
                memcpy(&nodes[num], &announce->requests[i].nodes[j], sizeof(Node_format));

                if (*num_tcp_nodes == 0 && announce->requests[i].num_tcp_nodes) {
                    *num_tcp_nodes = announce->requests[i].num_tcp_nodes;
                    memcpy(tcp_nodes, announce->requests[i].tcp_nodes, *num_tcp_nodes * sizeof(Node_format));
                }

                if (++num == MAX_GCA_SENT_NODES)
                    return num;
            }
        }
    }

    return num;
}

int handle_gca_ping_response(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    GC_Announce *announce = object;
    DHT *dht = announce->dht;

    if (length != GCA_PING_RESPONSE_DHT_SIZE)
        return -1;

    uint8_t data[GCA_PING_RESPONSE_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];

    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, public_key, data,
                                         sizeof(data), packet[0], packet, length);

    if (plain_length != GCA_PING_RESPONSE_PLAIN_SIZE)
        return -1;

    uint64_t ping_id;
    memcpy(&ping_id, data + 1, RAND_ID_SIZE);

    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (announce->announcements[i].ping_id == ping_id) {
            announce->announcements[i].ping_id = 0;

            if (!ipport_isset(&announce->announcements[i].node.ip_port))
                return -1;

            announce->announcements[i].last_rcvd_ping = unix_time();
            return 0;
        }
    }

    return -1;
}

static int send_gca_ping_response(DHT *dht, IP_Port ipp, const uint8_t *data, const uint8_t *rcv_pk)
{
    uint8_t response[GCA_PING_RESPONSE_PLAIN_SIZE];
    response[0] = NET_PACKET_GCA_PING_RESPONSE;
    memcpy(response + 1, data + 1, GCA_PING_RESPONSE_PLAIN_SIZE - 1);

    uint8_t packet[GCA_PING_RESPONSE_DHT_SIZE];
    int len = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, rcv_pk, packet, sizeof(packet),
                              response, GCA_PING_RESPONSE_PLAIN_SIZE, NET_PACKET_GCA_PING_RESPONSE);
    if (len == -1)
        return -1;

    return sendpacket(dht->net, ipp, packet, len);
}

int handle_gca_ping_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    GC_Announce *announce = object;
    DHT *dht = announce->dht;

    if (length != GCA_PING_REQUEST_DHT_SIZE)
        return -1;

    uint8_t self_public_key[ENC_PUBLIC_KEY];
    memcpy(self_public_key, packet + 1 + ENC_PUBLIC_KEY, ENC_PUBLIC_KEY);

    size_t i;
    bool node_found = false;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set)
            continue;

        if (memcmp(self_public_key, announce->self_announce[i].self_public_key, ENC_PUBLIC_KEY) == 0) {
            node_found = true;
            break;
        }
    }

    if (!node_found) {
        fprintf(stderr, "handle announce ping request failed\n");
        return -1;
    }

    uint8_t data[GCA_PING_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht->self_public_key, announce->self_announce[i].self_secret_key,
                                         public_key, data, sizeof(data), packet[0], packet, length);

    if (plain_length != GCA_PING_REQUEST_PLAIN_SIZE) {
        fprintf(stderr, "handle ping request unwrap failed\n");
        return -1;
    }

    announce->self_announce[i].last_rcvd_ping = unix_time();

    return send_gca_ping_response(dht, ipp, data, public_key);
}

static int send_gca_ping_request(DHT *dht, Node_format *node, uint64_t ping_id)
{
    uint8_t data[GCA_PING_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GCA_PING_REQUEST;
    memcpy(data + 1, &ping_id, RAND_ID_SIZE);

    uint8_t packet[GCA_PING_REQUEST_DHT_SIZE];
    int len = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, node->public_key, packet,
                              sizeof(packet), data, GCA_PING_REQUEST_PLAIN_SIZE, NET_PACKET_GCA_PING_REQUEST);
    if (len == -1)
        return -1;

    /* insert recipient's public key into packet header after the packet type and dht_pk */
    memmove(packet + 1 + ENC_PUBLIC_KEY + ENC_PUBLIC_KEY, packet + 1 + ENC_PUBLIC_KEY, len - 1 - ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, node->public_key, ENC_PUBLIC_KEY);
    len += ENC_PUBLIC_KEY;

    return sendpacket(dht->net, node->ip_port, packet, len);
}

static void ping_gca_nodes(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (announce->announcements[i].self || !is_timeout(announce->announcements[i].last_sent_ping, GCA_PING_INTERVAL))
            continue;

        uint64_t ping_id = random_64b();
        announce->announcements[i].ping_id = ping_id;
        announce->announcements[i].last_sent_ping = unix_time();
        send_gca_ping_request(announce->dht, &announce->announcements[i].node, ping_id);
    }
}

/* Handles TCP announce packets.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_tcp_gca(void *object, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    IP_Port ip_port = {0};
    ip_port.ip.family = TCP_FAMILY;

    if (data[0] != NET_PACKET_GCA_SEND_NODES)
        return -1;

    return handle_gca_get_nodes_response(object, ip_port, data, length);
}

/* Inits a TCP connection for announcements.
 *
 * Returns number of relays connected to on success.
 * Returns -1 on failure.
 */
static int init_gca_tcp_connection(GC_Announce *announce)
{
    Messenger *m = announce->m;

    if (m == NULL) {
        return -1;
    }

    uint16_t num_relays = m->net_crypto->tcp_c->tcp_connections_length;
    Node_format tcp_relays[num_relays];
    unsigned int i, num = tcp_copy_connected_relays(m->net_crypto->tcp_c, tcp_relays, num_relays);

    if (num == 0) {
        return -1;
    }

    crypto_box_keypair(announce->tcp_public_key, announce->tcp_secret_key);
    announce->tcp_conn = new_tcp_connections(announce->tcp_secret_key, &m->options.proxy_info);

    if (announce->tcp_conn == NULL) {
        return -1;
    }

    for (i = 0; i < num; ++i) {
        add_tcp_relay_global(announce->tcp_conn, tcp_relays[i].ip_port, tcp_relays[i].public_key);
    }

    set_gc_announce_packet_tcp_connection_callback(announce->tcp_conn, &handle_tcp_gca, announce);

    return num;
}

static int kill_gca_tcp_connection(GC_Announce *announce)
{
    if (!announce->tcp_conn)
        return;

    kill_tcp_connections(announce->tcp_conn);
    memset(announce->tcp_public_key, 0, ENC_PUBLIC_KEY);
    memset(announce->tcp_secret_key, 0, ENC_SECRET_KEY);
}

/* Checks time of last received ping request for self announces and renews the announcement if necessary */
#define SELF_ANNOUNCE_TIMEOUT GCA_NODES_EXPIRATION
static void renew_gca_self_announces(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set)
            continue;

        if (is_timeout(announce->self_announce[i].last_rcvd_ping, SELF_ANNOUNCE_TIMEOUT)) {
            announce->self_announce[i].last_rcvd_ping = unix_time();
            announce->self_announce[i].is_set = false;
            gca_send_announce_request(announce, announce->self_announce[i].self_public_key,
                                      announce->self_announce[i].self_secret_key,
                                      announce->self_announce[i].chat_id,
                                      announce->self_announce[i].tcp_nodes,
                                      announce->self_announce[i].num_tcp_nodes);
        }
    }
}

static void check_gca_node_timeouts(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (!announce->announcements[i].self && is_timeout(announce->announcements[i].last_rcvd_ping, GCA_NODES_EXPIRATION))
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
    }
}

#define GCA_CONNECTION_SECONDS 5

void do_gca(GC_Announce *announce)
{
    if (announce->tcp_conn)
        do_tcp_connections(announce->tcp_conn);

    uint64_t t = unix_time();

    if (announce->last_run == t)
        return;

    ping_gca_nodes(announce);
    check_gca_node_timeouts(announce);
    renew_gca_self_announces(announce);

    if (announce->tcp_conn) {
        set_tcp_substitute_status(announce->tcp_conn, !DHT_non_lan_connected(announce->dht));
    } else if (announce->m) {
        init_gca_tcp_connection(announce);
    }

    announce->last_run = t;
}

/* Removes peer with public_key in chat_id's group from requests list */
void gca_peer_cleanup(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *peer_pk)
{
    size_t i, j;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (! (announce->requests[i].ready && announce->requests[i].req_id != 0) )
            continue;

        if (!chat_id_equal(announce->requests[i].chat_id, chat_id))
            continue;

        for (j = 0; j < MAX_GCA_SENT_NODES; ++j) {
            if (id_equal(announce->requests[i].nodes[j].public_key, peer_pk)) {
                memset(&announce->requests[i].nodes[j], 0, sizeof(Node_format));
                return;
            }
        }
    }
}

void gca_cleanup(GC_Announce *announce, const uint8_t *chat_id)
{
    size_t i;

    /* Remove self announcements for chat_id */
    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (announce->announcements[i].self && chat_id_equal(announce->announcements[i].chat_id, chat_id)) {
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
        }
    }

    remove_gca_self_announce(announce, chat_id);
}

GC_Announce *new_gca(DHT *dht)
{
    GC_Announce *announce = calloc(1, sizeof(GC_Announce));

    if (announce == NULL)
        return NULL;

    announce->dht = dht;
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_ANNOUNCE, &handle_gca_announce_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_GET_NODES, &handle_gc_get_announced_nodes_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_SEND_NODES, &handle_gca_get_nodes_response, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_REQUEST, &handle_gca_ping_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_RESPONSE, &handle_gca_ping_response, announce);

    return announce;
}

void kill_gca(GC_Announce *announce)
{
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_ANNOUNCE, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_GET_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_SEND_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_RESPONSE, NULL, NULL);;

    if (announce->tcp_conn) {
        set_gc_announce_packet_tcp_connection_callback(announce->tcp_conn, NULL, NULL);
        kill_gca_tcp_connection(announce);
        announce->tcp_conn = NULL;
    }

    free(announce);
}
