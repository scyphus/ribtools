/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: mrt.h,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $ */

#ifndef _MRT_H
#define _MRT_H

#include <stdint.h>
#include <stddef.h>

/*
 * http://tools.ietf.org/html/draft-ietf-grow-mrt-11
 */

#define MSG_BGP                 5       /* MRT only */
#define MSG_BGP4PLUS            9       /* MRT only */
#define MSG_TABLE_DUMP          12      /* dump bgp routes-mrt */
#define MSG_TABLE_DUMP_V2       13      /* RIPE RIS */
#define MSG_BGP4MP              16      /* dump bgp all */

#define BGP4MP_STATE_CHANGE     0
#define BGP4MP_MESSAGE          1
#define BGP4MP_ENTRY            2
#define BGP4MP_SNAPSHOT         4

/* Subtypes for TABLE_DUMP */
#define AFI_IP                  1
#define AFI_IP6                 2

/* Subtypes for TABLE_DUMP_V2 */
#define PEER_INDEX_TABLE        1
#define RIB_IPV4_UNICAST        2
#define RIB_IPV4_MULTICAST      3
#define RIB_IPV6_UNICAST        4
#define RIB_IPV6_MULTICAST      5
#define RIB_GENERIC             6

#define BGP_TYPE_OPEN           1
#define BGP_TYPE_UPDATE         2
#define BGP_TYPE_NOTIFICATION   3
#define BGP_TYPE_KEEPALIVE      4

#define BGP_ATTR_FLAG_EXTLEN    0x10

#define AS_SET                  1
#define AS_SEQUENCE             2
#define AS_CONFED_SEQUENCE      3
#define AS_CONFED_SET           4

#define BGP_ATTR_ORIGIN                 1
#define BGP_ATTR_AS_PATH                2
#define BGP_ATTR_NEXT_HOP               3
#define BGP_ATTR_MULTI_EXIT_DISC        4
#define BGP_ATTR_LOCAL_PREF             5
#define BGP_ATTR_ATOMIC_AGGREGATE       6
#define BGP_ATTR_AGGREGATOR             7
#define BGP_ATTR_COMMUNITIES            8
#define BGP_ATTR_ORIGINATOR_ID          9
#define BGP_ATTR_CLUSTER_LIST           10
#define BGP_ATTR_DPA                    11
#define BGP_ATTR_ADVERTISER             12
#define BGP_ATTR_RCID_PATH              13
#define BGP_ATTR_MP_REACH_NLRI          14
#define BGP_ATTR_MP_UNREACH_NLRI        15
#define BGP_ATTR_EXT_COMMUNITIES        16

/*
 * MRT header
 */
struct mrt_header {
    uint32_t time;
    uint16_t type;
    uint16_t subtype;
    uint32_t message_length;
};

/*
 * Table dump
 */
struct table_dump {
    uint16_t view_number;
    uint16_t sequence_number;
    union {
        uint32_t v4;
        uint32_t v6[4];
    } prefix;
    uint8_t prefix_length;
    uint8_t status;
    uint32_t originated_time;
    union {
        uint32_t v4;
        uint32_t v6[4];
    } peer_ip_addr;
    uint16_t peer_as;
    uint16_t attrlen;
};

/*
 * Peer index table
 */
struct peer_index_table_header {
    uint32_t collector_bgp_id;
    uint16_t view_name_length;
    unsigned char *view_name;   /* Pointer */
    uint16_t peer_count;
};
struct peer_index_table_record {
    char peer_type_ipv6;
    char peer_type_as4;
    uint32_t peer_bgp_id;
    union {
        uint32_t v4;
        uint32_t v6[4];
    } peer_ip_addr;
    union {
        uint16_t asn2;
        uint32_t asn4;
    } peer_as;
};
struct peer_index_table {
    struct peer_index_table_header header;
    struct peer_index_table_record *records;
};

/*
 * RIB unicast/multicast
 */
struct rib_header {
    uint32_t sequence_number;
    uint8_t prefix_length;
    uint8_t *prefix;
    uint16_t entry_count;
};
struct rib_entry {
    uint16_t peer_index;
    uint32_t originated_time;
    uint16_t attrlen;           /* Attribute length */
};
struct rib {
    struct rib_header header;
    struct rib_entry *entries;
};


#ifdef __cplusplus
extern "C" {
#endif

    struct mrt_header parse_mrt_header(unsigned char *);
    int parse_mrt_message(struct mrt_header *, unsigned char *, size_t);
    int parse_table_dump(struct mrt_header *, unsigned char *, size_t);
    int parse_table_dump_ip(struct mrt_header *, unsigned char *, size_t);
    int parse_table_dump_ip6(struct mrt_header *, unsigned char *, size_t);
    int parse_table_dump_v2(struct mrt_header *, unsigned char *, size_t);
    int
    parse_table_dump_v2_peer_index_table(
        struct mrt_header *, unsigned char *, size_t,
        struct peer_index_table **);
    int
    parse_table_dump_v2_rib(
        struct mrt_header *, unsigned char *, size_t,
        struct peer_index_table *);
    int parse_bgp_attribute(unsigned char *, size_t, int);
    int print_bgp_attribute(unsigned char *, size_t, int);

#ifdef __cplusplus
}
#endif

#endif /* _MRT_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
