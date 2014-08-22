/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: mrt.c,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $ */

#include "mrt.h"
#include "bsconv.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * Parse MRT header
 */
struct mrt_header
parse_mrt_header(unsigned char *hbuf)
{
    struct mrt_header header;

    /* Parse header from the buffer */
    header.time = bs2uint32(hbuf, _ENDIAN_NETWORK);
    header.type = bs2uint16(hbuf+4, _ENDIAN_NETWORK);
    header.subtype = bs2uint16(hbuf+6, _ENDIAN_NETWORK);
    header.message_length = bs2uint32(hbuf+8, _ENDIAN_NETWORK);

    return header;
}

/*
 * Parse MRT message
 */
int
parse_mrt_message(struct mrt_header *header, unsigned char *body, size_t len)
{
    if ( MSG_TABLE_DUMP == header->type ) {
        parse_table_dump(header, body, len);
    } else if ( MSG_TABLE_DUMP_V2 == header->type ) {
        parse_table_dump_v2(header, body, len);
    } else {
        fputs("Unsupported type\n", stderr);
        return -1;
    }

    return 0;
}

/*
 * Parse TABLE_DUMP type
 */
int
parse_table_dump(struct mrt_header *header, unsigned char *body, size_t len)
{
    int ret;

    if ( AFI_IP == header->subtype ) {
        ret = parse_table_dump_ip(header, body, len);
    } else if ( AFI_IP6 == header->subtype ) {
        ret = parse_table_dump_ip6(header, body, len);
    } else {
        ret = -1;
    }

    return ret;
}

/*
 * Parse AFI_IPv4 of TABLE_DUMP type
 */
int
parse_table_dump_ip(struct mrt_header *header, unsigned char *body, size_t len)
{
    struct table_dump td;
    size_t rest;
    unsigned char *cptr;

    /* Check the length */
    if ( len < 22 ) {
        return -1;
    }

    cptr = body;
    rest = len;

    /* Get view # */
    td.view_number = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get sequence number */
    td.sequence_number = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get prefix */
    td.prefix.v4 = bs2uint32(cptr, _ENDIAN_NETWORK);
    cptr += 4;
    rest -= 4;

    /* Get prefix length */
    td.prefix_length = *cptr;
    cptr++;
    rest--;

    /* Get status */
    td.status = *cptr;
    cptr++;
    rest--;

    /* Get originated time */
    td.originated_time = bs2uint32(cptr, _ENDIAN_NETWORK);
    cptr += 4;
    rest -= 4;

    /* Get peer IP address */
    td.peer_ip_addr.v4 = bs2uint32(cptr, _ENDIAN_NETWORK);
    cptr += 4;
    rest -= 4;

    /* Get peer AS */
    td.peer_as = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get attribute length */
    td.attrlen = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Check the length */
    if ( rest < td.attrlen ) {
        /* Length error */
        return -1;
    }
    /* Parse attribute */
    print_bgp_attribute(cptr, td.attrlen, 0);

    return 0;
}

/*
 * Parse AFI_IPv6 of TABLE_DUMP type
 */
int
parse_table_dump_ip6(struct mrt_header *header, unsigned char *body, size_t len)
{
    struct table_dump td;
    size_t rest;
    unsigned char *cptr;

    /* Check the length */
    if ( len < 46 ) {
        return -1;
    }

    cptr = body;
    rest = len;

    /* Get view # */
    td.view_number = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get sequence number */
    td.sequence_number = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get prefix */
    td.prefix.v6[0] = bs2uint32(cptr, _ENDIAN_NETWORK);
    td.prefix.v6[1] = bs2uint32(cptr+4, _ENDIAN_NETWORK);
    td.prefix.v6[2] = bs2uint32(cptr+8, _ENDIAN_NETWORK);
    td.prefix.v6[3] = bs2uint32(cptr+12, _ENDIAN_NETWORK);
    cptr += 16;
    rest -= 16;

    /* Get prefix length */
    td.prefix_length = *cptr;
    cptr++;
    rest--;

    /* Get status */
    td.status = *cptr;
    cptr++;
    rest--;

    /* Get originated time */
    td.originated_time = bs2uint32(cptr, _ENDIAN_NETWORK);
    cptr += 4;
    rest -= 4;

    /* Get peer IP address */
    td.peer_ip_addr.v6[0] = bs2uint32(cptr, _ENDIAN_NETWORK);
    td.peer_ip_addr.v6[1] = bs2uint32(cptr+4, _ENDIAN_NETWORK);
    td.peer_ip_addr.v6[2] = bs2uint32(cptr+8, _ENDIAN_NETWORK);
    td.peer_ip_addr.v6[3] = bs2uint32(cptr+12, _ENDIAN_NETWORK);
    cptr += 16;
    rest -= 16;

    /* Get peer AS */
    td.peer_as = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Get attribute length */
    td.attrlen = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    /* Check the length */
    if ( rest < td.attrlen ) {
        /* Length error */
        return -1;
    }
    /* Parse attribute */
    parse_bgp_attribute(cptr, td.attrlen, 0);

    return 0;
}

/*
 * Parse TABLE_DUMP_V2 type
 */
int
parse_table_dump_v2(struct mrt_header *header, unsigned char *body, size_t len)
{
    int ret;
    static struct peer_index_table *pit = NULL;

    if ( PEER_INDEX_TABLE == header->subtype ) {
        /* PEER_INDEX_TABLE */
        ret = parse_table_dump_v2_peer_index_table(header, body, len, &pit);
    } else if ( RIB_IPV4_UNICAST == header->subtype
                || RIB_IPV4_MULTICAST == header->subtype
                || RIB_IPV6_UNICAST == header->subtype
                || RIB_IPV6_MULTICAST == header->subtype ) {
        /* RIB */
        ret = parse_table_dump_v2_rib(header, body, len, pit);
    } else if ( RIB_GENERIC == header->subtype ) {
        fputs("Unsupported subtype\n", stderr);
        ret = -1;
    } else {
        ret = -1;
    }

    return ret;
}

/*
 * Parse TABLE_DUMP_V2's PEER_INDEX_TABLE
 */
int
parse_table_dump_v2_peer_index_table(
    struct mrt_header *header, unsigned char *body, size_t len,
    struct peer_index_table **pit)
{
    int i;
    size_t rest;
    unsigned char *cptr;
    struct peer_index_table_header pith;
    struct peer_index_table_record *rec;

    /* Check the length */
    if ( len < 8 ) {
        return -1;
    }

    /* Get collector BGP ID */
    pith.collector_bgp_id = bs2uint32(body, _ENDIAN_NETWORK);
    /* Get view name length */
    pith.view_name_length = bs2uint16(body+4, _ENDIAN_NETWORK);
    /* Check the header length */
    if ( len < 8 + pith.view_name_length ) {
        return -1;
    }
    /* Get view name */
    pith.view_name = body + 6;
    /* Get peer count */
    pith.peer_count = bs2uint16(body+6+pith.view_name_length, _ENDIAN_NETWORK);

    /* Get current pointer and rest */
    cptr = body + 8 + pith.view_name_length;
    rest = len - (8 + pith.view_name_length);

    /* Allocate for records */
    rec = malloc(sizeof(struct peer_index_table_record) * pith.peer_count);
    if ( NULL == rec ) {
        /* Memory error */
        return -1;
    }

    /* For all peers */
    for ( i = 0; i < pith.peer_count; i++ ) {
        /* Check the length */
        if ( rest < 5 ) {
            /* Length error */
            free(rec);
            return -1;
        }
        /* Get peer type */
        if ( *cptr & 1 ) {
            rec[i].peer_type_ipv6 = 1;
        } else {
            rec[i].peer_type_ipv6 = 0;
        }
        if ( *cptr & 2 ) {
            rec[i].peer_type_as4 = 1;
        } else {
            rec[i].peer_type_as4 = 0;
        }
        cptr++;
        rest--;
        /* Get peer BGP ID */
        rec[i].peer_bgp_id = bs2uint32(cptr, _ENDIAN_NETWORK);
        cptr += 4;
        rest -= 4;

        printf("%d %d %d\n", len, rest, rec[i].peer_type_ipv6);
        /* by type */
        if ( rec[i].peer_type_ipv6 ) {
            /* IPv6 */
            /* Check the length */
            if ( rest < 16 ) {
                /* Length error */
                free(rec);
                return -1;
            }
            /* Get IP address */
            rec[i].peer_ip_addr.v6[0] = bs2uint32(cptr, _ENDIAN_NETWORK);
            rec[i].peer_ip_addr.v6[1] = bs2uint32(cptr+4, _ENDIAN_NETWORK);
            rec[i].peer_ip_addr.v6[2] = bs2uint32(cptr+8, _ENDIAN_NETWORK);
            rec[i].peer_ip_addr.v6[3] = bs2uint32(cptr+12, _ENDIAN_NETWORK);
            cptr += 16;
            rest -= 16;
        } else {
            /* IPv4 */
            /* Check the length */
            if ( rest < 4 ) {
                /* Length error */
                free(rec);
                return -1;
            }
            /* Get IP address */
            rec[i].peer_ip_addr.v4 = bs2uint32(cptr, _ENDIAN_NETWORK);
            cptr += 4;
            rest -= 4;
        }
        /* by type */
        if ( rec[i].peer_type_as4 ) {
            /* 4-octet AS number */
            /* Check the length */
            if ( rest < 4 ) {
                /* Length error */
                free(rec);
                return -1;
            }
            /* Get AS number */
            rec[i].peer_as.asn4 = bs2uint32(cptr, _ENDIAN_NETWORK);
            cptr += 4;
            rest -= 4;
        } else {
            /* 2-octet AS number */
            /* Check the length */
            if ( rest < 2 ) {
                /* Length error */
                free(rec);
                return -1;
            }
            /* Get AS number */
            rec[i].peer_as.asn2 = bs2uint16(cptr, _ENDIAN_NETWORK);
            cptr += 2;
            rest -= 2;
        }
    }

    /* Set */
    *pit = malloc(sizeof(struct peer_index_table));
    if ( NULL == *pit ) {
        /* Memory error */
        free(rec);
        return -1;
    }
    (*pit)->header = pith;
    (*pit)->records = rec;

    return 0;
}

/*
 * Parse MRT TABLE_DUMP_V2's RIB
 */
int
parse_table_dump_v2_rib(
    struct mrt_header *header, unsigned char *body, size_t len,
    struct peer_index_table *pit)
{
    int i;
    unsigned char *cptr;
    size_t rest;
    int prefix_byte;
    struct rib rib;
    struct rib_header ribh;
    struct rib_entry *entries;
    int as4;

    if ( NULL == pit ) {
        /* Peer index table is not specified. */
        return -1;
    }

    rest = len;
    cptr = body;

    /* Check the length */
    if ( rest < 5 ) {
        return -1;
    }

    /* Get sequence number */
    ribh.sequence_number = bs2uint32(cptr, _ENDIAN_NETWORK);
    cptr += 4;
    rest -= 4;

    /* Get prefix length */
    ribh.prefix_length = *cptr;
    cptr++;
    rest--;

    if ( ribh.prefix_length > 0 ) {
        prefix_byte = (ribh.prefix_length-1)/8+1;
    } else {
        prefix_byte = 0;
    }

    /* Check length */
    if ( rest < prefix_byte ) {
        return -1;
    }

    /* Get prefix */
    ribh.prefix = cptr;
    cptr += prefix_byte;
    rest -= prefix_byte;

    /* Check length */
    if ( rest < 2 ) {
        return -1;
    }

    /* Get entry count */
    ribh.entry_count = bs2uint16(cptr, _ENDIAN_NETWORK);
    cptr += 2;
    rest -= 2;

    entries = malloc(sizeof(struct rib_entry) * ribh.entry_count);
    if ( NULL == entries ) {
        /* Memory error */
        return -1;
    }

    for ( i = 0; i < ribh.entry_count; i++ ) {
        /* Check the length */
        if ( rest < 8 ) {
            /* Length error */
            free(entries);
            return -1;
        }
        entries[i].peer_index = bs2uint16(cptr, _ENDIAN_NETWORK);
        cptr += 2;
        rest -= 2;
        entries[i].originated_time = bs2uint32(cptr, _ENDIAN_NETWORK);
        cptr += 4;
        rest -= 4;
        entries[i].attrlen = bs2uint16(cptr, _ENDIAN_NETWORK);
        cptr += 2;
        rest -= 2;

        /* Check the length */
        if ( rest < entries[i].attrlen ) {
            /* Length error */
            free(entries);
            return -1;
        }

        /* 4-octet? */
        if ( entries[i].peer_index >= pit->header.peer_count ) {
            fputs("Bad format\n", stderr);
            free(entries);
            return -1;
        }
        if ( pit->records[entries[i].peer_index].peer_type_as4 ) {
            as4 = 1;
        } else {
            as4 = 0;
        }

        parse_bgp_attribute(cptr, entries[i].attrlen, as4);

        cptr += entries[i].attrlen;
        rest -= entries[i].attrlen;
    }

    rib.header = ribh;
    rib.entries = entries;
    free(entries);

    return 0;
}

/*
 * RFC4271  pp. 17
 */
int
parse_bgp_attribute(unsigned char *attr, size_t attrlen, int as4)
{
    size_t p;
    uint8_t flags;
    uint8_t type;
    uint16_t attriblen;
    unsigned char *attrib;
    int i;
    size_t x;
    int as_set;

    p = 0;
    while ( attrlen > p ) {
        flags = attr[p];
        type = attr[p+1];
        if ( flags & BGP_ATTR_FLAG_EXTLEN ) {
            /* Extended attribute length (16 bits) */
            attriblen = bs2uint16(attr+p+2, _ENDIAN_NETWORK);
            attrib = &attr[p+4];
            p = p + 4 + attriblen;
        } else {
            /* Normal attribute length (8 bits) */
            attriblen = attr[p+2];
            attrib = &attr[p+3];
            p = p + 3 + attriblen;
        }

        if ( BGP_ATTR_AS_PATH == type ) {
            /* seg_type = attrib[q]; */
            /* seg_length = attrib[q+1]; */
            /* seg_value = attrib[q+2:q+seg_length*as_size]; */
            x = 0;
            while ( x < attriblen ) {
                if ( 0 != x ) {
                    printf(" ");
                }
                if ( AS_SET == attrib[x] ) {
                    as_set = 1;
                } else {
                    as_set = 0;
                }
                if ( as_set ) {
                    printf("{");
                }
                for ( i = 0; i < attrib[x+1]; i++ ) {
                    if ( i != 0 ) {
                        if ( as_set ) {
                            printf(",");
                        } else {
                            printf(" ");
                        }
                    }
                    if ( as4 ) {
                        printf("%u", bs2uint32(&attrib[x+2+i*4], _ENDIAN_NETWORK));
                    } else {
                        printf("%u", bs2uint16(&attrib[x+2+i*2], _ENDIAN_NETWORK));
                    }
                }
                if ( as_set ) {
                    printf("}");
                }
                if ( as4 ) {
                    x += 2 + attrib[x+1] * 4;
                } else {
                    x += 2 + attrib[x+1] * 2;
                }
            }
            printf("\n");
        }
    }

    return 0;
}

/*
 * Temporal implementation
 * Excluding AS sets, and dividing by sequences
 */
int
print_bgp_attribute(unsigned char *attr, size_t attrlen, int as4)
{
    size_t p;
    uint8_t flags;
    uint8_t type;
    uint16_t attriblen;
    unsigned char *attrib;
    int i;
    size_t x;
    int f;
    int as_set;

    p = 0;
    while ( attrlen > p ) {
        flags = attr[p];
        type = attr[p+1];
        if ( flags & BGP_ATTR_FLAG_EXTLEN ) {
            /* Extended attribute length (16 bits) */
            attriblen = bs2uint16(attr+p+2, _ENDIAN_NETWORK);
            attrib = &attr[p+4];
            p = p + 4 + attriblen;
        } else {
            /* Normal attribute length (8 bits) */
            attriblen = attr[p+2];
            attrib = &attr[p+3];
            p = p + 3 + attriblen;
        }

        if ( BGP_ATTR_AS_PATH == type ) {
            /* seg_type = attrib[q]; */
            /* seg_length = attrib[q+1]; */
            /* seg_value = attrib[q+2:q+seg_length*as_size]; */
            x = 0;
            f = 0;
            while ( x < attriblen ) {
                if ( AS_SET == attrib[x] ) {
                    as_set = 1;
                } else {
                    as_set = 0;
                }
                if ( !as_set ) {
                    for ( i = 0; i < attrib[x+1]; i++ ) {
                        if ( f ) {
                            printf(" ");
                        }
                        if ( as4 ) {
                            printf("%u", bs2uint32(&attrib[x+2+i*4], _ENDIAN_NETWORK));
                        } else {
                            printf("%u", bs2uint16(&attrib[x+2+i*2], _ENDIAN_NETWORK));
                        }
                        f = 1;
                    }
                } else {
                    if ( f ) {
                        printf("\n");
                        f = 0;
                    }
                }
                if ( as4 ) {
                    x += 2 + attrib[x+1] * 4;
                } else {
                    x += 2 + attrib[x+1] * 2;
                }
            }
            if ( f ) {
                printf("\n");
                f = 0;
            }
        }
    }

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
