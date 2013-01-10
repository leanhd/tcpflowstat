
#include <xstat.h>
#include <tcpflowstat.h>

inline uint64_t
get_key(uint32_t ip, uint16_t port)
{
    uint64_t value = ((uint64_t) ip ) << 16;

    value += port;

    return value;
}


int
check_pack_src(ip_port_pair_mappings_t *transfer, uint32_t ip,
        uint16_t port, int src_flag)
{
    int                     i, ret;
    ip_port_pair_mapping_t *pair, **mappings;

    ret = UNKNOWN;
    mappings = transfer->mappings;

    for (i = 0; i < transfer->num; i++) {

        pair = mappings[i];
        if (CHECK_DEST == src_flag) {
            /* interested in INPUT raw socket */
            if (ip == pair->server_ip && port == pair->server_port) {
                ret = LOCAL;
                break;
            } else if (0 == pair->server_ip && port == pair->server_port) {
                ret = LOCAL;
                break;
            }
        } 
    }

    return ret;
}
