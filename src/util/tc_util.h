#ifndef  _TCPSTAT_UTIL_H_INC
#define  _TCPSTAT_UTIL_H_INC

#include <xstat.h>
#include <tcpflowstat.h>


#define TCP_HDR_LEN(tcph) (tcph->doff << 2)
#define IP_HDR_LEN(iph) (iph->ihl << 2)                                                                 
#define TCP_PAYLOAD_LENGTH(iph, tcph) \
        (ntohs(iph->tot_len) - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

inline uint64_t get_key(uint32_t s_ip, uint16_t s_port);
int check_pack_src(ip_port_pair_mappings_t *transfer, uint32_t ip,
        uint16_t port, int src_flag);


#endif   /* ----- #ifndef _TCPSTAT_UTIL_H_INC  ----- */

