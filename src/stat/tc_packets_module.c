
#include <xstat.h>
#include <tcpflowstat.h>


static int get_l2_len(const unsigned char *packet, const int pkt_len,
        const int datalink);
static unsigned char * get_ip_data(unsigned char *packet, const int pkt_len,
        int *p_l2_len);

static uint64_t clt_syn_cnt          = 0;
static uint64_t clt_cont_cnt         = 0;
static uint64_t clt_packs_cnt        = 0;


bool
is_packet_needed(const char *packet)
{
    bool              is_needed = false;
    uint16_t          size_ip, size_tcp, tot_len, cont_len, header_len;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    ip_header = (tc_ip_header_t *) packet;

    /* check if it is a tcp packet(could be removed) */
    if (ip_header->protocol != IPPROTO_TCP) {
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    tot_len   = ntohs(ip_header->tot_len);
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp   = tcp_header->doff << 2;
    if (size_tcp < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid TCP header len: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return is_needed;
    }

    /* filter the packets we do care about */
    if (LOCAL == check_pack_src(&(settings.stat), 
                ip_header->daddr, tcp_header->dest, CHECK_DEST)) {
        header_len = size_tcp + size_ip;
        if (tot_len >= header_len) {

            is_needed = true;
            cont_len  = tot_len - header_len;
            if (tcp_header->syn) {
                clt_syn_cnt++;
            } else if (cont_len > 0) {
                clt_cont_cnt++;
            }
            clt_packs_cnt++;
        } else {
            tc_log_info(LOG_WARN, 0, "bad tot_len:%d bytes, header len:%d",
                    tot_len, header_len);
        }
    }

    return is_needed;

}


int
tc_offline_parse(char *pcap_file)
{
    int                 l2_len, ip_pack_len = 0;
    bool                stop = false;
    char                ebuf[PCAP_ERRBUF_SIZE];
    pcap_t             *pcap;
    unsigned char      *pkt_data, *ip_data;
    struct pcap_pkthdr  pkt_hdr;  
    struct timeval      last_pack_time;


    if (pcap_file == NULL) {
        return TC_ERROR;
    }

    if ((settings.pcap = pcap_open_offline(pcap_file, ebuf)) == NULL) {
        tc_log_info(LOG_ERR, 0, "open %s" , ebuf);
        fprintf(stderr, "open %s\n", ebuf);
        return TC_ERROR;
    }

    pcap = settings.pcap;

    tc_log_info(LOG_NOTICE, 0, "open pcap success:%s", pcap_file);

    while (!stop) {

        pkt_data = (u_char *) pcap_next(pcap, &pkt_hdr);
        if (pkt_data != NULL) {

            if (pkt_hdr.caplen < pkt_hdr.len) {
                tc_log_debug0(LOG_DEBUG, 0, "truncated packets,drop");
            } 

            ip_data = get_ip_data(pkt_data, pkt_hdr.caplen, &l2_len);
            last_pack_time = pkt_hdr.ts;
            if (ip_data != NULL) {
                settings.pcap_time = last_pack_time.tv_sec * 1000 + 
                    last_pack_time.tv_usec/1000; 

                ip_pack_len = pkt_hdr.len - l2_len;
                if (is_packet_needed((const char *) ip_data)) {  

                    process((char *)ip_data);

                } else {

                    tc_log_debug0(LOG_DEBUG, 0, "invalid flag");
                }
            }
        } else {

            tc_log_info(LOG_WARN, 0, "stop, null from pcap_next");
            stop = true;
        }
    }

    return TC_OK;
}


static int
get_l2_len(const unsigned char *packet, const int pkt_len, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;
        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *)packet;
            switch (ntohs(eth_hdr->ether_type)) {
                case ETHERTYPE_VLAN:
                    return 18;
                    break;
                default:
                    return 14;
                    break;
            }
            break;
        case DLT_C_HDLC:
            return CISCO_HDLC_LEN;
            break;
        case DLT_LINUX_SLL:
            return SLL_HDR_LEN;
            break;
        default:
            tc_log_info(LOG_ERR, 0, "unsupported DLT type: %s (0x%x)", 
                    pcap_datalink_val_to_description(datalink), datalink);
            break;
    }

    return -1;
}

#ifdef FORCE_ALIGN
static unsigned char pcap_ip_buf[65536];
#endif

static unsigned char *
get_ip_data(unsigned char *packet, const int pkt_len, int *p_l2_len)
{
    int      l2_len;
    u_char  *ptr;
    pcap_t  *pcap = settings.pcap;

    l2_len    = get_l2_len(packet, pkt_len, pcap_datalink(pcap));
    *p_l2_len = l2_len;

    if (pkt_len <= l2_len) {
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(packet)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(packet)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(packet)[l2_len]);
#endif

    return ptr;

}


