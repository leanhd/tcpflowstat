#ifndef __TCPSTAT_H__
#define __TCPSTAT_H__ 


typedef struct {
    uint32_t server_ip;
    uint16_t server_port;
} ip_port_pair_mapping_t;


typedef struct {
    int                      num;
    ip_port_pair_mapping_t **mappings;
} ip_port_pair_mappings_t;


typedef struct xstat_settings {
    unsigned int  do_daemonize:1;       /* daemon flag */

    char         *raw_stat;         

    char         *pid_file;             /* pid file */
    char         *log_path;             /* error log path */
    char         *pcap_file;            /* pcap file */
    pcap_t       *pcap;
    long          pcap_time;
    ip_port_pair_mappings_t stat;
} xstat_settings;


extern xstat_settings settings;

#include <tc_util.h>

#include <tc_manager.h>
#include <tc_session.h>
#include <tc_packets_module.h>

#endif /* __TCPSTAT_H__ */
