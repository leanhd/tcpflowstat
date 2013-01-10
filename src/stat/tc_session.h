#ifndef  _TCP_SESSION_H_INC
#define  _TCP_SESSION_H_INC

#include <xstat.h>
#include <tcpflowstat.h>

/* global functions */
void init_for_sessions();
void destroy_for_sessions();
bool process(char *packet);
void output_global_stat();

typedef struct sess_state_machine_s{
    /* session over flag */
    uint32_t sess_over:1;
    uint32_t clt_closed:1;
    uint32_t candidate_response_waiting:1;
    uint32_t clt_syn_received:1;

}sess_state_machine_t;

typedef struct session_s{
    /* hash key for this session */
    uint64_t hash_key;

    uint32_t clt_addr;
    uint16_t clt_port;


    uint32_t req_cont_last_ack;
    uint32_t req_last_ack;
    uint32_t req_last_seq;
    long     last_pcap_time;
    long     req_start_time;
    long     req_end_time;
    long     resp_start_time;
    long     resp_end_time;

    sess_state_machine_t sm; 

}session_t;

#endif   /* ----- #ifndef _TCP_SESSION_H_INC ----- */

