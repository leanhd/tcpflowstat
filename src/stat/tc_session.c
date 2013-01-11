
#include <xstat.h>
#include <tcpflowstat.h>

static hash_table *sessions_table;
static double      total_req_time = 0;
static uint64_t    total_reqs = 0;


void
init_for_sessions()
{
    /* create 65536 slots for session table */
    sessions_table = hash_create(65536);
    strcpy(sessions_table->name, "session-table");

}


void
destroy_for_sessions()
{
    size_t       i;           
    hash_node   *hn;
    session_t   *s;
    link_list   *list;
    p_link_node  ln, tmp_ln;


   tc_log_info(LOG_NOTICE, 0, "enter destroy_for_sessions");

    if (sessions_table != NULL) {

        /* free session table */
        for (i = 0; i < sessions_table->size; i++) {

            list = sessions_table->lists[i];
            ln   = link_list_first(list);   
            while (ln) {

                tmp_ln = link_list_get_next(list, ln);
                hn = (hash_node *)ln->data;
                if (hn->data != NULL) {

                    s = hn->data;
                    hn->data = NULL;
                    /* delete session */
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del");
                    }
                    free(s);
                }
                ln = tmp_ln;
            }
            free(list);
        }

        free(sessions_table->lists);
        free(sessions_table);
        sessions_table = NULL;
    }

    tc_log_info(LOG_NOTICE, 0, "leave destroy_for_sessions");

}


void 
output_global_stat()
{
    tc_log_info(LOG_NOTICE, 0, "total req time(in second):%3f, reqs=%llu",
            total_req_time/1000, total_reqs);
    tc_log_info(LOG_NOTICE, 0, "average req time(in second):%.3f",
            total_req_time/(1000*total_reqs));
}


static session_t *
session_create(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    session_t               *s;

    s = (session_t *)calloc(1, sizeof(session_t));
    if (s == NULL) {
        return NULL;
    }

    return s;
}


static session_t *
session_add(uint64_t key, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    session_t *s;

    s = session_create(ip_header, tcp_header);
    if (s != NULL) {
        s->hash_key = key;
        if (!hash_add(sessions_table, key, s)) {
            tc_log_info(LOG_ERR, 0, "session item already exist");
        }
    }

    return s;
}



/*
 * processing client packets
 */
void
process_client_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t  cont_len;
    uint32_t  seq, ack, diff;
    long      req_time = 0;

    tc_log_debug_trace(LOG_DEBUG, 0, CLIENT_FLAG, ip_header, tcp_header);

    if (s->clt_port == 0) {
        s->clt_port = ntohs(tcp_header->source);
    }

    /* process the syn packet */
    if (tcp_header->syn) {
        s->syn_recv_time = settings.pcap_time;
        s->sm.clt_syn_received = 1;
        return;
    }

    /* if not receiving syn packet */ 
    if (!s->sm.clt_syn_received) {
        return;
    }

    ack = ntohl(tcp_header->ack_seq);
    seq = ntohl(tcp_header->seq);

    diff = ack - s->req_last_ack;

    if (diff == 1 && seq == s->req_last_seq) {
        /* it may ack the fin packet */
        if (s->req_start_time != 0 && s->resp_end_time !=0) {                        
            req_time = s->resp_end_time - s->req_start_time;
            total_req_time += req_time;
            total_reqs++;
            tc_log_info(LOG_INFO, 0, "req time 5 style(ms): %u , p:%u", 
                    req_time, s->clt_port);
        }

        s->sm.sess_over = 1;
    }

    /* process the reset packet */
    if (tcp_header->rst || tcp_header->fin) {

        if (s->resp_end_time == 0) {
            if (s->req_start_time != 0) {                        
                s->resp_end_time = settings.pcap_time;
                req_time = s->resp_end_time - s->req_start_time;
                total_req_time += req_time;
                total_reqs++;
                tc_log_info(LOG_INFO, 0, "req time 3 style(ms): %u , p:%u", 
                        req_time, s->clt_port);
            }
        } else {
            if (ack != s->req_cont_last_ack) {
                req_time = s->last_pcap_time - s->req_start_time;
                total_req_time += req_time;
                total_reqs++;
                tc_log_info(LOG_INFO, 0, "req time 4 style(ms): %u , p:%u", 
                        req_time, s->clt_port);
            }
        }
        s->sm.sess_over = 1;

        return;
    }

    /* retrieve the content length of tcp payload */
    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);

    if (cont_len > 0) {

        if (ack != s->req_cont_last_ack) {

            s->reqs++;

            /* a new request */

            if (s->resp_end_time == 0) {
                if (s->req_start_time != 0) {                        
                    s->resp_end_time = settings.pcap_time;
                    req_time = s->resp_end_time - s->req_start_time;
                    total_req_time += req_time;
                    total_reqs++;
                    tc_log_info(LOG_INFO, 0, "req time 1 style(ms): %u , p:%u",
                            req_time, s->clt_port);
                }
            } else {
                req_time = s->last_pcap_time - s->req_start_time;
                total_req_time += req_time;
                total_reqs++;
                tc_log_info(LOG_INFO, 0, "req time 2 style(ms): %u , p:%u", 
                        req_time, s->clt_port);
            }

            if (!s->sm.first_req) {
                s->sm.first_req = 1;
                s->req_start_time = s->syn_recv_time;
            } else {
                s->req_start_time = settings.pcap_time;
            }
            s->req_cont_last_ack = ack;
        }
        s->resp_end_time = 0;

    } else {


        s->req_last_ack = ack;
        s->req_last_seq = seq;

        if (s->req_start_time) {
            s->resp_end_time = settings.pcap_time;
        }
    }

    s->last_pcap_time = settings.pcap_time;

}


/*
 * main procedure for processing the filtered packets
 */
bool
process(char *packet)
{
    uint16_t           size_ip;
    uint64_t           key;
    session_t         *s;
    tc_ip_header_t    *ip_header;
    tc_tcp_header_t   *tcp_header;

    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);


    key = get_key(ip_header->saddr, tcp_header->source);
    if (tcp_header->syn) {

        s  = hash_find(sessions_table, key);
        if (NULL == s) {
            /* create a new session */
            s = session_add(key, ip_header, tcp_header);
            if (s == NULL) {
                return true;
            }
            process_client_packet(s, ip_header, tcp_header);
        }


    } else {

        s = hash_find(sessions_table, key);
        if (s) {
            process_client_packet(s, ip_header, tcp_header);
            if (s->sm.sess_over) {
                if (!hash_del(sessions_table, s->hash_key)) {
                    tc_log_info(LOG_ERR, 0, "wrong del:%u",
                            s->clt_port);
                }
                free(s);
            }
        }
    }

    return true;
}

