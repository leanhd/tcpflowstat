/*
 *  TCPFlowStat
 *  A tool for calculating request time for TCP applications
 *
 *  Copyright 2013 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      Bin Wang <wangbin579@gmail.com>
 */

#include <xstat.h>
#include <tcpflowstat.h>

/* global variables for TCPStat */
xstat_settings settings;


static void
set_signal_handler()
{
    signal(SIGINT,  tcp_stat_over);
    signal(SIGPIPE, tcp_stat_over);
    signal(SIGHUP,  tcp_stat_over);
    signal(SIGTERM, tcp_stat_over);
}

static void
usage(void)
{
    printf("TCPFlowStat " VERSION "\n");
    printf("-x <target,>   use <target,> to specify the IPs and ports of target\n"
           "               servers. Suppose 'serverIP' and 'serverPort' are the IP \n"
           "               and port number of the target server you want to stat,\n"
           "               the format of <target,> could be as follows:\n"
           "               'serverIP:serverPort,...'. Most of the time,\n");
    printf("               serverIP could be omitted and thus <target,> could also be:\n"
           "               'serverPort,...'. As seen, the IP address and the\n"
           "               port number are segmented by ':' (colon) and two 'target's \n"
           "               are segmented by',' (comma). For example, \n"
           "               './tcpflowstat -x 18080 -i 80.pcap' \n"
           "               would stat request time from TCP port '18080' on current server\n");
    printf("-i <file>      set the pcap file used for TCPStat to <file> (only valid for the\n"
           "               offline version of TCPStat when it is configured to run at\n"
           "               enable-offline mode)\n");
    printf("-l <file>      save the log information in <file>\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n"
           "-h             print this help and exit\n"
           "-v             version\n"
           "-d             run as a daemon\n");
}



static int
read_args(int argc, char **argv)
{
    int  c;

    while (-1 != (c = getopt(argc, argv,
         "x:" /* <target,> */
         "i:" /* input pcap file */
         "l:" /* error log file */
         "P:" /* save PID in file */
         "h"  /* help, licence info */
         "v"  /* version */
         "d"  /* daemon mode */
        ))) {
        switch (c) {
            case 'x':
                settings.raw_stat= optarg;
                break;
            case 'i':
                settings.pcap_file= optarg;
                break;
            case 'l':
                settings.log_path = optarg;
                break;
            case 'h':
                usage();
                return -1;
            case 'v':
                printf ("TCPStat version:%s\n", VERSION);
                return -1;
            case 'd':
                settings.do_daemonize = 1;
                break;
            case 'P':
                settings.pid_file = optarg;
                break;
            default:
                fprintf(stderr, "Illegal argument \"%c\"\n", c);
                return -1;
        }
    }

    return 0;
}

static void
output_for_debug(int argc, char **argv)
{
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "TCPStat version:%s", VERSION);
    /* print out target info */
    tc_log_info(LOG_NOTICE, 0, "target:%s", settings.raw_stat);
}

static void
parse_ip_port_pair(char *addr, ip_port_pair_mapping_t *pair)
{
    char    *seq, *ip_s, *port_s;
    uint16_t tmp_port;

    if ((seq = strchr(addr, ':')) == NULL) {
        tc_log_info(LOG_NOTICE, 0, "set global port for TCPStat");
        pair->server_ip = 0;
        port_s = addr;
    } else {
        ip_s = addr;
        port_s = seq + 1;

        *seq = '\0';
        pair->server_ip = inet_addr(ip_s);
        *seq = ':';
    }

    tmp_port = atoi(port_s);
    pair->server_port = htons(tmp_port);
}


/*
 * retrieve target addresses
 */
static int
retrieve_target_addresses(char *raw_stat,
        ip_port_pair_mappings_t *stat)
{
    int   i;
    char *p, *seq;

    if (raw_stat == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -x argument");
        fprintf(stderr, "no -x argument\n");
        return -1;
    }

    for (stat->num = 1, p = raw_stat; *p; p++) {
        if (*p == ',') {
            stat->num++;
        }
    }

    stat->mappings = malloc(stat->num *
                                sizeof(ip_port_pair_mapping_t *));
    if (stat->mappings == NULL) {
        return -1;
    }

    for (i = 0; i < stat->num; i++) {
        stat->mappings[i] = malloc(sizeof(ip_port_pair_mapping_t));
        if (stat->mappings[i] == NULL) {
            return -1;
        }
    }

    p = raw_stat;
    i = 0;
    for ( ;; ) {
        if ((seq = strchr(p, ',')) == NULL) {
            parse_ip_port_pair(p, stat->mappings[i++]);
            break;
        } else {
            *seq = '\0';
            parse_ip_port_pair(p, stat->mappings[i++]);
            *seq = ',';

            p = seq + 1;
        }
    }

    return 0;
}

static int
sigignore(int sig)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }

    return 0;
}


static int
set_details()
{

    /* set the ip port pair mapping according to settings */
    if (retrieve_target_addresses(settings.raw_stat,
                              &settings.stat) == -1)
    {
        return -1;
    }

    if (settings.pcap_file == NULL) {
        tc_log_info(LOG_ERR, 0, "it must have -i argument for offline");
        fprintf(stderr, "no -i argument\n");
        return -1;
    }

    /* daemonize */
    if (settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "Failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return -1;
        }    
    }    


    return 0;
}

static void
settings_init()
{
    set_signal_handler();
}

/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret;

    settings_init();

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }
    
    if (settings.log_path == NULL) {
        settings.log_path = "error_tcpflowstat.log";
    }   

    if (tc_log_init(settings.log_path) == -1) {
        return -1;
    }

    /* output debug info */
    output_for_debug(argc, argv);

    /* set details for running */
    if (set_details() == -1) {
        return -1;
    }

    ret = tcp_stat();
    if (ret == TC_ERROR) {
        exit(EXIT_FAILURE);
    }

    return 0;
}

