
#include <xstat.h>
#include <tcpflowstat.h>


void
tcp_stat_release_resources()
{
    destroy_for_sessions();

    tc_log_end();

    pcap_close(settings.pcap);

}

void
tcp_stat_over(const int sig)
{
    long int pid   = (long int)syscall(SYS_gettid);

    tc_log_info(LOG_WARN, 0, "sig %d received, pid=%ld", sig, pid);
    settings.over = 1;

}


int
tcp_stat()
{

    init_for_sessions();

    if (tc_offline_parse(settings.pcap_file) == TC_ERROR) {
        return TC_ERROR;
    }

    output_global_stat();

    tcp_stat_release_resources();

    return TC_OK;
}
