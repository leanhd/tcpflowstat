#ifndef  _MANAGER_H_INC
#define  _MANAGER_H_INC

#include <xstat.h>
#include <tcpflowstat.h>

int  tcp_stat();
void tcp_stat_over(const int sig);
void tcp_stat_release_resources();

#endif   /* ----- #ifndef _MANAGER_H_INC ----- */

