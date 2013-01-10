bin_PROGRAMS=tcpflowstat

tcpflowstat_SOURCES=\
                tcpflowstat.h\
                tc_manager.c tc_manager.h\
                tc_session.c tc_session.h\
				tc_packets_module.c tc_packets_module.h\
                main.c
tcpflowstat_LDADD=\
               ../core/libcore.a\
               ../util/libutil.a\
               -lm
