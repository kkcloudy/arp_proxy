OBJS=main.o eloop.o l2_packet_linux.o arp_proxy.o arp_snoop.o arpp_tbl.o common.o os.o debug.o
TARGET=arp-proxy
TARGET_CLI=arpp_cli
LIBS_DEPEND=-lnetfilter_queue

.PHONY:all
all:$(TARGET) $(TARGET_CLI)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} $(LIBS_DEPEND) -o $(TARGET) $(OBJS)

$(TARGET_CLI):arpp_cli.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $(TARGET_CLI) arpp_cli.o

%.o:%.c
	#${CC} -c ${CFLAGS} ${INC} $< -o $@
	${CC} -c ${CFLAGS} $< -o $@


