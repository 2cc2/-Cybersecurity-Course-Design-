CC = gcc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = -lm -lnet -lpcap -pthread

SRCS = src/scanhost.c src/scanport_tcp.c  src/main.c src/cap.c src/printer.c src/scan.c  
OBJS = $(SRCS:.c=.o) 
TARGET = myping

all: macdb.csv $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	$(RM) $(OBJS) $(TARGET)
	rm *.csv
	
macdb.csv:
	wget http://standards-oui.ieee.org/oui/oui.csv
	cat oui.csv | cut -d',' -f2- > macdb.csv
	rm oui.csv