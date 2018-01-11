OUT = ../libmylibc.a
CC = gcc
ODIR = obj
SDIR = src
INC = -Iinc

_OBJS = RIPEMD160.o common.o timer.o 
OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))


$(ODIR)/%.o: $(SDIR)/%.c 
	$(CC) -c $(INC) -o $@ $< $(CFLAGS) 

$(OUT): $(OBJS) 
	ar rvs $(OUT) $^

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o $(OUT)