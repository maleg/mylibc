OUT = libmylibc.a
CC = gcc
ODIR = obj
SDIR = .
IDIR = .
INC = -Iinc
GLOBAL_LIBDIR = ..

_DEPS = RIPEMD160.h common.h timer.h
_OBJ = RIPEMD160.o common.o timer.o 
LIBS = -lm




DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

OBJS = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SDIR)/%.S
	$(CC) -c $(INC) -o $@ $^ $(CFLAGS) 

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c $(INC) -o $@ $^ $(CFLAGS) 

$(OUT): $(OBJS) 
	ar rcs $(OUT) $^

$(DEPS):
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o $(OUT)
	
copy:
	cp -f $(DEPS) $(GLOBAL_LIBDIR)
	cp -f $(OUT) $(GLOBAL_LIBDIR)
