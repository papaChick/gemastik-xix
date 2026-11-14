CC      ?= gcc
CFLAGS  ?= -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

OBJ = lmk.o detector.o

lmk: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c detector.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f lmk $(OBJ)

.PHONY: clean
