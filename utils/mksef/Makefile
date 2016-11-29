INCLUDES=-I../../include -I../../lib/
CFLAGS=$(ARCH_FLAGS) $(INCLUDES)

MKSEF_OBJ=mksef.o buf.o sha2.o os.o hmac_sha256.o rijndael_alg.o rijndael_api.o

all:	mksef

clean:
	rm -f mksef $(MKSEF_OBJ)

mksef:	$(MKSEF_OBJ)
	$(CC) -o $@ $(MKSEF_OBJ) $(OS_LIBS)

buf.o: ../../lib/buf.c ../../lib/buf.h 
	$(CC) $(CFLAGS) -c $<

mksef.o: ../../lib/buf.h ../../include/sef/inode.h ../../include/sef/super.h \
	../../include/sef/checkpoint.h

sha2.o: ../../lib/sha2.c
	$(CC) $(CFLAGS) -c $<

hmac_sha256.o: ../../lib/hmac_sha256.c
	$(CC) $(CFLAGS) -c $<

os.o: ../../lib/os.c
	$(CC) $(CFLAGS) -c $<

rijndael_alg.o: ../../lib/rijndael/rijndael_alg.c
	$(CC) $(CFLAGS) -c $<

rijndael_api.o: ../../lib/rijndael/rijndael_api.c
	$(CC) $(CFLAGS) -c $<
