INCLUDES=-I../../include -I../../lib/
CFLAGS=$(ARCH_FLAGS) $(INCLUDES)

SEFC_OBJ=sefc.o buf.o sha2.o hmac_sha256.o os.o \
	rijndael_alg.o rijndael_api.o

all:	sefc

clean:
	rm -f sefc $(SEFC_OBJ)

sefc:	$(SEFC_OBJ)
	$(CC) -o $@ $(SEFC_OBJ) $(OS_LIBS)

sefc.o: ../../lib/buf.h ../../include/sef/checkpoint.h ../../include/sef/inode.h

buf.o: ../../lib/buf.c ../../lib/buf.h 
	$(CC) $(CFLAGS) -c $<

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
