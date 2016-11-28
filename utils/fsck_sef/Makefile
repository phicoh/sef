INCLUDES=-I../../include -I../../lib/
CFLAGS=$(ARCH_FLAGS) $(INCLUDES)

FSCK_SEF_OBJ=fsck_sef.o buf.o sha2.o hmac_sha256.o rijndael_alg.o rijndael_api.o

all:	fsck_sef

clean:
	rm -f fsck_sef $(FSCK_SEF_OBJ)

fsck_sef:	$(FSCK_SEF_OBJ)
	$(CC) -o $@ $(FSCK_SEF_OBJ)

fsck_sef.o: ../../lib/buf.h ../../include/sef/inode.h \
	../../include/sef/checkpoint.h

buf.o: ../../lib/buf.c ../../lib/buf.h 
	$(CC) $(CFLAGS) -c $<

sha2.o: ../../lib/sha2.c
	$(CC) $(CFLAGS) -c $<

hmac_sha256.o: ../../lib/hmac_sha256.c
	$(CC) $(CFLAGS) -c $<

rijndael_alg.o: ../../lib/rijndael/rijndael_alg.c
	$(CC) $(CFLAGS) -c $<

rijndael_api.o: ../../lib/rijndael/rijndael_api.c
	$(CC) $(CFLAGS) -c $<
