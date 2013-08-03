CC=gcc
CFLAGS=$(INCLUDE) $(LIBRARIES) $(DEFINES) -Wall
INCLUDE=$(patsubst %,-I%,$(IDIR))
LIBRARIES=$(patsubst %,-l%,$(LIBS))
DEFINES=$(patsubst %,-D%,$(DEFS))
LIBS=
DEFS=DISABLE_PARITY_CHECK

# Source, object, and include directories
SDIR=./src
ODIR=$(SDIR)/obj
IDIR=./include

DEPS=des block_cipher
DEBUGGERS=self_test test_batch
PROGRAMS=efile dfile

.PHONY  : default debug all
default : $(PROGRAMS)
debug   : $(DEBUGGERS)
all     : $(PROGRAMS) $(DEBUGGERS)

$(patsubst %,$(ODIR)/%.o,$(DEPS)) : $(ODIR)/%.o : $(SDIR)/%.c $(IDIR)/crypto.h
$(ODIR)/%.o : LIBS=
$(ODIR)/%.o : $(SDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
$(ODIR)/efile.o : DEFS=ENCRYPT
$(ODIR)/efile.o : $(SDIR)/crypt_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
$(ODIR)/dfile.o : $(SDIR)/crypt_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
$(PROGRAMS) $(DEBUGGERS) :
	$(CC) $(CFLAGS) -o $@ $^

# Set up proper dependencies
$(DEBUGGERS) $(PROGRAMS): % : $(patsubst %,$(ODIR)/%.o,$(DEPS) %)

.PHONY: clean realclean
clean:
	-rm -f $(ODIR)/*.o $(PROGRAMS) $(DEBUGGERS)
realclean: clean
	-rm -f $(SDIR)/*~ $(IDIR)/*~ ./*~
