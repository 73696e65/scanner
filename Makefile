PROGNAME   = scanner
VERSION    = 0.33

OBJFILES   = scan.c
INCFILES   = allocate.h debug.h random_u32.h scanner.h types.h

SIMFILES   = 

CFLAGS_GEN = -Wall -funsigned-char -g -ggdb -I/usr/local/include/ \
	     -I/opt/local/include/ $(CFLAGS) -DVERSION=\"$(VERSION)\"
CFLAGS_DBG = -DDEBUG_ENABLED $(CFLAGS_GEN)
CFLAGS_OPT = -O2 -Wno-format $(CFLAGS_GEN)

LDFLAGS   += -L/usr/local/lib/ -L/opt/local/lib
LIBS      += -lpthread

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(LDFLAGS) $(PROGNAME).c -o $(PROGNAME) $(CFLAGS_OPT) $(OBJFILES) $(LIBS)
	@echo
	@echo Scanner version $(VERSION)
	@echo "See README to more information"
	@echo

simulate: simulate.c $(SIMFILES) $(OBJFILES) $(INCFILES) 
	$(CC) $(LDFLAGS) simulate.c -o simulate $(CFLAGS_OPT) \
		$(OBJFILES) $(SIMFILES) $(LIBS) -DSIMULATION_ENABLED

debug: $(PROGNAME).c $(OBJFILES) $(INCFILES)
	$(CC) $(LDFLAGS) $(PROGNAME).c -o $(PROGNAME) $(CFLAGS_DBG) \
		$(OBJFILES) $(LIBS)

clean:
	rm -f $(PROGNAME) *.exe *.o *~ a.out core core.[1-9][0-9]* *.stackdump \
		simulate

publish: clean
	 rm -rf ../scanner-$(VERSION).tgz; \
         cd ..; tar --exclude-vcs -cvzf scanner-$(VERSION).tgz scanner; cd -; 
	
