# Sample Makefile
# CC - compiler
# OBJ - compiled source files that should be linked
# COPT - compiler flags
# BIN - binary
CC=clang
OBJ=helper1.o dns.o tick_timer.o dns_cache.o file_io.o
COPT=-Wall -Wpedantic
LCOPT=-lpthread
BIN_PHASE2=dns_svr

# Running "make" with no argument will make the first target in the file
all: $(BIN_PHASE2)

# Rules of the form
#     target_to_be_made : dependencies_to_be_up-to-date_first
#     <tab>commands_to_make_target
# (Note that spaces will not work.)

$(BIN_PHASE2): main.c dns.c helper1.c tick_timer.c dns_cache.c file_io.c $(OBJ)
	$(CC) -o $(BIN_PHASE2) main.c $(OBJ) $(COPT) $(LCOPT)

# Wildcard rule to make any  .o  file,
# given a .c and .h file with the same leading filename component
%.o: %.c %.h
	$(CC) -c $< $(COPT) -g

format:
	clang-format -i *.c *.h

clean:
	rm -rf *.o && rm -rf $(BIN_PHASE2)
