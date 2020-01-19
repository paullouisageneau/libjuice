# libjuice

NAME=libjuice
CC=$(CROSS)gcc
AR=$(CROSS)ar
RM=rm -f
CFLAGS=-g -O0 -pthread -fPIC -Wall -Wno-address-of-packed-member
LDFLAGS=-pthread
LIBS=nettle

LDLIBS= $(shell pkg-config --libs $(LIBS))
INCLUDES=-Iinclude/juice $(shell pkg-config --cflags $(LIBS))

SRCS=$(shell printf "%s " src/*.c)
OBJS=$(subst .c,.o,$(SRCS))

all: $(NAME).a $(NAME).so tests

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -MMD -MP -o $@ -c $<

test/%.o: test/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -Iinclude -Isrc -MMD -MP -o $@ -c $<

-include $(subst .c,.d,$(SRCS))

$(NAME).a: $(OBJS)
	$(AR) crf $@ $(OBJS)

$(NAME).so: $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $(OBJS) $(LDLIBS)

tests: $(NAME).a test/main.o
	$(CC) $(LDFLAGS) -o $@ test/main.o $(LDLIBS) $(NAME).a

clean:
	-$(RM) include/juice/*.d *.d
	-$(RM) src/*.o src/*.d
	-$(RM) test/*.o test/*.d

dist-clean: clean
	-$(RM) $(NAME).a
	-$(RM) $(NAME).so
	-$(RM) tests
	-$(RM) include/*~
	-$(RM) src/*~
	-$(RM) test/*~

