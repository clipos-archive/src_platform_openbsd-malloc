CC ?= gcc

LIB := libopenbsd-malloc.so
MAJOR := 0
MINOR := 0
MICRO := 0
FULLVER := ${MAJOR}.${MINOR}.${MICRO}
LIB_FULLVER := ${LIB}.${FULLVER}


DEFINES := -D__LINUX__ -DLINUX_THREADS
LFLAGS := -Wl,-soname,${LIB}.${MAJOR}

OBJS_DIR ?= obj

DEPS_DIR = ${OBJS_DIR}/.deps

all: build

${OBJS_DIR}:
	mkdir -p ${OBJS_DIR}

${DEPS_DIR}:
	mkdir -p ${DEPS_DIR}

${OBJS_DIR}/%.o:%.c Makefile
	$(CC) $(DEFINES) -fpic $(CFLAGS) $(IFLAGS) -MT $@ -MD -MP -MF ${DEPS_DIR}/$*.d -c -o $@ $<

build: ${OBJS_DIR} ${DEPS_DIR} ${LIB_FULLVER}

${LIB_FULLVER}: ${OBJS_DIR}/malloc.o ${OBJS_DIR}/arc4random.o
	$(CC) -shared $(CFLAGS) $(LFLAGS) -o $@ $^ $(LDFLAGS)
	ln -sf $@ ${LIB}
	ln -sf $@ ${LIB}.${MAJOR}

clean:
	rm -f ${LIB_FULLVER} ${LIB}.${MAJOR} ${LIB} 
	rm -fr ${OBJS_DIR}

-include ${DEPS_DIR}/*.d
