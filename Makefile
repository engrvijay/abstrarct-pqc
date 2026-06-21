# Compiler
CC = gcc

# Compiler flags
CFLAGS = -I/usr/local/include

# Linker flags
LDFLAGS = -L/usr/local/lib

# Libraries
LIBS = -loqs -lm

# Target executable
TARGET = pqc_example

# Source files
SRCS = pqc_example.c pqc_abstract.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link executable
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
