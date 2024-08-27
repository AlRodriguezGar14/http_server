CXX = gcc
CXXFLAGS = -Wall -Wextra -Werror -I ./
LDFLAGS = -lz

SRCS =	src/action_handlers.c \
		src/compressor.c \
		src/get_info.c \
		src/memory_pools.c \
		src/parsers.c \
		src/queue.c \
		src/threads.c \
		src/server.c

OBJS = $(SRCS:.c=.o)

TARGET = server

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking the object files to create the executable..."
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@echo "Compiling the source file $< into the object file $@..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@echo "Removing the object files..."
	@rm -f $(OBJS) *.gch

fclean: clean
	@echo "Removing the executable..."
	@rm -f $(TARGET)

re: fclean all

.PHONY: all clean fclean re
