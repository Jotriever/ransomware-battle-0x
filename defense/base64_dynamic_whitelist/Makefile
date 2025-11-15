CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -Isrc $(shell pkg-config fuse3 --cflags)
LDFLAGS = $(shell pkg-config fuse3 --libs) -lpthread -lm
TARGET = blue2
SRCDIR = src

# 기본 타겟
all: $(TARGET)

# 소스 파일을 직접 컴파일하고 링크
$(TARGET): $(SRCDIR)/blue2.c $(SRCDIR)/analyzer.c $(SRCDIR)/entropy.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 정리
clean:
	rm -f $(TARGET)

# 재컴파일
rebuild: clean all

.PHONY: all clean rebuild

