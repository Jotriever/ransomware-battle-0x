CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -Isrc $(shell pkg-config fuse3 --cflags)
LDFLAGS = $(shell pkg-config fuse3 --libs) -lpthread -lm
TARGET = blue2
SRCDIR = src

# 소스 파일 목록
SOURCES = $(SRCDIR)/blue2.c \
          $(SRCDIR)/analyzer.c \
          $(SRCDIR)/entropy.c \
          $(SRCDIR)/extension_checker.c \
          $(SRCDIR)/file_size_tracker.c \
          $(SRCDIR)/logger.c \
          $(SRCDIR)/pattern_detector.c \
          $(SRCDIR)/whitelist.c \
          $(SRCDIR)/blacklist.c \
          $(SRCDIR)/dummy_file.c \
          $(SRCDIR)/process_tracker.c \
          $(SRCDIR)/restore.c

# 오브젝트 파일 목록
OBJECTS = $(SOURCES:.c=.o)

# 기본 타겟
all: $(TARGET)

# 타겟 빌드 (오브젝트 파일들을 링크)
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# 오브젝트 파일 컴파일 규칙
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리
clean:
	rm -f $(TARGET) $(OBJECTS)
	@echo "Clean complete"

# 재컴파일
rebuild: clean all

# 의존성 확인 (선택사항)
deps:
	@echo "Checking dependencies..."
	@pkg-config --exists fuse3 || (echo "Error: fuse3 not found. Install with: sudo apt-get install libfuse3-dev" && exit 1)
	@echo "All dependencies satisfied"

.PHONY: all clean rebuild deps
