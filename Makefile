# Makefile for C-Based Web Crawler
# Compile with static linking for portability

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/libxml2 -I/usr/include/mariadb
LDFLAGS = -lcurl -lxml2 -lmariadb -lz -lssl -lcrypto

# For static compilation (uncomment for fully static binary)
# STATIC_FLAGS = -static
# LDFLAGS = -static -lcurl -lxml2 -lmysqlclient -lpcre -lz -lssl -lcrypto -lidn2 -lunistring -lbrotlidec -lbrotlienc -lbrotlicommon -lpsl -lrtmp -lzstd -llzma -lbz2 -lnghttp2 -lssh2 -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lverto -ltevent -ltdb -ltalloc -lwbclient

TARGET = crawler
SRC = crawler.c

.PHONY: all clean test install db-schema

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Static build for maximum portability
static: $(SRC)
	$(CC) $(CFLAGS) $(STATIC_FLAGS) -o $(TARGET)-static $(SRC) $(LDFLAGS)

# Debug build with symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Run basic syntax check
check:
	$(CC) -fsyntax-only $(CFLAGS) $(SRC)

# Create database schema
db-schema:
	@echo "Creating database schema..."
	mysql -u root -p < schema.sql || echo "MySQL not available, please run schema manually"

# Install to /usr/local/bin
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

# Uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET)-static *.o

# Show help
help:
	@echo "C-Based Web Crawler Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build crawler (default)"
	@echo "  static    - Build statically linked crawler"
	@echo "  debug     - Build with debug symbols"
	@echo "  check     - Syntax check only"
	@echo "  db-schema - Create database tables"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                  # Build crawler"
	@echo "  make static           # Build static binary"
	@echo "  ./crawler -s example.com"
	@echo "  ./crawler -f seeds.txt -d 5 -m 1000"
	@echo "  ./crawler -s example.com -u root -p password -n crawler_db"
