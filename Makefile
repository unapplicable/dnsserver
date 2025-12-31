# Makefile for DNS Server with UPDATE support

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++14 -g -DLINUX
LDFLAGS = -lpthread
TEST_LDFLAGS = -lpthread -lCatch2Main -lCatch2

# Source files
SERVER_SOURCES = dnsserver.cpp message.cpp rr.cpp zoneFileLoader.cpp \
                 zone_database.cpp zone_authority.cpp \
                 update_processor.cpp query_processor.cpp \
                 rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                 rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_SOURCES = test_dns_update.cpp message.cpp rr.cpp zoneFileLoader.cpp \
               zone_database.cpp zone_authority.cpp \
               update_processor.cpp query_processor.cpp \
               rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
               rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

# Object files
SERVER_OBJECTS = $(SERVER_SOURCES:.cpp=.o)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)

# Executables
SERVER_BIN = dnsserver
TEST_BIN = test_dns_update

# Default target
all: $(SERVER_BIN)

# Build server
$(SERVER_BIN): $(SERVER_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Build tests
test: $(TEST_BIN)
	@echo "Running unit tests..."
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TEST_LDFLAGS)

# Build object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Integration tests
test-integration: $(SERVER_BIN)
	@echo "Running integration tests..."
	@chmod +x test_update.sh
	./test_update.sh

# Full test suite
test-all: test test-integration

# Clean
clean:
	rm -f $(SERVER_OBJECTS) $(TEST_OBJECTS) $(SERVER_BIN) $(TEST_BIN)
	rm -f *.o test_update.log

# Rebuild
rebuild: clean all

# Run server on test zone
run-test: $(SERVER_BIN)
	./$(SERVER_BIN) 127.0.0.1 5353 test.zone

# Dependencies
dnsserver.o: dnsserver.cpp socket.h zone.h message.h rr.h zoneFileLoader.h
message.o: message.cpp message.h rr.h socket.h
rr.o: rr.cpp rr.h socket.h rrsoa.h rrmx.h rrtxt.h rrptr.h rrcname.h rrns.h rraaaa.h rra.h rrcert.h
zoneFileLoader.o: zoneFileLoader.cpp zoneFileLoader.h zone.h rr.h

test_dns_update.o: test_dns_update.cpp message.h rr.h

.PHONY: all test test-integration test-all clean rebuild run-test
