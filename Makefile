# Makefile for DNS Server with UPDATE support

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++14 -g -DLINUX
LDFLAGS = -lpthread
TEST_LDFLAGS = -lpthread -lCatch2Main -lCatch2

# Directories
BUILD_DIR = build
BIN_DIR = bin

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
SERVER_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SERVER_SOURCES))
TEST_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_%.o,$(TEST_SOURCES))

# Executables
SERVER_BIN = $(BIN_DIR)/dnsserver
TEST_BIN = $(BIN_DIR)/test_dns_update

# Default target
all: $(SERVER_BIN)

# Create directories
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# Build server
$(SERVER_BIN): $(SERVER_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_OBJECTS) $(LDFLAGS)

# Build tests
test: $(TEST_BIN)
	@echo "Running unit tests..."
	$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJECTS) $(TEST_LDFLAGS)

# Build object files
$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%.o: %.cpp | $(BUILD_DIR)
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
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f *.o test_update.log dnsserver test_dns_update

# Rebuild
rebuild: clean all

# Run server on test zone
run-test: $(SERVER_BIN)
	$(SERVER_BIN) 127.0.0.1 5353 test.zone

# Dependencies
$(BUILD_DIR)/dnsserver.o: dnsserver.cpp socket.h zone.h message.h rr.h zoneFileLoader.h zone_database.h zone_authority.h update_processor.h query_processor.h
$(BUILD_DIR)/message.o: message.cpp message.h rr.h socket.h
$(BUILD_DIR)/rr.o: rr.cpp rr.h socket.h rrsoa.h rrmx.h rrtxt.h rrptr.h rrcname.h rrns.h rraaaa.h rra.h rrcert.h rrdhcid.h
$(BUILD_DIR)/zoneFileLoader.o: zoneFileLoader.cpp zoneFileLoader.h zone.h rr.h
$(BUILD_DIR)/zone_database.o: zone_database.cpp zone_database.h zone.h rr.h
$(BUILD_DIR)/zone_authority.o: zone_authority.cpp zone_authority.h zone.h rr.h
$(BUILD_DIR)/update_processor.o: update_processor.cpp update_processor.h message.h zone_authority.h rr.h
$(BUILD_DIR)/query_processor.o: query_processor.cpp query_processor.h message.h zone_authority.h rr.h
$(BUILD_DIR)/rra.o: rra.cpp rra.h rr.h socket.h
$(BUILD_DIR)/rraaaa.o: rraaaa.cpp rraaaa.h rr.h socket.h
$(BUILD_DIR)/rrcert.o: rrcert.cpp rrcert.h rr.h socket.h
$(BUILD_DIR)/rrcname.o: rrcname.cpp rrcname.h rr.h socket.h
$(BUILD_DIR)/rrdhcid.o: rrdhcid.cpp rrdhcid.h rr.h socket.h
$(BUILD_DIR)/rrmx.o: rrmx.cpp rrmx.h rr.h socket.h
$(BUILD_DIR)/rrns.o: rrns.cpp rrns.h rr.h socket.h
$(BUILD_DIR)/rrptr.o: rrptr.cpp rrptr.h rr.h socket.h
$(BUILD_DIR)/rrsoa.o: rrsoa.cpp rrsoa.h rr.h socket.h
$(BUILD_DIR)/rrtxt.o: rrtxt.cpp rrtxt.h rr.h socket.h

$(BUILD_DIR)/test_test_dns_update.o: test_dns_update.cpp message.h rr.h update_processor.h zone_authority.h

.PHONY: all test test-integration test-all clean rebuild run-test
