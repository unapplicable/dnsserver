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
                 zone.cpp zone_authority.cpp \
                 update_processor.cpp query_processor.cpp \
                 rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                 rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_UPDATE_SOURCES = test_dns_update.cpp message.cpp rr.cpp zoneFileLoader.cpp \
                      zone.cpp zone_authority.cpp \
                      update_processor.cpp query_processor.cpp \
                      rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                      rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_QUERY_SOURCES = test_query_processor.cpp zone.cpp \
                     rr.cpp rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                     rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_RR_SOURCES = test_rr_types.cpp message.cpp rr.cpp zoneFileLoader.cpp \
                  zone.cpp zone_authority.cpp \
                  update_processor.cpp query_processor.cpp \
                  rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                  rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

# Object files
SERVER_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SERVER_SOURCES))
TEST_UPDATE_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_%.o,$(TEST_UPDATE_SOURCES))
TEST_QUERY_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_qp_%.o,$(TEST_QUERY_SOURCES))
TEST_RR_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_rr_%.o,$(TEST_RR_SOURCES))

# Executables
SERVER_BIN = $(BIN_DIR)/dnsserver
TEST_UPDATE_BIN = $(BIN_DIR)/test_dns_update
TEST_QUERY_BIN = $(BIN_DIR)/test_query_processor
TEST_RR_BIN = $(BIN_DIR)/test_rr_types

# Default target
all: $(SERVER_BIN)

# Create directories
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# Build server
$(SERVER_BIN): $(SERVER_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_OBJECTS) $(LDFLAGS)

# Build tests
test: $(TEST_UPDATE_BIN) $(TEST_QUERY_BIN) $(TEST_RR_BIN)
	@echo "Running UPDATE unit tests..."
	$(TEST_UPDATE_BIN)
	@echo "Running QueryProcessor unit tests..."
	$(TEST_QUERY_BIN)
	@echo "Running RR types unit tests..."
	$(TEST_RR_BIN)

$(TEST_UPDATE_BIN): $(TEST_UPDATE_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_UPDATE_OBJECTS) $(TEST_LDFLAGS)

$(TEST_QUERY_BIN): $(TEST_QUERY_OBJECTS) $(BUILD_DIR)/query_processor.o | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_QUERY_OBJECTS) $(BUILD_DIR)/query_processor.o -lpthread

$(TEST_RR_BIN): $(TEST_RR_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_RR_OBJECTS) $(TEST_LDFLAGS)

# Build object files
$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_qp_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_rr_%.o: %.cpp | $(BUILD_DIR)
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
$(BUILD_DIR)/dnsserver.o: dnsserver.cpp socket.h zone.h message.h rr.h zoneFileLoader.h zone_authority.h update_processor.h query_processor.h
$(BUILD_DIR)/message.o: message.cpp message.h rr.h socket.h
$(BUILD_DIR)/rr.o: rr.cpp rr.h socket.h rrsoa.h rrmx.h rrtxt.h rrptr.h rrcname.h rrns.h rraaaa.h rra.h rrcert.h rrdhcid.h
$(BUILD_DIR)/zoneFileLoader.o: zoneFileLoader.cpp zoneFileLoader.h zone.h rr.h
$(BUILD_DIR)/zone.o: zone.cpp zone.h rr.h
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
$(BUILD_DIR)/test_qp_test_query_processor.o: test_query_processor.cpp query_processor.h zone.h rr.h
$(BUILD_DIR)/test_rr_test_rr_types.o: test_rr_types.cpp message.h rr.h rra.h rraaaa.h rrcert.h rrcname.h rrdhcid.h rrmx.h rrns.h rrptr.h rrsoa.h rrtxt.h zoneFileLoader.h zone.h

.PHONY: all test test-integration test-all clean rebuild run-test
