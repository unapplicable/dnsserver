# Makefile for DNS Server with UPDATE support

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++14 -g -DLINUX
LDFLAGS = -lpthread -lssl -lcrypto
TEST_LDFLAGS = -lpthread -lssl -lcrypto -lCatch2Main -lCatch2

# Version information
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date '+%Y-%m-%d %H:%M:%S')
VERSION_FILE = version.h

# Directories
BUILD_DIR = build
BIN_DIR = bin

# Source files
SERVER_SOURCES = dnsserver.cpp message.cpp rr.cpp acl.cpp zoneFileLoader.cpp zoneFileSaver.cpp \
                 zone.cpp zone_authority.cpp \
                 update_processor.cpp query_processor.cpp \
                 rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                 rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp \
                 tsig.cpp

TEST_UPDATE_SOURCES = test_dns_update.cpp message.cpp rr.cpp acl.cpp zoneFileLoader.cpp \
                      zoneFileSaver.cpp zone.cpp zone_authority.cpp \
                      update_processor.cpp query_processor.cpp \
                      rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                      rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp \
                      tsig.cpp

TEST_QUERY_SOURCES = test_query_processor.cpp message.cpp acl.cpp zoneFileLoader.cpp zoneFileSaver.cpp zone.cpp \
                     rr.cpp rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                     rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp tsig.cpp

TEST_RR_SOURCES = test_rr_types.cpp message.cpp rr.cpp acl.cpp zoneFileLoader.cpp \
                  zoneFileSaver.cpp zone.cpp zone_authority.cpp \
                  update_processor.cpp query_processor.cpp \
                  rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                  rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp \
                  tsig.cpp

TEST_TSIG_SOURCES = test_tsig.cpp tsig.cpp rrtsig.cpp rr.cpp acl.cpp \
                    message.cpp zone.cpp zoneFileLoader.cpp zoneFileSaver.cpp zone_authority.cpp \
                    rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                    rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp \
                    update_processor.cpp query_processor.cpp

TEST_ACL_SOURCES = test_acl.cpp acl.cpp zone.cpp zoneFileLoader.cpp zoneFileSaver.cpp \
                   rr.cpp tsig.cpp rrtsig.cpp message.cpp zone_authority.cpp \
                   rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                   rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp \
                   update_processor.cpp query_processor.cpp

TEST_RR_ROUNDTRIP_SOURCES = test_rr_roundtrip.cpp message.cpp rr.cpp acl.cpp zoneFileLoader.cpp \
                            zoneFileSaver.cpp zone.cpp zone_authority.cpp \
                            rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                            rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp \
                            tsig.cpp update_processor.cpp query_processor.cpp

TEST_ZONE_ROUNDTRIP_SOURCES = test_zone_roundtrip.cpp message.cpp rr.cpp acl.cpp zoneFileLoader.cpp \
                              zoneFileSaver.cpp zone.cpp zone_authority.cpp \
                              rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                              rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp rrtsig.cpp \
                              tsig.cpp update_processor.cpp query_processor.cpp

TEST_TSIG_HMAC_SOURCES = test_tsig_hmac.cpp tsig.cpp rrtsig.cpp rr.cpp message.cpp \
                        rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                        rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_ZONE_MATCHING_SOURCES = test_zone_matching.cpp zone.cpp zone_authority.cpp zoneFileLoader.cpp zoneFileSaver.cpp \
                             rr.cpp acl.cpp tsig.cpp rrtsig.cpp message.cpp \
                             rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                             rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp

TEST_ACL_QUERY_SOURCES = test_acl_query.cpp query_processor.cpp zone.cpp zoneFileLoader.cpp zoneFileSaver.cpp \
                         acl.cpp zone_authority.cpp rr.cpp tsig.cpp rrtsig.cpp message.cpp \
                         rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                         rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp update_processor.cpp

TEST_ACL_UNAUTHORIZED_SOURCES = test_acl_unauthorized.cpp zone_authority.cpp zone.cpp zoneFileLoader.cpp zoneFileSaver.cpp \
                                acl.cpp rr.cpp tsig.cpp rrtsig.cpp message.cpp query_processor.cpp \
                                rra.cpp rraaaa.cpp rrcert.cpp rrcname.cpp rrmx.cpp \
                                rrns.cpp rrptr.cpp rrsoa.cpp rrtxt.cpp rrdhcid.cpp update_processor.cpp

# Object files
SERVER_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SERVER_SOURCES))
TEST_UPDATE_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_%.o,$(TEST_UPDATE_SOURCES))
TEST_QUERY_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_qp_%.o,$(TEST_QUERY_SOURCES))
TEST_RR_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_rr_%.o,$(TEST_RR_SOURCES))
TEST_TSIG_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_tsig_%.o,$(TEST_TSIG_SOURCES))
TEST_ACL_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_acl_%.o,$(TEST_ACL_SOURCES))
TEST_RR_ROUNDTRIP_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_rr_rt_%.o,$(TEST_RR_ROUNDTRIP_SOURCES))
TEST_ZONE_ROUNDTRIP_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_zone_rt_%.o,$(TEST_ZONE_ROUNDTRIP_SOURCES))
TEST_TSIG_HMAC_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_tsig_hmac_%.o,$(TEST_TSIG_HMAC_SOURCES))
TEST_ZONE_MATCHING_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_zone_match_%.o,$(TEST_ZONE_MATCHING_SOURCES))
TEST_ACL_QUERY_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_acl_query_%.o,$(TEST_ACL_QUERY_SOURCES))
TEST_ACL_UNAUTHORIZED_OBJECTS = $(patsubst %.cpp,$(BUILD_DIR)/test_acl_unauth_%.o,$(TEST_ACL_UNAUTHORIZED_SOURCES))

# Executables
SERVER_BIN = $(BIN_DIR)/dnsserver
TEST_UPDATE_BIN = $(BIN_DIR)/test_dns_update
TEST_QUERY_BIN = $(BIN_DIR)/test_query_processor
TEST_RR_BIN = $(BIN_DIR)/test_rr_types
TEST_TSIG_BIN = $(BIN_DIR)/test_tsig
TEST_ACL_BIN = $(BIN_DIR)/test_acl
TEST_RR_ROUNDTRIP_BIN = $(BIN_DIR)/test_rr_roundtrip
TEST_ZONE_ROUNDTRIP_BIN = $(BIN_DIR)/test_zone_roundtrip
TEST_TSIG_HMAC_BIN = $(BIN_DIR)/test_tsig_hmac
TEST_ZONE_MATCHING_BIN = $(BIN_DIR)/test_zone_matching
TEST_ACL_QUERY_BIN = $(BIN_DIR)/test_acl_query
TEST_ACL_UNAUTHORIZED_BIN = $(BIN_DIR)/test_acl_unauthorized

# Default target
all: $(VERSION_FILE) $(SERVER_BIN)

# Generate version header
$(VERSION_FILE):
	@echo "Generating version information..."
	@echo "#ifndef VERSION_H" > $(VERSION_FILE)
	@echo "#define VERSION_H" >> $(VERSION_FILE)
	@echo "#define GIT_HASH \"$(GIT_HASH)\"" >> $(VERSION_FILE)
	@echo "#define GIT_BRANCH \"$(GIT_BRANCH)\"" >> $(VERSION_FILE)
	@echo "#define BUILD_DATE \"$(BUILD_DATE)\"" >> $(VERSION_FILE)
	@echo "#define VERSION \"$(GIT_BRANCH)-$(GIT_HASH) (built $(BUILD_DATE))\"" >> $(VERSION_FILE)
	@echo "#endif" >> $(VERSION_FILE)

# Create directories
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# Build server
$(SERVER_BIN): $(SERVER_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_OBJECTS) $(LDFLAGS)

# Build tests
test: $(TEST_UPDATE_BIN) $(TEST_QUERY_BIN) $(TEST_RR_BIN) $(TEST_TSIG_BIN) $(TEST_ACL_BIN) $(TEST_RR_ROUNDTRIP_BIN) $(TEST_ZONE_ROUNDTRIP_BIN) $(TEST_TSIG_HMAC_BIN) $(TEST_ZONE_MATCHING_BIN) $(TEST_ACL_QUERY_BIN) $(TEST_ACL_UNAUTHORIZED_BIN)
	@echo "Running UPDATE unit tests..."
	$(TEST_UPDATE_BIN)
	@echo "Running QueryProcessor unit tests..."
	$(TEST_QUERY_BIN)
	@echo "Running RR types unit tests..."
	$(TEST_RR_BIN)
	@echo "Running TSIG unit tests..."
	$(TEST_TSIG_BIN)
	@echo "Running ACL unit tests..."
	$(TEST_ACL_BIN)
	@echo "Running RR roundtrip tests..."
	$(TEST_RR_ROUNDTRIP_BIN)
	@echo "Running Zone roundtrip tests..."
	$(TEST_ZONE_ROUNDTRIP_BIN)
	@echo "Running TSIG HMAC tests..."
	$(TEST_TSIG_HMAC_BIN)
	@echo "Running Zone matching tests..."
	$(TEST_ZONE_MATCHING_BIN)
	@echo "Running ACL query tests..."
	$(TEST_ACL_QUERY_BIN)
	@echo "Running ACL unauthorized tests..."
	$(TEST_ACL_UNAUTHORIZED_BIN)

$(TEST_UPDATE_BIN): $(TEST_UPDATE_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_UPDATE_OBJECTS) $(TEST_LDFLAGS)

$(TEST_QUERY_BIN): $(TEST_QUERY_OBJECTS) $(BUILD_DIR)/query_processor.o | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_QUERY_OBJECTS) $(BUILD_DIR)/query_processor.o -lpthread -lssl -lcrypto

$(TEST_RR_BIN): $(TEST_RR_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_RR_OBJECTS) $(TEST_LDFLAGS)

$(TEST_TSIG_BIN): $(TEST_TSIG_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_TSIG_OBJECTS) -lpthread -lssl -lcrypto

$(TEST_ACL_BIN): $(TEST_ACL_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_ACL_OBJECTS) -lpthread -lssl -lcrypto

$(TEST_RR_ROUNDTRIP_BIN): $(TEST_RR_ROUNDTRIP_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_RR_ROUNDTRIP_OBJECTS) $(TEST_LDFLAGS)

$(TEST_ZONE_ROUNDTRIP_BIN): $(TEST_ZONE_ROUNDTRIP_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_ZONE_ROUNDTRIP_OBJECTS) $(TEST_LDFLAGS)

$(TEST_TSIG_HMAC_BIN): $(TEST_TSIG_HMAC_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_TSIG_HMAC_OBJECTS) -lpthread -lssl -lcrypto

$(TEST_ZONE_MATCHING_BIN): $(TEST_ZONE_MATCHING_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_ZONE_MATCHING_OBJECTS) -lpthread -lssl -lcrypto

$(TEST_ACL_QUERY_BIN): $(TEST_ACL_QUERY_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_ACL_QUERY_OBJECTS) -lpthread -lssl -lcrypto

$(TEST_ACL_UNAUTHORIZED_BIN): $(TEST_ACL_UNAUTHORIZED_OBJECTS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_ACL_UNAUTHORIZED_OBJECTS) -lpthread -lssl -lcrypto

# Build object files
$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_qp_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_rr_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_tsig_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_acl_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_rr_rt_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_zone_rt_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_tsig_hmac_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_zone_match_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_acl_query_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_acl_unauth_%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Integration tests
test-integration: $(SERVER_BIN)
	@echo "Running integration tests..."
	@chmod +x test_update.sh test_wildcard_simple.sh test_tsig.sh
	./test_update.sh
	./test_wildcard_simple.sh
	./test_tsig.sh

# Full test suite
test-all: test test-integration

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f *.o test_update.log dnsserver test_dns_update $(VERSION_FILE)

# Rebuild
rebuild: clean all

# Run server on test zone
run-test: $(SERVER_BIN)
	$(SERVER_BIN) 127.0.0.1 5353 test.zone

# Dependencies
$(BUILD_DIR)/dnsserver.o: dnsserver.cpp socket.h zone.h message.h rr.h zoneFileLoader.h zone_authority.h update_processor.h query_processor.h $(VERSION_FILE)
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
