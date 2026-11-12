# RenkuRemoteDesktop
#
#   make            build for the host: the server and input add-on on Haiku,
#                   the test harness on Linux
#   make test       build and run the unit tests
#   make clean

UNAME := $(shell uname)
BUILD := build/$(UNAME)

CXX ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-unused-parameter -Isrc/core -MMD -MP

CORE_SOURCES := \
	src/core/Auth.cpp \
	src/core/Capabilities.cpp \
	src/core/CredSsp.cpp \
	src/core/Crypto.cpp \
	src/core/Der.cpp \
	src/core/Log.cpp \
	src/core/Mcs.cpp \
	src/core/Ntlm.cpp \
	src/core/Planar.cpp \
	src/core/Pointer.cpp \
	src/core/Resize.cpp \
	src/core/Server.cpp \
	src/core/Session.cpp \
	src/core/Settings.cpp \
	src/core/Transport.cpp

CORE_OBJECTS := $(CORE_SOURCES:%.cpp=$(BUILD)/%.o)

ifeq ($(UNAME),Haiku)
LIBS := -lssl -lcrypto -lnetwork -lbe
SERVER := $(BUILD)/RenkuRemoteDesktop
SERVER_SOURCES := src/haiku/HaikuMain.cpp src/haiku/ScreenFrameSource.cpp \
	src/haiku/ObserverFrameSource.cpp \
	src/haiku/PortInputSink.cpp
SERVER_RSRC := $(BUILD)/src/haiku/RenkuRemoteDesktop.rsrc
ADDON := $(BUILD)/RenkuRemoteDesktopInput
ADDON_SOURCES := src/haiku/input/RemoteInputDevice.cpp
TARGETS := $(SERVER) $(ADDON)
# The screen observer talks to app_server through private libbe classes.
PRIVATE_HEADERS := /boot/system/develop/headers/private
$(BUILD)/src/haiku/ObserverFrameSource.o: CXXFLAGS += \
	-I$(PRIVATE_HEADERS)/app -I$(PRIVATE_HEADERS)/interface
else
LIBS := -lssl -lcrypto -lpthread
SERVER := $(BUILD)/rrd-test-server
SERVER_SOURCES := src/linux/TestServer.cpp
TARGETS := $(SERVER)
endif

SERVER_OBJECTS := $(SERVER_SOURCES:%.cpp=$(BUILD)/%.o)
ADDON_OBJECTS := $(ADDON_SOURCES:%.cpp=$(BUILD)/%.o)

TEST_SOURCES := tests/UnitTests.cpp
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD)/%.o)
TESTS := $(BUILD)/rrd-unit-tests

all: $(TARGETS)

$(SERVER): $(CORE_OBJECTS) $(SERVER_OBJECTS) $(SERVER_RSRC)
	$(CXX) -o $@ $(CORE_OBJECTS) $(SERVER_OBJECTS) $(LIBS)
ifneq ($(SERVER_RSRC),)
	xres -o $@ $(SERVER_RSRC)
	mimeset -f $@
endif

$(BUILD)/%.rsrc: %.rdef
	@mkdir -p $(dir $@)
	rc -o $@ $<

$(ADDON): $(ADDON_OBJECTS)
	$(CXX) -shared -o $@ $^ -lbe -lshared

$(TESTS): $(CORE_OBJECTS) $(TEST_OBJECTS)
	$(CXX) -o $@ $^ $(LIBS)

$(BUILD)/src/haiku/input/%.o: src/haiku/input/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

test: $(TESTS)
	$(TESTS)

clean:
	rm -rf build

.PHONY: all test clean

-include $(CORE_OBJECTS:.o=.d) $(SERVER_OBJECTS:.o=.d) \
	$(ADDON_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
