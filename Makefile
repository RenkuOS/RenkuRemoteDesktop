# RenkuRemoteDesktop
#
#   make            build for the host: the server, preferences, and input
#                   add-on on Haiku, the test harness on Linux
#   make test       build and run the unit tests
#   make install    install the server, preferences, input add-on, and
#                   launch_daemon service (Haiku; PREFIX, default
#                   /boot/system/non-packaged, and DESTDIR)
#   make clean

UNAME := $(shell uname)
BUILD := build/$(UNAME)

CXX ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-unused-parameter -Isrc/core -MMD -MP

CORE_SOURCES := \
	src/core/Auth.cpp \
	src/core/Capabilities.cpp \
	src/core/ClipboardChannel.cpp \
	src/core/CredSsp.cpp \
	src/core/Crypto.cpp \
	src/core/Der.cpp \
	src/core/DynamicChannels.cpp \
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
	src/haiku/ObserverFrameSource.cpp src/haiku/HaikuClipboard.cpp \
	src/haiku/PortInputSink.cpp
SERVER_RSRC := $(BUILD)/src/haiku/RenkuRemoteDesktop.rsrc
ADDON := $(BUILD)/RenkuRemoteDesktopInput
ADDON_SOURCES := src/haiku/input/RemoteInputDevice.cpp
PREFS := $(BUILD)/RemoteDesktopPrefs
PREFS_SOURCES := src/haiku/prefs/RemoteDesktopPrefs.cpp \
	src/haiku/prefs/PrefsWindow.cpp src/haiku/prefs/PasswordWindow.cpp \
	src/haiku/prefs/ServiceControl.cpp
PREFS_RSRC := $(BUILD)/src/haiku/prefs/RemoteDesktopPrefs.rsrc
PREFS_LIBS := -lssl -lcrypto -lnetwork -lbnetapi -lbe -llocalestub
TARGETS := $(SERVER) $(ADDON) $(PREFS)
# The screen observer talks to app_server, and the preferences to
# launch_daemon, through private libbe classes.
PRIVATE_HEADERS := /boot/system/develop/headers/private
$(BUILD)/src/haiku/ObserverFrameSource.o: CXXFLAGS += \
	-I$(PRIVATE_HEADERS)/app -I$(PRIVATE_HEADERS)/interface
$(BUILD)/src/haiku/prefs/%.o: CXXFLAGS += -Isrc/haiku -I$(PRIVATE_HEADERS)/app
else
LIBS := -lssl -lcrypto -lpthread
SERVER := $(BUILD)/rrd-test-server
SERVER_SOURCES := src/linux/TestServer.cpp
TARGETS := $(SERVER)
endif

SERVER_OBJECTS := $(SERVER_SOURCES:%.cpp=$(BUILD)/%.o)
PREFS_OBJECTS := $(PREFS_SOURCES:%.cpp=$(BUILD)/%.o)
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

$(PREFS): $(CORE_OBJECTS) $(PREFS_OBJECTS) $(PREFS_RSRC)
	$(CXX) -o $@ $(CORE_OBJECTS) $(PREFS_OBJECTS) $(PREFS_LIBS)
	xres -o $@ $(PREFS_RSRC)
	mimeset -f $@

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

# Installs below PREFIX, the path the files have on the running system.
# DESTDIR, if set, is a staging directory in front of it. The launch_daemon
# service gets the server's path below PREFIX.
PREFIX ?= /boot/system/non-packaged
INSTALL_DIR := $(DESTDIR)$(PREFIX)

install: all
	mkdir -p $(INSTALL_DIR)/servers $(INSTALL_DIR)/preferences \
		$(INSTALL_DIR)/add-ons/input_server/devices \
		$(INSTALL_DIR)/data/user_launch
	cp $(SERVER) $(INSTALL_DIR)/servers/RenkuRemoteDesktop
	cp $(PREFS) "$(INSTALL_DIR)/preferences/Remote Desktop"
	cp $(ADDON) $(INSTALL_DIR)/add-ons/input_server/devices/
	sed "s|@SERVER@|$(PREFIX)/servers/RenkuRemoteDesktop|" \
		data/RenkuRemoteDesktop.launch \
		> $(INSTALL_DIR)/data/user_launch/RenkuRemoteDesktop

clean:
	rm -rf build

.PHONY: all test install clean

-include $(CORE_OBJECTS:.o=.d) $(SERVER_OBJECTS:.o=.d) \
	$(ADDON_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d) $(PREFS_OBJECTS:.o=.d)
