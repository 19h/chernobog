# Convenience Makefile for Chernobog - Hikari Deobfuscator

BUILD_DIR = build
PLUGIN_NAME = chernobog
# IDA SDK cmake outputs to bin/plugins (or src/bin/plugins for GitHub SDK structure)
IDASDK_PLUGINS = $(IDASDK)/bin/plugins
IDASDK_PLUGINS_SRC = $(IDASDK)/src/bin/plugins

.PHONY: all clean configure build install

all: build

configure:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. -G Ninja

build: configure
	@cd $(BUILD_DIR) && ninja

clean:
	@rm -rf $(BUILD_DIR)

install: build
	@echo "Installing plugin..."
	@mkdir -p ~/.idapro/plugins
ifeq ($(shell uname -s),Darwin)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
	@echo "Signing plugin (macOS)..."
	@codesign -s - -f ~/.idapro/plugins/$(PLUGIN_NAME)*.dylib 2>/dev/null || true
else ifeq ($(shell uname -s),Linux)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
else
	@cp $(BUILD_DIR)/$(PLUGIN_NAME)64.dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dll ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
endif
	@echo "Done!"

help:
	@echo "Chernobog - Hikari Deobfuscator Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the plugin (default)"
	@echo "  configure - Run CMake configuration"
	@echo "  build     - Build the plugin"
	@echo "  clean     - Remove build directory"
	@echo "  install   - Build and install to ~/.idapro/plugins"
	@echo ""
	@echo "Requirements:"
	@echo "  - IDA SDK (set IDASDK environment variable)"
	@echo "  - CMake 3.10+"
	@echo "  - Ninja build system"
