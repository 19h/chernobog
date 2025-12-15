# Convenience Makefile for Chernobog - Hikari Deobfuscator

BUILD_DIR = build
PLUGIN_NAME = chernobog

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
	@cp $(BUILD_DIR)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
	@echo "Signing plugin (macOS)..."
	@codesign -s - -f ~/.idapro/plugins/$(PLUGIN_NAME)*.dylib 2>/dev/null || true
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
