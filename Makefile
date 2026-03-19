# Convenience Makefile for Chernobog - Hikari Deobfuscator

BUILD_DIR = build
PLUGIN_NAME = chernobog
WINDOWS_CLANG_PRESET = windows-clang-release
# IDA SDK cmake outputs to bin/plugins (or src/bin/plugins for GitHub SDK structure)
IDASDK_PLUGINS = $(IDASDK)/bin/plugins
IDASDK_PLUGINS_SRC = $(IDASDK)/src/bin/plugins

.PHONY: all clean configure build configure-windows-clang build-windows-clang install

all: build

configure:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. -G Ninja

build: configure
	@cd $(BUILD_DIR) && ninja

configure-windows-clang:
	@test -n "$(XWIN_ROOT)" || (echo "XWIN_ROOT is not set" && exit 1)
	@cmake --preset $(WINDOWS_CLANG_PRESET) -DXWIN_ROOT="$(XWIN_ROOT)"

build-windows-clang: configure-windows-clang
	@cmake --build --preset $(WINDOWS_CLANG_PRESET)

clean:
	@rm -rf $(BUILD_DIR) out

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
	@echo "  configure-windows-clang - Configure Windows x64 cross-build"
	@echo "  build-windows-clang     - Build Windows x64 with clang-cl + xwin"
	@echo "  clean     - Remove build directory"
	@echo "  install   - Build and install to ~/.idapro/plugins"
	@echo ""
	@echo "Requirements:"
	@echo "  - IDA SDK (set IDASDK environment variable)"
	@echo "  - XWIN_ROOT (for Windows clang cross-builds)"
	@echo "  - CMake 3.27+"
	@echo "  - Ninja build system"
