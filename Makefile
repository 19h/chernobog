# Convenience Makefile for Chernobog - Hikari Deobfuscator

BUILD_DIR = build
OUT_DIR = out
ARTIFACT_DIR = $(OUT_DIR)/artifacts
PLUGIN_NAME = chernobog
NATIVE_PRESET = native-release
MACOS_ARM64_PRESET = macos-arm64-release
MACOS_X86_64_PRESET = macos-x86_64-release
LINUX_CLANG_PRESET = linux-clang-release
WINDOWS_CLANG_PRESET = windows-clang-release
DOCKER_LINUX_IMAGE = ubuntu:24.04
HOST_OS = $(shell uname -s)
NPROC = $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
# IDA SDK cmake outputs to bin/plugins (or src/bin/plugins for GitHub SDK structure)
IDASDK_PLUGINS = $(IDASDK)/bin/plugins
IDASDK_PLUGINS_SRC = $(IDASDK)/src/bin/plugins

ifeq ($(HOST_OS),Darwin)
ALL_PLATFORM_TARGETS = build-macos-arm64 build-macos-x86_64 build-linux-clang build-windows-clang
else ifeq ($(HOST_OS),Linux)
ALL_PLATFORM_TARGETS = build-linux-clang build-windows-clang
else
ALL_PLATFORM_TARGETS = build-windows-clang
endif

.PHONY: all all-platforms clean configure build configure-macos-arm64 build-macos-arm64 configure-macos-x86_64 build-macos-x86_64 configure-linux-clang build-linux-clang configure-windows-clang build-windows-clang install help

all: build

all-platforms: $(ALL_PLATFORM_TARGETS)
	@echo "Built multi-platform artifacts in $(ARTIFACT_DIR)"

configure:
	@cmake --preset $(NATIVE_PRESET)

build: configure
	@cmake --build --preset $(NATIVE_PRESET) --parallel $(NPROC)

configure-macos-arm64:
	@test "$(HOST_OS)" = "Darwin" || (echo "macOS arm64 builds require a macOS host" && exit 1)
	@cmake --preset $(MACOS_ARM64_PRESET)

build-macos-arm64: configure-macos-arm64
	@cmake --build --preset $(MACOS_ARM64_PRESET) --parallel $(NPROC)
	@mkdir -p $(ARTIFACT_DIR)
	@cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-arm64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-arm64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-arm64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-arm64.dylib 2>/dev/null || \
	 echo "macOS arm64 plugin not found - check build output"

configure-macos-x86_64:
	@test "$(HOST_OS)" = "Darwin" || (echo "macOS x86_64 builds require a macOS host" && exit 1)
	@cmake --preset $(MACOS_X86_64_PRESET)

build-macos-x86_64: configure-macos-x86_64
	@cmake --build --preset $(MACOS_X86_64_PRESET) --parallel $(NPROC)
	@mkdir -p $(ARTIFACT_DIR)
	@cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-x86_64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-x86_64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-x86_64.dylib 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dylib $(ARTIFACT_DIR)/$(PLUGIN_NAME)_macos-x86_64.dylib 2>/dev/null || \
	 echo "macOS x86_64 plugin not found - check build output"

configure-linux-clang:
	@if [ "$(HOST_OS)" = "Linux" ]; then \
		cmake --preset $(LINUX_CLANG_PRESET); \
	else \
		echo "configure-linux-clang is Linux-only; use build-linux-clang on macOS to build via Docker"; \
		exit 1; \
	fi

build-linux-clang:
	@test -n "$(IDASDK)" || (echo "IDASDK is not set" && exit 1)
	@if [ "$(HOST_OS)" = "Linux" ]; then \
		cmake --preset $(LINUX_CLANG_PRESET) && \
		cmake --build --preset $(LINUX_CLANG_PRESET) --parallel $(NPROC); \
	else \
		docker run --rm --platform linux/amd64 \
			-e IDASDK=/ida-sdk \
			-v "$(CURDIR)":/workspace \
			-v "$(IDASDK)":/ida-sdk \
			-w /workspace \
			$(DOCKER_LINUX_IMAGE) \
			bash -lc 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake ninja-build clang git python3 && cmake --preset $(LINUX_CLANG_PRESET) && cmake --build --preset $(LINUX_CLANG_PRESET) --parallel $$(nproc)'; \
	fi
	@mkdir -p $(ARTIFACT_DIR)
	@cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).so $(ARTIFACT_DIR)/$(PLUGIN_NAME)_linux-x86_64.so 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).so $(ARTIFACT_DIR)/$(PLUGIN_NAME)_linux-x86_64.so 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.so $(ARTIFACT_DIR)/$(PLUGIN_NAME)_linux-x86_64.so 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.so $(ARTIFACT_DIR)/$(PLUGIN_NAME)_linux-x86_64.so 2>/dev/null || \
	 echo "Linux plugin not found - check build output"

configure-windows-clang:
	@test -n "$(XWIN_ROOT)" || (echo "XWIN_ROOT is not set" && exit 1)
	@cmake --preset $(WINDOWS_CLANG_PRESET) -DXWIN_ROOT="$(XWIN_ROOT)"

build-windows-clang: configure-windows-clang
	@cmake --build --preset $(WINDOWS_CLANG_PRESET) --parallel $(NPROC)
	@mkdir -p $(ARTIFACT_DIR)
	@cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dll $(ARTIFACT_DIR)/$(PLUGIN_NAME)_windows-x86_64-clang.dll 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dll $(ARTIFACT_DIR)/$(PLUGIN_NAME)_windows-x86_64-clang.dll 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dll $(ARTIFACT_DIR)/$(PLUGIN_NAME)_windows-x86_64-clang.dll 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dll $(ARTIFACT_DIR)/$(PLUGIN_NAME)_windows-x86_64-clang.dll 2>/dev/null || \
	 echo "Windows plugin not found - check build output"

clean:
	@rm -rf $(BUILD_DIR) $(OUT_DIR)

install: build
	@echo "Installing plugin..."
	@mkdir -p ~/.idapro/plugins
ifeq ($(shell uname -s),Darwin)
	@cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.dylib ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).dylib ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
	@echo "Signing plugin (macOS)..."
	@codesign -s - -f ~/.idapro/plugins/$(PLUGIN_NAME)*.dylib 2>/dev/null || true
else ifeq ($(shell uname -s),Linux)
	@cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME)64.so ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(IDASDK_PLUGINS_SRC)/$(PLUGIN_NAME).so ~/.idapro/plugins/ 2>/dev/null || \
	 echo "Plugin not found - check build output"
else
	@cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME)64.dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/plugins/$(PLUGIN_NAME).dll ~/.idapro/plugins/ 2>/dev/null || \
	 cp $(BUILD_DIR)/$(PLUGIN_NAME)64.dll ~/.idapro/plugins/ 2>/dev/null || \
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
	@echo "  all-platforms - Build all supported platform artifacts from this host"
	@echo "  configure - Run CMake configuration"
	@echo "  build     - Build the plugin"
	@echo "  configure-macos-arm64   - Configure macOS arm64 build"
	@echo "  build-macos-arm64       - Build macOS arm64 dylib"
	@echo "  configure-macos-x86_64  - Configure macOS x86_64 build"
	@echo "  build-macos-x86_64      - Build macOS x86_64 dylib"
	@echo "  configure-linux-clang     - Configure Linux clang build on Linux hosts"
	@echo "  build-linux-clang         - Build Linux x86_64 with clang (Docker on macOS)"
	@echo "  configure-windows-clang - Configure Windows x64 cross-build"
	@echo "  build-windows-clang     - Build Windows x64 with clang-cl + xwin"
	@echo "  clean     - Remove build directory"
	@echo "  install   - Build and install to ~/.idapro/plugins"
	@echo ""
	@echo "Requirements:"
	@echo "  - IDA SDK (set IDASDK environment variable)"
	@echo "  - Docker (for Linux builds from non-Linux hosts)"
	@echo "  - XWIN_ROOT (for Windows clang cross-builds)"
	@echo "  - CMake 3.27+"
	@echo "  - Ninja build system"
