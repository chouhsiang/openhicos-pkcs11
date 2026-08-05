# Build standalone PKCS#11 module (Rust)
#
#   make                  → build/openhicos-pkcs11-<os>-<arch>.so
#   make release          → optimized build
#   make test-load        → verify C_GetFunctionList loads

PREFIX  ?= /usr/local
OUT     ?= build
CARGO   ?= cargo
PROFILE ?= release

TARGET_OS   ?=
TARGET_ARCH ?=

# ---- detect host ----
ifeq ($(OS),Windows_NT)
  HOST_OS := windows
  ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
    HOST_ARCH := x86_64
  else ifeq ($(PROCESSOR_ARCHITECTURE),ARM64)
    HOST_ARCH := arm64
  else
    HOST_ARCH := x86_64
  endif
else
  UNAME_S := $(shell uname -s)
  UNAME_M := $(shell uname -m)
  ifeq ($(UNAME_S),Darwin)
    HOST_OS := macos
  else ifeq ($(UNAME_S),Linux)
    HOST_OS := linux
  else
    HOST_OS := $(shell echo $(UNAME_S) | tr '[:upper:]' '[:lower:]')
  endif
  HOST_ARCH := $(UNAME_M)
  ifeq ($(HOST_ARCH),aarch64)
    HOST_ARCH := arm64
  else ifeq ($(HOST_ARCH),amd64)
    HOST_ARCH := x86_64
  endif
endif

OS_NAME   := $(if $(TARGET_OS),$(TARGET_OS),$(HOST_OS))
ARCH_NAME := $(if $(TARGET_ARCH),$(TARGET_ARCH),$(HOST_ARCH))
LIBNAME   := openhicos-pkcs11-$(OS_NAME)-$(ARCH_NAME).so
TARGET    := $(OUT)/$(LIBNAME)

ifeq ($(PROFILE),release)
  CARGO_PROFILE := --release
  CARGO_OUT     := target/release
else
  CARGO_PROFILE :=
  CARGO_OUT     := target/debug
endif

ifeq ($(OS_NAME),macos)
  CARGO_LIB := $(CARGO_OUT)/libopenhicos_pkcs11.dylib
else ifeq ($(OS_NAME),windows)
  CARGO_LIB := $(CARGO_OUT)/openhicos_pkcs11.dll
else
  CARGO_LIB := $(CARGO_OUT)/libopenhicos_pkcs11.so
endif

.PHONY: all release clean install test-load

all: $(TARGET)

release:
	$(MAKE) PROFILE=release

$(OUT):
	mkdir -p $@

$(TARGET): $(CARGO_LIB) | $(OUT)
	cp $< $@
	@echo "built $@"

$(CARGO_LIB): $(shell find src -type f) Cargo.toml
	$(CARGO) build $(CARGO_PROFILE)

clean:
	$(CARGO) clean
	rm -rf $(OUT)

install: $(TARGET)
	install -d $(PREFIX)/lib
	install -m 755 $(TARGET) $(PREFIX)/lib/$(LIBNAME)

test-load: $(TARGET)
	@python3 -c "import ctypes; \
lib=ctypes.CDLL('$(TARGET)'); \
fl=ctypes.c_void_p(); \
rv=lib.C_GetFunctionList(ctypes.byref(fl)); \
print('C_GetFunctionList ->', rv, 'list=', hex(fl.value or 0)); \
print('module:', '$(TARGET)'); \
assert rv==0 and fl.value"
