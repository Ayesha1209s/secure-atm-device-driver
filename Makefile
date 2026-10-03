# ==============================================================================
# Project: Secure ATM PIN Authenticator Device Driver
# File:    Makefile
# Targets: Kernel Module (atm_driver.ko) & User-Space Application (atm_app)
# ==============================================================================

# Kernel Module Object Definition
obj-m += atm_driver.o

# Paths and Flags
KDIR        ?= /lib/modules/$(shell uname -r)/build
PWD         := $(shell pwd)
CXX         := g++
CXXFLAGS    := -std=c++17 -Wall -Wextra -O2 -pthread
APP_SRC     := atm_app.cpp
APP_BIN     := atm_app
DEVICE_NAME := atm_auth
DEVICE_PATH := /dev/$(DEVICE_NAME)

# Default Target: Build both Kernel Module and User-Space Application
all: driver app
	@echo "======================================================================"
	@echo " Build Complete: 'atm_driver.ko' and '$(APP_BIN)' are ready."
	@echo " Run 'sudo make load' to insert the driver into the Linux kernel."
	@echo " Run './$(APP_BIN)' to launch the ATM terminal application."
	@echo "======================================================================"

# Build the Linux Loadable Kernel Module (LKM)
driver:
	@echo "===> [1/2] Compiling Linux Kernel Module (Kbuild)..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build the C++ User-Space Terminal Application
app: $(APP_SRC)
	@echo "===> [2/2] Compiling C++ User-Space Application..."
	$(CXX) $(CXXFLAGS) $(APP_SRC) -o $(APP_BIN)

# Clean all generated build artifacts
clean:
	@echo "===> Cleaning Kernel Module and Application build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(APP_BIN)
	rm -f *.o *.ko *.mod.* *.symvers *.order .*.cmd

# Load the Kernel Module and adjust permissions
load:
	@echo "===> Inserting Kernel Module '$(DEVICE_NAME)'..."
	@if lsmod | grep -q "$(DEVICE_NAME)"; then \
		echo "Module $(DEVICE_NAME) is already loaded."; \
	else \
		sudo insmod atm_driver.ko; \
		sleep 0.5; \
		if [ -e $(DEVICE_PATH) ]; then \
			sudo chmod 666 $(DEVICE_PATH); \
			echo "Device node $(DEVICE_PATH) permissions set to 666 (rw-rw-rw-)."; \
		else \
			echo "Notice: $(DEVICE_PATH) not automatically created by udev."; \
			echo "Run 'sudo make mknod' to create it manually."; \
		fi; \
		echo "Driver loaded successfully. Check logs with 'dmesg | tail -n 10'."; \
	fi

# Unload the Kernel Module
unload:
	@echo "===> Removing Kernel Module '$(DEVICE_NAME)'..."
	@if lsmod | grep -q "$(DEVICE_NAME)"; then \
		sudo rmmod atm_driver; \
		echo "Module $(DEVICE_NAME) unloaded successfully."; \
	else \
		echo "Module $(DEVICE_NAME) is not currently loaded."; \
	fi

# Manually create the character device node using mknod (fallback if udev is inactive)
mknod:
	@echo "===> Creating device node manually via mknod..."
	@MAJOR=$$(awk '$$2=="$(DEVICE_NAME)" {print $$1}' /proc/devices); \
	if [ -n "$$MAJOR" ]; then \
		if [ -e $(DEVICE_PATH) ]; then \
			echo "Device $(DEVICE_PATH) already exists. Recreating..."; \
			sudo rm -f $(DEVICE_PATH); \
		fi; \
		sudo mknod -m 666 $(DEVICE_PATH) c $$MAJOR 0; \
		echo "Device node $(DEVICE_PATH) created with Major $$MAJOR, Minor 0."; \
	else \
		echo "Error: Device '$(DEVICE_NAME)' not found in /proc/devices."; \
		echo "Ensure the module is loaded first using 'sudo make load'."; \
		exit 1; \
	fi

# Check system status, device node, and recent kernel log messages
status:
	@echo "===================== KERNEL MODULE STATUS ====================="
	@lsmod | grep "$(DEVICE_NAME)" || echo "Module '$(DEVICE_NAME)' NOT loaded."
	@echo ""
	@echo "===================== DEVICE NODE DETAILS ======================"
	@if [ -e $(DEVICE_PATH) ]; then \
		ls -la $(DEVICE_PATH); \
	else \
		echo "Device node $(DEVICE_PATH) does NOT exist."; \
	fi
	@echo ""
	@echo "===================== /proc/devices ENTRY ======================"
	@grep "$(DEVICE_NAME)" /proc/devices || echo "Not found in /proc/devices."
	@echo ""
	@echo "===================== RECENT KERNEL LOGS ======================="
	@sudo dmesg | grep -E "atm_auth|ATM" | tail -n 10 || true
	@echo "================================================================"

.PHONY: all driver app clean load unload mknod status
