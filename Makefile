TARGET = x86_64-unknown-uefi
BUILD_DIR = target/$(TARGET)/release
ESP_DIR = esp
OUT_EFI = $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI


.PHONY: all

all: build-efi

build-efi:
	cargo build --target $(TARGET) --release
	mkdir -p $(dir $(OUT_EFI))
	cp $(BUILD_DIR)/efi-key-enroller.efi $(OUT_EFI)

clean:
	cargo clean

run-qemu:
	qemu-system-x86_64 -enable-kvm -m 4G --machine q35 \
	-drive if=pflash,format=raw,readonly=on,file=${PWD}/OVMF_CODE.fd \
  	-drive if=pflash,format=raw,file=${PWD}/OVMF_VARS.fd \
	-drive file=fat:rw:./$(ESP_DIR)/,format=raw,media=disk -rtc base=utc