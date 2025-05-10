TARGET = x86_64-unknown-uefi
BUILD_DIR = target/$(TARGET)/release
ESP_DIR = esp
OUT_EFI = $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
KEYS_DIR := keys
UUID := $(shell uuidgen)


.PHONY: all

all: clean generate-keys build-efi

build-efi:
	@cargo build --target $(TARGET) --release
	@mkdir -p $(dir $(OUT_EFI))
	@cp $(BUILD_DIR)/efi-key-enroller.efi $(OUT_EFI)
clean:
	@cargo clean
	@rm -Rf $(ESP_DIR)
	@rm -Rf $(KEYS_DIR)

run-qemu:
	cp OVMF_VARS.fd.clean OVMF_VARS.fd
	qemu-system-x86_64 -enable-kvm -m 4G --machine q35 \
	-drive if=pflash,format=raw,readonly=on,file=${PWD}/OVMF_CODE.fd \
  	-drive if=pflash,format=raw,file=${PWD}/OVMF_VARS.fd \
	-drive file=fat:rw:./$(ESP_DIR)/,format=raw,media=disk -rtc base=utc \
	-netdev bridge,id=net0,br=virbr0 \
    -device e1000,netdev=net0

generate-keys:
	@rm -rf $(KEYS_DIR)
	@echo "[*] Generating EFI Secure Boot keys in $(KEYS_DIR)/"
	@mkdir -p $(KEYS_DIR)

	@echo "[+] Generating PK"
	@openssl req -new -x509 -newkey rsa:2048 -nodes \
		-keyout $(KEYS_DIR)/PK.key -out $(KEYS_DIR)/PK.crt \
		-subj "/CN=Test PK/" -days 3650

	@echo "[+] Generating KEK"
	@openssl req -new -x509 -newkey rsa:2048 -nodes \
		-keyout $(KEYS_DIR)/KEK.key -out $(KEYS_DIR)/KEK.crt \
		-subj "/CN=Test KEK/" -days 3650

	@echo "[+] Generating DB"
	@openssl req -new -x509 -newkey rsa:2048 -nodes \
		-keyout $(KEYS_DIR)/DB.key -out $(KEYS_DIR)/DB.crt \
		-subj "/CN=Test db/" -days 3650

	@echo "[+] Creating ESLs"
	@cert-to-efi-sig-list -g $(UUID) $(KEYS_DIR)/PK.crt  $(KEYS_DIR)/PK.esl
	@cert-to-efi-sig-list -g $(UUID) $(KEYS_DIR)/KEK.crt $(KEYS_DIR)/KEK.esl
	@cert-to-efi-sig-list -g $(UUID) $(KEYS_DIR)/DB.crt  $(KEYS_DIR)/DB.esl

	@echo "[+] Signing ESLs to .auth"
	@sign-efi-sig-list -k $(KEYS_DIR)/PK.key -c $(KEYS_DIR)/PK.crt  PK  $(KEYS_DIR)/PK.esl  $(KEYS_DIR)/PK.auth
	@sign-efi-sig-list -k $(KEYS_DIR)/PK.key -c $(KEYS_DIR)/PK.crt  KEK $(KEYS_DIR)/KEK.esl $(KEYS_DIR)/KEK.auth
	@sign-efi-sig-list -k $(KEYS_DIR)/KEK.key -c $(KEYS_DIR)/KEK.crt db  $(KEYS_DIR)/DB.esl  $(KEYS_DIR)/DB.auth

	@echo "[✔] Keys generated:"
	@ls -lh $(KEYS_DIR)/*.auth