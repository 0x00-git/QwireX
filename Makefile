obj-m += qwirex.o

SOURCE_DIR = src
OUTPUT_DIR = binaries

all:
	mkdir -p $(OUTPUT_DIR)
	cp $(SOURCE_DIR)/*.c $(SOURCE_DIR)/*.h $(OUTPUT_DIR)/ 2>/dev/null || true
	cp Makefile $(OUTPUT_DIR)/Makefile
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/$(OUTPUT_DIR) modules
	@echo "! Модуль в $(PWD)/$(OUTPUT_DIR)/qwirex.ko"

clean:
	rm -rf $(OUTPUT_DIR)/*
	@echo "! $(PWD)/$(OUTPUT_DIR) очищен"