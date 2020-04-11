all:
	@# Check structures.h
	gcc -Wall -Wextra -m32 -ffreestanding -c -o /dev/null -DNOT_IN_IDA=1 structures.h
	gcc -Wall -Wextra -m64 -ffreestanding -c -o /dev/null -DNOT_IN_IDA=1 structures.h

	@# Check python scripts
	flake8 --max-line-length=120 ./*.py
	mypy --disallow-any-generics --disallow-subclassing-any ./*.py

	@# Extract the firmware
	./extract_firmware.py
	./extract_firmware.py > firmware_parts.out.txt

.PHONY: all
