all:
	@# Check python scripts
	flake8 --max-line-length=120 ./*.py
	mypy --disallow-any-generics --disallow-subclassing-any ./*.py

	@# Extract the firmware
	./extract_firmware.py
	./extract_firmware.py > firmware_parts.out.txt

.PHONY: all
