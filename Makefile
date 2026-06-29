NAME   := vault
TARGET := $(shell rustc -vV | awk '/^host:/ {print $$2}')

lint:
	cargo fmt --all
	cargo clippy --fix --allow-dirty --all-targets --all-features -- --deny warnings

dist:
	cargo clean -p $(NAME) --release --target $(TARGET)
	RUSTFLAGS="-Zlocation-detail=none -Zshare-generics=y -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=n -Clink-arg=-Wl,-x" \
	cargo build --profile dist \
	  -Z build-std=std \
	  -Z build-std-features= \
	  --target $(TARGET)

.PHONY: lint dist
