NAME   := vault
TARGET := $(shell rustc -vV | awk '/^host:/ {print $$2}')
PREFIX ?= $(HOME)/usr

# Code-signing identity. Create once with:
#   /usr/bin/openssl req -x509 -newkey rsa:2048 \
#     -keyout /tmp/vault-key.pem -out /tmp/vault-cert.pem \
#     -days 3650 -nodes \
#     -subj "/CN=Vault Signing" \
#     -addext "basicConstraints=critical,CA:false" \
#     -addext "keyUsage=critical,digitalSignature" \
#     -addext "extendedKeyUsage=codeSigning"
#   /usr/bin/openssl pkcs12 -export \
#     -out /tmp/vault-cert.p12 \
#     -inkey /tmp/vault-key.pem -in /tmp/vault-cert.pem \
#     -passout pass:vault
#   security import /tmp/vault-cert.p12 \
#     -k ~/Library/Keychains/login.keychain-db \
#     -P vault -T /usr/bin/codesign -A
#   rm /tmp/vault-key.pem /tmp/vault-cert.pem /tmp/vault-cert.p12
SIGN_ID ?= Vault Signing

lint:
	cargo fmt --all
	cargo clippy --fix --allow-dirty --all-targets --all-features -- --deny warnings

install: dist
	codesign --sign "$(SIGN_ID)" --force --timestamp=none target/$(TARGET)/dist/$(NAME)
	cp target/$(TARGET)/dist/$(NAME) $(PREFIX)/bin/$(NAME)

dist:
	cargo clean -p $(NAME) --release --target $(TARGET)
	RUSTFLAGS="-Zlocation-detail=none -Zshare-generics=y -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=n -Clink-arg=-Wl,-x" \
	cargo build --profile dist \
	  -Z build-std=std \
	  -Z build-std-features= \
	  --target $(TARGET)

.PHONY: lint install dist
