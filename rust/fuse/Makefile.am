AUTOMAKE_OPTIONS = foreign

EXTRA_PROGRAMS  = target/$(RUSTC_TARGET)/$(RUSTC_MODE)/erofsfuse
EXTRA_DIST = src/main.rs Cargo.toml Cargo.lock

all-local:
	$(CARGO) build -vvv --$(RUSTC_MODE) --target $(RUSTC_TARGET)

install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) target/$(RUSTC_TARGET)/$(RUSTC_MODE)/erofsfuse-rs $(DESTDIR)$(bindir)/erofsfuse

clean-local:
	$(CARGO) clean
