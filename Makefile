FEATURES ?= "all_clients"

ifdef RELEASE
TARGET_PATH=release
CARGO_ARGS += --release
else
TARGET_PATH=debug
endif

ifdef SVSM
CARGO_ARGS += --target x86_64-unknown-none --no-default-features
FEATURES := alloc,${FEATURES}
endif

ifdef NIGHTLY
CARGO=cargo +nightly
else
CARGO=cargo
endif

ifdef OFFLINE
CARGO_ARGS += --locked --offline
endif

ifeq ($(V), 1)
CARGO_ARGS += -v
else ifeq ($(V), 2)
CARGO_ARGS += -vv
endif

CARGO_ARGS += --features ${FEATURES}

all: lib examples
check: fmt clippy test

lib:
	${CARGO} build ${CARGO_ARGS}

examples:
	@if [ -n "$(SVSM)" ]; then \
		echo "Examples not supported in SVSM"; \
	else \
		${CARGO} build ${CARGO_ARGS} --examples; \
	fi

clippy:
	${CARGO} clippy ${CARGO_ARGS}

fmt:
	${CARGO} fmt --all -- --check 2>/dev/null

test:
	@if [ -n "$(SVSM)" ]; then \
		echo "Tests not supported in SVSM"; \
	else \
		${CARGO} test ${CARGO_ARGS}; \
	fi

clean:
	cargo clean

.PHONY: all check lib examples fmt clippy test clean
