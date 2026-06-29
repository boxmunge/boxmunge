VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
BUNDLE  := dist/boxmunge-$(VERSION).tar.gz

# ---------------------------------------------------------------------------
# Bundle manifest — single source of truth for what ships in a release.
#
# BUNDLE_DIRS:         dirs copied as-is (source path == staged path).
# BUNDLE_RENAMED_DIRS: dirs copied with a different staged name. Format src=dest.
#                      Used because install.sh expects on-server/ at the bundle
#                      root, not docs/on-server/.
# BUNDLE_TOP_FILES:    files copied to the bundle root.
#
# To add a top-level dir to releases: append it to BUNDLE_DIRS. The verify
# step below fails the build if a declared entry is missing from staging,
# so the manifest cannot drift from the cp commands.
# ---------------------------------------------------------------------------
BUNDLE_DIRS         := bootstrap src systemd config scripts caddy canary system
BUNDLE_RENAMED_DIRS := docs/on-server=on-server
BUNDLE_TOP_FILES    := install.sh pyproject.toml

# Names as they appear in the staged bundle (used by the verify step).
BUNDLE_STAGED_DIRS  := $(BUNDLE_DIRS) $(foreach pair,$(BUNDLE_RENAMED_DIRS),$(word 2,$(subst =, ,$(pair))))
# Source paths driving Make's dependency tracking.
BUNDLE_SRC_DIRS     := $(BUNDLE_DIRS) $(foreach pair,$(BUNDLE_RENAMED_DIRS),$(word 1,$(subst =, ,$(pair))))
BUNDLE_DEPS         := $(shell find $(BUNDLE_SRC_DIRS) -type f 2>/dev/null) $(BUNDLE_TOP_FILES)

.PHONY: bundle installer test test-integration test-all clean

bundle: $(BUNDLE)

installer: $(BUNDLE)
	@./scripts/build-installer.sh

$(BUNDLE): $(BUNDLE_DEPS)
	@mkdir -p dist/.stage/boxmunge
	cp $(BUNDLE_TOP_FILES) dist/.stage/boxmunge/
	cp -r $(BUNDLE_DIRS) dist/.stage/boxmunge/
	@for pair in $(BUNDLE_RENAMED_DIRS); do \
	    src="$${pair%%=*}"; dest="$${pair##*=}"; \
	    cp -r "$$src" "dist/.stage/boxmunge/$$dest"; \
	done
	@find dist/.stage -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@find dist/.stage -name '*.pyc' -delete 2>/dev/null || true
	@find dist/.stage -name '*.egg-info' -type d -exec rm -rf {} + 2>/dev/null || true
	@for d in $(BUNDLE_STAGED_DIRS); do \
	    if [ ! -d "dist/.stage/boxmunge/$$d" ]; then \
	        echo "ERROR: bundle staging missing declared dir: $$d" >&2; exit 1; \
	    fi; \
	done
	@for f in $(BUNDLE_TOP_FILES); do \
	    if [ ! -f "dist/.stage/boxmunge/$$f" ]; then \
	        echo "ERROR: bundle staging missing declared file: $$f" >&2; exit 1; \
	    fi; \
	done
	tar czf $@ -C dist/.stage boxmunge
	rm -rf dist/.stage
	@echo "Built $@ ($$(du -h $@ | cut -f1))"
	@echo "Bundle contains: $(BUNDLE_STAGED_DIRS) $(BUNDLE_TOP_FILES)"

test:
	python3 -m pytest tests/ -v --ignore=tests/integration

test-integration:
	python3 -m pytest tests/integration/ -v

test-all:
	python3 -m pytest tests/ -v

test-vm:
	python3 tests/vm/vm-test.py

clean:
	rm -rf dist/
