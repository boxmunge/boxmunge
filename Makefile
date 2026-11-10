VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
# DIST: where the bundle is built (tests build into a temporary directory,
# so parallel runs never share a staging tree).
DIST    ?= dist
STAGE   := $(DIST)/.stage
BUNDLE  := $(DIST)/boxmunge-$(VERSION).tar.gz

# ---------------------------------------------------------------------------
# Bundle manifest — single source of truth for what ships in a release.
#
# BUNDLE_DIRS:         dirs copied as-is (source path == staged path).
# BUNDLE_RENAMED_DIRS: dirs copied with a different staged name. Format src=dest.
#                      Used because install.sh expects on-server/ at the bundle
#                      root, not docs/on-server/.
# BUNDLE_TOP_FILES:    files copied to the bundle root. The requirements files
#                      are what on-box installs use (pip --require-hashes);
#                      SHA256SUMS signs the bundle, so they arrive signed.
#
# To add a top-level dir to releases: append it to BUNDLE_DIRS. The verify
# step below fails the build if a declared entry is missing from staging,
# so the manifest cannot drift from the cp commands.
# ---------------------------------------------------------------------------
BUNDLE_DIRS         := bootstrap src systemd config scripts caddy canary system
BUNDLE_RENAMED_DIRS := docs/on-server=on-server
BUNDLE_TOP_FILES    := install.sh pyproject.toml requirements-build.txt requirements-tui.txt requirements-mcp.txt

# Names as they appear in the staged bundle (used by the verify step).
BUNDLE_STAGED_DIRS  := $(BUNDLE_DIRS) $(foreach pair,$(BUNDLE_RENAMED_DIRS),$(word 2,$(subst =, ,$(pair))))
# Source paths driving Make's dependency tracking.
BUNDLE_SRC_DIRS     := $(BUNDLE_DIRS) $(foreach pair,$(BUNDLE_RENAMED_DIRS),$(word 1,$(subst =, ,$(pair))))
BUNDLE_DEPS         := $(shell find $(BUNDLE_SRC_DIRS) -type f 2>/dev/null) $(BUNDLE_TOP_FILES)

.PHONY: bundle installer test test-serial test-cli test-integration test-all lint clean

bundle: $(BUNDLE)

installer: $(BUNDLE)
	@./scripts/build-installer.sh

$(BUNDLE): $(BUNDLE_DEPS)
	@mkdir -p $(STAGE)/boxmunge
	cp $(BUNDLE_TOP_FILES) $(STAGE)/boxmunge/
	cp -r $(BUNDLE_DIRS) $(STAGE)/boxmunge/
	@for pair in $(BUNDLE_RENAMED_DIRS); do \
	    src="$${pair%%=*}"; dest="$${pair##*=}"; \
	    cp -r "$$src" "$(STAGE)/boxmunge/$$dest"; \
	done
	@find $(STAGE) -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@find $(STAGE) -name '*.pyc' -delete 2>/dev/null || true
	@find $(STAGE) -name '*.egg-info' -type d -exec rm -rf {} + 2>/dev/null || true
	@# Ship the upgrade shim as one self-contained file: every installer of it,
	@# older releases' shims included, copies only scripts/boxmunge-upgrade.
	python3 scripts/build-shim.py scripts/boxmunge-upgrade $(STAGE)/boxmunge/scripts/boxmunge-upgrade
	rm -rf $(STAGE)/boxmunge/scripts/boxmunge-upgrade.d
	@for d in $(BUNDLE_STAGED_DIRS); do \
	    if [ ! -d "$(STAGE)/boxmunge/$$d" ]; then \
	        echo "ERROR: bundle staging missing declared dir: $$d" >&2; exit 1; \
	    fi; \
	done
	@for f in $(BUNDLE_TOP_FILES); do \
	    if [ ! -f "$(STAGE)/boxmunge/$$f" ]; then \
	        echo "ERROR: bundle staging missing declared file: $$f" >&2; exit 1; \
	    fi; \
	done
	python3 scripts/build-bundle.py $@ $(STAGE) boxmunge
	rm -rf $(STAGE)
	@echo "Built $@ ($$(du -h $@ | cut -f1))"
	@echo "Bundle contains: $(BUNDLE_STAGED_DIRS) $(BUNDLE_TOP_FILES)"

# Parallel (pytest-xdist, one worker per CPU; PYTEST_XDIST_AUTO_NUM_WORKERS
# caps it on a shared machine). `make test-serial` for a debugger or pdb.
test:
	python3 -m pytest tests/ -q -n auto --ignore=tests/integration --ignore=tests/vm -m 'not integration'

test-serial:
	python3 -m pytest tests/ -v --ignore=tests/integration --ignore=tests/vm -m 'not integration'

test-cli:
	cd cli && python3 -m pytest tests -v

test-integration:
	python3 -m pytest tests/ -v --ignore=tests/vm -m integration

lint:
	ruff check src tests cli/src cli/tests

test-all:
	python3 -m pytest tests/ -v

test-vm:
	python3 tests/vm/vm-test.py

clean:
	rm -rf dist/

# Regenerate hash-pinned requirements files from pyproject.toml.
# Run when pyproject.toml's [project.dependencies] or optional-dependencies
# changes. CI does not run this — it consumes the checked-in files.
#
# The runtime locks (lock-runtime) are pyproject extras, which Dependabot
# never regenerates: `make relock` upgrades them, before each release
# (docs/DEVELOPMENT.md). Both take no release younger than Dependabot's
# 7-day cooldown (.github/dependabot.yml; pip >= 26, from requirements-dev.txt).
# Majors not yet taken are held in relock-holds.txt.
RUNTIME_COMPILE := pip-compile --generate-hashes --pip-args='--uploaded-prior-to P7D' -c relock-holds.txt

.PHONY: lock lock-runtime relock
lock: lock-runtime
	pip-compile --generate-hashes --allow-unsafe -o requirements-dev.txt requirements-dev.in
	pip-compile --generate-hashes --allow-unsafe -o requirements-build.txt requirements-build.in
	pip-compile --generate-hashes --strip-extras --allow-unsafe -o cli/requirements-publish.txt cli/requirements-publish.in
	pip-compile --generate-hashes --strip-extras --allow-unsafe -o services/version-check/requirements.txt services/version-check/requirements.in

lock-runtime:
	$(RUNTIME_COMPILE) $(UPGRADE) -o requirements.txt pyproject.toml
	$(RUNTIME_COMPILE) $(UPGRADE) --extra=tui -o requirements-tui.txt pyproject.toml
	$(RUNTIME_COMPILE) $(UPGRADE) --extra=mcp -o requirements-mcp.txt pyproject.toml
	$(RUNTIME_COMPILE) $(UPGRADE) -o cli/requirements.txt cli/pyproject.toml

relock:
	$(MAKE) lock-runtime UPGRADE=--upgrade
