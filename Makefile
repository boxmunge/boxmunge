VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
BUNDLE  := dist/boxmunge-$(VERSION).tar.gz

SRC_FILES     := $(shell find src -type f -name '*.py')
SYSTEMD_FILES := $(shell find systemd -type f)
CONFIG_FILES  := $(shell find config -type f)
DOC_FILES     := $(shell find docs/on-server -type f 2>/dev/null)

.PHONY: bundle installer test test-integration test-all clean

bundle: $(BUNDLE)

installer: $(BUNDLE)
	@./scripts/build-installer.sh

$(BUNDLE): install.sh bootstrap/init-host.sh pyproject.toml $(SRC_FILES) $(SYSTEMD_FILES) $(CONFIG_FILES) $(DOC_FILES)
	@mkdir -p dist/.stage/boxmunge
	cp install.sh pyproject.toml dist/.stage/boxmunge/
	cp -r bootstrap src systemd config docs/on-server dist/.stage/boxmunge/
	find dist/.stage -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find dist/.stage -name '*.pyc' -delete 2>/dev/null || true
	find dist/.stage -name '*.egg-info' -type d -exec rm -rf {} + 2>/dev/null || true
	tar czf $@ -C dist/.stage boxmunge
	rm -rf dist/.stage
	@echo "Built $@ ($$(du -h $@ | cut -f1))"

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
