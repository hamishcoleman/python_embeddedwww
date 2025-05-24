
describe := $(shell git describe --dirty)
tarfile := $(NAME)-$(describe).tar.gz

TESTFILES+=server.py
COV_PERCENT=76

all: lint test

build-dep:
	sudo apt-get install \
            flake8 \
            python3-pytest \
            python3-pytest-cov \
	    shellcheck \

install:
	mkdir -p $(INSTALLDIR)
	install -p server.py $(INSTALLDIR)/server

tar:    $(tarfile)

$(tarfile):
	$(MAKE) install
	tar -v -c -z -C $(DESTDIR) -f $(tarfile) .

test:
	pytest-3 \
            $(TESTFILES)

cover:
	pytest-3 \
            -vv \
            --cov=. \
            --cov-report=html \
            --cov-report=term \
            --cov-fail-under=$(COV_PERCENT) \
            $(TESTFILES)

lint:
	flake8
	shellcheck --format=gcc site_query.sh

clean:
	rm -rf htmlcov .coverage __pycache__/ .pytest_cache
