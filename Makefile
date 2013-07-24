VERSION=$(shell cat package.json | grep -i version | grep -oE "\"[^\"]+\",*$$" | grep -oE "[0-9a-z.+\-]+")

.PHONY: all clean

all:
	@mkdir -p build
	cat version.gypi | sed -e s/{{VERSION}}/$(VERSION)/ > build/version.gypi
	node-gyp configure build

clean:
	rm -rf build
