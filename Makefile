.PHONY: all clean

all:
	node-gyp configure build

clean:
	rm -rf build/
