.PHONY: all clean opt

all:
	cd src/ && $(MAKE)
clean:
	cd src/ && $(MAKE) clean
                         
install:
	cd src/ && $(MAKE) install

conf:
	cd src/ && $(MAKE) conf
