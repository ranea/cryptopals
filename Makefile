CXX=/usr/bin/clang++
CXXFLAGS=-std=c++1z
LDFLAGS=-Wall -Wextra

all: challenge1

challenge1:
	$(CXX) $(CXXFLAGS) challenge1.cpp -o challenge1 $(LDFLAGS)

clean:
	rm -f $(OUT)
