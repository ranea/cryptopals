CXX := clang++

CXXFLAGS := -std=c++1z
LDFLAGS := -Wall -Wextra

SOURCES = challenge1.cpp \
    tests.cpp

OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = tests

all: $(OBJECTS) $(EXECUTABLE)

%: %.o
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

clean:
	-rm -f $(EXECUTABLE) $(OBJECTS) *~
