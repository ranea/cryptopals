CXX := clang++

CXXFLAGS := -std=c++1z
LDFLAGS := -Wall -Wextra

SOURCES = utilities.cpp \
    challenges.cpp

OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = challenges

all: $(OBJECTS) $(EXECUTABLE)

%: %.o
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

clean:
	-rm -f $(EXECUTABLE) $(OBJECTS) *~
