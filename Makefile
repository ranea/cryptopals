CXX := clang++

CXXFLAGS := -std=c++1z
LDFLAGS := -Wall -Wextra

SOURCES = utilities.cpp \
    main.cpp

OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = main

all: $(OBJECTS) $(EXECUTABLE)
	./$(EXECUTABLE)

%: %.o
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

clean:
	-rm -f $(EXECUTABLE) $(OBJECTS) *~
