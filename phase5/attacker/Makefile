CXX := g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2
LDLIBS := -lpcap
TARGET := interceptor
SRC := interceptor.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)
