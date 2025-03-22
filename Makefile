CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS = 

TARGET = credban
SRCS = credban.cpp firewall_manager.cpp logger.cpp
OBJS = $(SRCS:.cpp=.o)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: $(TARGET)
	@echo "Installazione di $(TARGET)..."
	sudo cp $(TARGET) /usr/local/sbin/
	sudo cp credban.config /etc/credban.config
	@echo "Creazione del servizio systemd..."
	sudo cp credban.service /etc/systemd/system/
	@echo "Completato. Utilizzare 'sudo systemctl enable credban' per abilitare all'avvio."

uninstall:
	@echo "Disinstallazione di $(TARGET)..."
	sudo systemctl stop credban || true
	sudo systemctl disable credban || true
	sudo rm -f /usr/local/sbin/$(TARGET)
	sudo rm -f /etc/credban.config
	sudo rm -f /etc/systemd/system/credban.service
	@echo "Disinstallazione completata."

clean:
	rm -f $(OBJS) $(TARGET) 