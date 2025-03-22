#include "firewall_manager.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <cstdio>
#include <array>
#include <regex>

// Constructor definition
FirewallManager::FirewallManager() : initialized(false) {
}

// Destructor definition
FirewallManager::~FirewallManager() {
    // Nessuna pulizia necessaria
}

// Inizializza il firewall manager
bool FirewallManager::initialize() {
    std::lock_guard<std::mutex> lock(firewall_mutex);
    if (initialized) {
        return true;
    }

    // Verifica i permessi (deve essere eseguito come root)
    if (geteuid() != 0) {
        std::cerr << "Il FirewallManager deve essere eseguito con permessi di root.\n";
        return false;
    }

    // Verifica che iptables sia disponibile
    std::string testCommand = "iptables --version > /dev/null 2>&1";
    int result = system(testCommand.c_str());
    if (result != 0) {
        std::cerr << "Impossibile trovare iptables. Assicurarsi che sia installato.\n";
        return false;
    }

    initialized = true;
    return true;
}

// Converte un indirizzo IP in stringa al formato uint32_t
bool FirewallManager::convertIPToUint(const std::string& ip, uint32_t& ip_uint) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }
    ip_uint = ntohl(addr.s_addr);
    return true;
}

// Esegue un comando di iptables in modo sicuro
bool FirewallManager::executeIptablesCommand(const std::string& command) {
    // Verifica che il comando contenga solo caratteri consentiti
    std::regex safeCommandRegex("^[a-zA-Z0-9 \\-\\._/]*$");
    if (!std::regex_match(command, safeCommandRegex)) {
        std::cerr << "Comando non sicuro rilevato: " << command << std::endl;
        return false;
    }
    
    // Esegue il comando e cattura l'output
    std::array<char, 128> buffer;
    std::string result;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Errore nell'esecuzione del comando: " << command << std::endl;
        return false;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    int status = pclose(pipe);
    return (status == 0);
}

// Aggiunge una regola per bloccare un IP
bool FirewallManager::blockIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(firewall_mutex);
    
    if (!initialized) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Verifica se l'IP è già bloccato
    if (isIPBlocked(ip)) {
        return true;
    }
    
    // Verifica che l'IP sia valido
    uint32_t ip_uint;
    if (!convertIPToUint(ip, ip_uint)) {
        std::cerr << "Indirizzo IP non valido: " << ip << std::endl;
        return false;
    }
    
    // Usa un formato di comando sicuro e prevedibile
    std::string command = "iptables -A INPUT -s " + ip + " -j DROP";
    return executeIptablesCommand(command);
}

// Rimuove una regola per sbloccare un IP
bool FirewallManager::unblockIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(firewall_mutex);
    
    if (!initialized) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Verifica che l'IP sia valido
    uint32_t ip_uint;
    if (!convertIPToUint(ip, ip_uint)) {
        std::cerr << "Indirizzo IP non valido: " << ip << std::endl;
        return false;
    }
    
    // Usa un formato di comando sicuro e prevedibile
    std::string command = "iptables -D INPUT -s " + ip + " -j DROP";
    return executeIptablesCommand(command);
}

// Verifica se un IP è bloccato
bool FirewallManager::isIPBlocked(const std::string& ip) {
    std::lock_guard<std::mutex> lock(firewall_mutex);
    
    if (!initialized) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Verifica che l'IP sia valido
    uint32_t ip_uint;
    if (!convertIPToUint(ip, ip_uint)) {
        std::cerr << "Indirizzo IP non valido: " << ip << std::endl;
        return false;
    }
    
    // Comando sicuro per verificare se l'IP è bloccato
    std::string command = "iptables -L INPUT -n | grep " + ip + " | grep DROP";
    
    std::array<char, 128> buffer;
    std::string result;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return false;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    pclose(pipe);
    
    // Se il risultato contiene l'IP, è bloccato
    return result.find(ip) != std::string::npos;
}

// Ottiene la lista degli IP bloccati
std::vector<std::string> FirewallManager::getBlockedIPs() {
    std::lock_guard<std::mutex> lock(firewall_mutex);
    std::vector<std::string> blockedIPs;
    
    if (!initialized) {
        if (!initialize()) {
            return blockedIPs;
        }
    }
    
    // Comando sicuro per ottenere la lista degli IP bloccati
    std::string command = "iptables -L INPUT -n | grep 'DROP' | awk '{print $4}'";
    
    std::array<char, 128> buffer;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return blockedIPs;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string line(buffer.data());
        // Rimuovi spazi bianchi e caratteri di nuova linea
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        
        if (!line.empty()) {
            // Verifica che sia un IP valido
            struct in_addr addr;
            if (inet_pton(AF_INET, line.c_str(), &addr) == 1) {
                blockedIPs.push_back(line);
            }
        }
    }
    
    pclose(pipe);
    return blockedIPs;
} 