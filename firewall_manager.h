#ifndef FIREWALL_MANAGER_H
#define FIREWALL_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <netinet/in.h>

class FirewallManager {
private:
    std::mutex firewall_mutex;
    bool initialized;

    // Converte un indirizzo IP in stringa al formato uint32_t
    bool convertIPToUint(const std::string& ip, uint32_t& ip_uint);

    // Esegue un comando di iptables in modo sicuro
    bool executeIptablesCommand(const std::string& command);

public:
    FirewallManager();
    ~FirewallManager();

    // Inizializza il firewall manager
    bool initialize();

    // Aggiunge una regola per bloccare un IP
    bool blockIP(const std::string& ip);

    // Rimuove una regola per sbloccare un IP
    bool unblockIP(const std::string& ip);

    // Verifica se un IP è bloccato
    bool isIPBlocked(const std::string& ip);

    // Ottiene la lista degli IP bloccati
    std::vector<std::string> getBlockedIPs();
};

#endif // FIREWALL_MANAGER_H 