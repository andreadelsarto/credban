#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <thread>
#include <chrono>
#include <mutex>
#include <filesystem>
#include <fcntl.h>    // Per open()
#include <unistd.h>   // Per dup2()
#include <signal.h>   // Per gestire i segnali
#include <set>        // Per la lista degli IP fidati
#include <cstring>    // Per strerror()
#include <cctype>     // Per std::isdigit
#include <iomanip>    // Per std::put_time
#include <vector>     // Per gestire array di stringhe
#include "firewall_manager.h" // Per la gestione del firewall
#include "logger.h"    // Per il logging avanzato

// Classe per gestire la configurazione
class ConfigManager {
private:
    std::map<std::string, std::map<std::string, std::string>> config;
    std::string configFilePath;

    // Rimuove gli spazi iniziali e finali da una stringa
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t");
        return str.substr(first, (last - first + 1));
    }

    // Rimuove i commenti dalla riga
    std::string removeComments(const std::string& str) {
        size_t pos = str.find(';');
        if (pos != std::string::npos) {
            return str.substr(0, pos);
        }
        return str;
    }

public:
    ConfigManager(const std::string& filePath) : configFilePath(filePath) {}

    bool loadConfig() {
        std::ifstream file(configFilePath);
        if (!file.is_open()) {
            std::cerr << "Impossibile aprire il file di configurazione: " << configFilePath << std::endl;
            return false;
        }

        std::string line;
        std::string currentSection;

        while (std::getline(file, line)) {
            line = trim(removeComments(line));
            if (line.empty()) continue;

            if (line[0] == '[' && line[line.length() - 1] == ']') {
                currentSection = line.substr(1, line.length() - 2);
            } else if (currentSection.length() > 0) {
                size_t equalPos = line.find('=');
                if (equalPos != std::string::npos) {
                    std::string key = trim(line.substr(0, equalPos));
                    std::string value = trim(line.substr(equalPos + 1));
                    config[currentSection][key] = value;
                }
            }
        }

        file.close();
        return true;
    }

    std::string getString(const std::string& section, const std::string& key, const std::string& defaultValue = "") {
        if (config.find(section) != config.end() && config[section].find(key) != config[section].end()) {
            return config[section][key];
        }
        return defaultValue;
    }

    int getInt(const std::string& section, const std::string& key, int defaultValue = 0) {
        std::string value = getString(section, key, "");
        if (value.empty()) return defaultValue;
        try {
            return std::stoi(value);
        } catch (...) {
            return defaultValue;
        }
    }

    std::set<std::string> getIPList(const std::string& section, const std::string& key) {
        std::set<std::string> result;
        std::string value = getString(section, key, "");
        if (value.empty()) return result;
        
        std::istringstream ss(value);
        std::string ip;
        while (std::getline(ss, ip, ',')) {
            ip = trim(ip);
            if (!ip.empty()) {
                result.insert(ip);
            }
        }
        return result;
    }

    void saveConfig() {
        std::ofstream file(configFilePath);
        if (!file.is_open()) {
            std::cerr << "Impossibile salvare il file di configurazione: " << configFilePath << std::endl;
            return;
        }

        for (const auto& section : config) {
            file << "[" << section.first << "]" << std::endl;
            for (const auto& keyValue : section.second) {
                file << keyValue.first << " = " << keyValue.second << std::endl;
            }
            file << std::endl;
        }
        file.close();
    }
};

// Global variables for configuration
int MAX_CREDITS = 10;
int INITIAL_CREDITS = 3;
int BAN_DURATION = 3600; // Durata del ban in secondi (1 ora)
std::string CREDITS_FILE = "credits.dat";
std::string LOG_FILE_PATH = "/var/log/credban.log";
std::string AUTH_LOG_FILE = "/var/log/auth.log";
std::string PID_FILE = "/var/run/credban.pid";
int CLEANUP_INTERVAL = 3600;
int LOG_CHECK_INTERVAL = 5;

// Variabile globale per la configurazione
ConfigManager* g_configManager = nullptr;

// Global variable for firewall manager
FirewallManager* g_firewallManager = nullptr;

// Variabile globale per il logger
Logger* g_logger = nullptr;

// Struttura per tenere traccia dei crediti e del ban
struct IPInfo {
    int credits;
    time_t ban_end_time;
    int ban_count;  // Numero di volte che l'IP è stato bannato
};

// Mappa per tenere traccia degli IP
std::map<std::string, IPInfo> ip_map;

// Mutex per proteggere l'accesso a ip_map
std::mutex ip_map_mutex;

// Variabile globale per tenere traccia delle modifiche ai crediti
bool creditsChanged = false;

// Prototipi delle funzioni
bool isValidIP(const std::string& ip);
bool backupCreditsFile(const std::string& filename);
bool saveCredits(const std::string& filename);
bool loadCredits(const std::string& filename);
bool banIP(const std::string& ip);
bool unbanIP(const std::string& ip);
void processLogLine(const std::string& line);
void periodicCleanup(const std::string& filename, int interval_seconds);

// Variabili globali per la gestione del log
int log_fd = -1;
std::string logFilePath;

// Funzione per ottenere l'ora corrente formattata
std::string getCurrentTime() {
    auto now = std::time(nullptr);
    std::tm* tm_ptr = std::localtime(&now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_ptr);
    return std::string(buffer);
}

// Funzione per formattare un time_t in stringa leggibile
std::string formatTime(time_t timeValue) {
    std::tm* tm_ptr = std::localtime(&timeValue);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_ptr);
    return std::string(buffer);
}

// Funzione per riaprire il file di log (gestione del SIGHUP)
void reopenLogFile(int signum) {
    if (g_logger) {
        g_logger->reopenLogFile();
        g_logger->info("Log file reopened in response to SIGHUP signal");
    }
}

// Lista degli IP fidati (opzionale, aggiungi il tuo IP per evitare di essere bannato)
std::set<std::string> trusted_ips = {
    // "TUO_IP", // Sostituisci "TUO_IP" con il tuo indirizzo IP pubblico
};

// Funzione per validare l'indirizzo IP senza espressioni regolari
bool isValidIP(const std::string& ip) {
    std::istringstream ss(ip);
    std::string token;
    int octet;
    int count = 0;

    while (std::getline(ss, token, '.')) {
        if (token.empty() || token.size() > 3) {
            return false;
        }
        for (char c : token) {
            if (!std::isdigit(c)) {
                return false;
            }
        }
        try {
            octet = std::stoi(token);
        } catch (...) {
            return false;
        }
        if (octet < 0 || octet > 255) {
            return false;
        }
        count++;
    }
    return count == 4;
}

// Funzione per creare un backup del file
bool backupCreditsFile(const std::string& filename) {
    // Controlla se il file esiste prima di tentare il backup
    if (!std::filesystem::exists(filename)) {
        // Il file non esiste, quindi non è necessario fare il backup
        return true;
    }

    try {
        std::filesystem::copy_file(
            filename,
            filename + ".bak",
            std::filesystem::copy_options::overwrite_existing
        );
        g_logger->debug("File di backup creato: " + filename + ".bak");
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        g_logger->error("Errore nel backup del file dei crediti: " + std::string(e.what()));
        return false;
    }
}

// Funzione per calcolare la durata del ban basata sulla sequenza di Fibonacci
int calculateBanDuration(int banCount) {
    // Sequenza di Fibonacci: 1, 1, 2, 3, 5, 8, 13, 21, ...
    // Ma noi vogliamo: 1, 2, 3, 5, 8, 13, 21, ...
    if (banCount <= 0) return BAN_DURATION; // 1 ora di default
    
    int prev = 1;
    int curr = 1;
    for (int i = 0; i < banCount; i++) {
        int next = prev + curr;
        prev = curr;
        curr = next;
    }
    
    // Moltiplicare per la durata di base (3600 secondi = 1 ora)
    return curr * BAN_DURATION;
}

// Salva i crediti su un file
bool saveCredits(const std::string& filename) {
    std::lock_guard<std::mutex> lock(ip_map_mutex);

    // Backup del file esistente
    backupCreditsFile(filename);

    std::ofstream outfile(filename);
    if (!outfile) {
        g_logger->error("Errore nell'apertura del file per salvare i crediti: " + filename);
        return false;
    }
    for (const auto& [ip, info] : ip_map) {
        if (isValidIP(ip)) {
            outfile << ip << " " << info.credits << " " << info.ban_end_time << " " << info.ban_count << "\n";
        }
    }
    outfile.close();
    g_logger->debug("Crediti salvati nel file: " + filename);
    return true;
}

// Carica i crediti salvati da un file
bool loadCredits(const std::string& filename) {
    std::lock_guard<std::mutex> lock(ip_map_mutex);

    std::ifstream infile(filename);
    if (!infile) {
        g_logger->info("Credits file not found. A new file will be created when saving.");
        return true;
    }

    std::string ip;
    int credits;
    time_t ban_end_time;
    int ban_count;
    int line_number = 0;
    bool data_modified = false;

    std::string line;
    while (std::getline(infile, line)) {
        line_number++;
        std::istringstream iss(line);
        
        // Legge i quattro campi: IP, crediti, tempo di ban, contatore ban
        if (!(iss >> ip >> credits >> ban_end_time >> ban_count)) {
            // Formato vecchio, prova a leggere senza il contatore di ban
            std::istringstream iss2(line);
            if (!(iss2 >> ip >> credits >> ban_end_time)) {
                g_logger->warning("Invalid format at line " + std::to_string(line_number) + " in credits file.");
                data_modified = true;
                continue;
            }
            // Se legge correttamente il vecchio formato, imposta il contatore a 0
            ban_count = 0;
            data_modified = true; // Per salvare con il nuovo formato
        }
        
        if (isValidIP(ip)) {
            ip_map[ip] = {credits, ban_end_time, ban_count};
        } else {
            g_logger->warning("Invalid IP address at line " + std::to_string(line_number) + ": " + ip);
            data_modified = true;
        }
    }
    infile.close();

    if (data_modified) {
        g_logger->info("Updating credits file to new format.");
        saveCredits(filename);
    } else {
        g_logger->info("Credits file loaded successfully.");
    }

    return true;
}

// Applica il ban all'IP
bool banIP(const std::string& ip) {
    if (!isValidIP(ip)) {
        g_logger->error("Tentativo di bannare un IP non valido: " + ip);
        return false;
    }
    
    // Utilizziamo il FirewallManager invece di system()
    if (g_firewallManager->blockIP(ip)) {
        std::lock_guard<std::mutex> lock(ip_map_mutex);
        
        // Incrementa il contatore dei ban
        if (ip_map.find(ip) == ip_map.end()) {
            ip_map[ip] = {0, 0, 1}; // Inizializza se è un nuovo IP
        } else {
            ip_map[ip].ban_count++;
        }
        
        // Calcola la durata del ban in base al contatore
        int banDuration = calculateBanDuration(ip_map[ip].ban_count - 1);
        time_t banEndTime = time(nullptr) + banDuration;
        ip_map[ip].ban_end_time = banEndTime;
        
        // Log con informazioni sul ban
        std::string banInfo = "IP bannato: " + ip + " fino a " + formatTime(banEndTime) + 
                             " (Ban #" + std::to_string(ip_map[ip].ban_count) + 
                             ", durata: " + std::to_string(banDuration / 3600) + " ore)";
        g_logger->warning(banInfo);
        
        creditsChanged = true;
        return true;
    }
    return false;
}

// Rimuove il ban dall'IP
bool unbanIP(const std::string& ip) {
    if (!isValidIP(ip)) {
        g_logger->error("Tentativo di rimuovere il ban da un IP non valido: " + ip);
        return false;
    }
    
    // Utilizziamo il FirewallManager invece di system()
    if (g_firewallManager->unblockIP(ip)) {
        std::lock_guard<std::mutex> lock(ip_map_mutex);
        ip_map[ip].ban_end_time = 0;
        ip_map[ip].credits = INITIAL_CREDITS;
        // Non resettiamo il contatore dei ban, così la prossima volta il ban sarà più lungo
        g_logger->info("Ban scaduto per IP: " + ip + ". IP sbloccato con " + std::to_string(INITIAL_CREDITS) + 
                      " crediti. Storia di ban: " + std::to_string(ip_map[ip].ban_count));
        creditsChanged = true;
        return true;
    }
    return false;
}

// Processa una linea del log
void processLogLine(const std::string& line) {
    std::string ip;
    bool success = false;

    // Adattare il parsing in base al formato del log
    if (line.find("Failed password") != std::string::npos) {
        success = false;
    } else if (line.find("Accepted password") != std::string::npos) {
        success = true;
    } else {
        return; // Linea non rilevante
    }

    // Estrarre l'IP dalla linea in modo sicuro
    size_t pos = line.find("from ");
    if (pos != std::string::npos) {
        size_t start = pos + 5;
        size_t end = line.find(" ", start);
        if (end != std::string::npos) {
            ip = line.substr(start, end - start);
        } else {
            ip = line.substr(start);
        }
    } else {
        return; // IP non trovato
    }

    // Ignora gli IP fidati
    if (trusted_ips.find(ip) != trusted_ips.end()) {
        g_logger->debug("IP fidato ignorato: " + ip);
        return;
    }

    // Validare l'indirizzo IP
    if (!isValidIP(ip)) {
        g_logger->error("Indirizzo IP non valido nel log: " + ip);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(ip_map_mutex);

        // Controlla se l'IP esiste già nella mappa
        if (ip_map.find(ip) == ip_map.end()) {
            // L'IP è nuovo, inizializza i crediti
            ip_map[ip] = {INITIAL_CREDITS, 0, 0};
            g_logger->debug("Nuovo IP rilevato: " + ip + ". Crediti iniziali: " + std::to_string(INITIAL_CREDITS));
        }

        // Verifica se l'IP è bannato
        time_t current_time = time(nullptr);
        if (ip_map[ip].ban_end_time > current_time) {
            // L'IP è ancora bannato
            g_logger->debug("Tentativo di accesso da IP bannato: " + ip);
            return;
        } else if (ip_map[ip].ban_end_time != 0) {
            // Il ban è scaduto
            if (!unbanIP(ip)) {
                return;
            }
        }

        // Aggiorna i crediti
        if (success) {
            ip_map[ip].credits = std::min(ip_map[ip].credits + 1, MAX_CREDITS);
            creditsChanged = true;
            g_logger->info("Accesso riuscito da " + ip + ". Crediti: " + std::to_string(ip_map[ip].credits));
        } else {
            ip_map[ip].credits--;
            creditsChanged = true;
            g_logger->info("Accesso fallito da " + ip + ". Crediti: " + std::to_string(ip_map[ip].credits));
            if (ip_map[ip].credits <= 0) {
                banIP(ip);
            }
        }
    }
}

// Funzione per la pulizia periodica
void periodicCleanup(const std::string& filename, int interval_seconds) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
        g_logger->debug("Avvio pulizia periodica...");
        loadCredits(filename);
        saveCredits(filename);
        g_logger->debug("Pulizia periodica completata.");
    }
}

int main(int argc, char* argv[]) {
    std::string configFile = "credban.config"; // Default configuration file
    std::string version = "1.2.0";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            // Print help message
            std::cout << "CredBan - SSH Brute Force Protection System\n";
            std::cout << "Usage: " << argv[0] << " [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  -c, --config FILE    Specify the configuration file to use\n";
            std::cout << "  -h, --help           Show this help message\n";
            std::cout << "  -v, --version        Show the program version\n";
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            // Print version
            std::cout << "CredBan version " << version << "\n";
            return 0;
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            // Specify configuration file
            configFile = argv[i + 1];
            i++; // Skip next argument (file name)
        }
    }
    
    // Initialize configuration manager
    g_configManager = new ConfigManager(configFile);
    if (!g_configManager->loadConfig()) {
        std::cerr << getCurrentTime() << " - Error loading configuration. Using default values.\n";
    } else {
        // Load values from configuration
        MAX_CREDITS = g_configManager->getInt("Credits", "MaxCredits", MAX_CREDITS);
        INITIAL_CREDITS = g_configManager->getInt("Credits", "InitialCredits", INITIAL_CREDITS);
        BAN_DURATION = g_configManager->getInt("Credits", "BanDurationSeconds", BAN_DURATION);
        
        CREDITS_FILE = g_configManager->getString("Files", "CreditsFile", CREDITS_FILE);
        LOG_FILE_PATH = g_configManager->getString("Files", "CredBanLogFile", LOG_FILE_PATH);
        AUTH_LOG_FILE = g_configManager->getString("Files", "AuthLogFile", AUTH_LOG_FILE);
        
        PID_FILE = g_configManager->getString("General", "PidFile", PID_FILE);
        
        CLEANUP_INTERVAL = g_configManager->getInt("Intervals", "PeriodicCleanupSeconds", CLEANUP_INTERVAL);
        LOG_CHECK_INTERVAL = g_configManager->getInt("Intervals", "LogCheckSeconds", LOG_CHECK_INTERVAL);
        
        // Load trusted IPs list
        trusted_ips = g_configManager->getIPList("IP", "TrustedIPs");
    }
    
    // Initialize logger
    std::string logLevelStr = g_configManager->getString("Logging", "MinLevel", "INFO");
    LogLevel logLevel = Logger::stringToLogLevel(logLevelStr);
    bool enableConsole = g_configManager->getString("Logging", "EnableConsole", "false") == "true";
    bool enableSyslog = g_configManager->getString("Logging", "EnableSyslog", "true") == "true";
    
    g_logger = new Logger(LOG_FILE_PATH, logLevel, enableConsole, enableSyslog);
    if (!g_logger->initialize()) {
        std::cerr << getCurrentTime() << " - Error initializing logger.\n";
        return 1;
    }
    
    // Initialize firewall manager
    g_firewallManager = new FirewallManager();
    if (!g_firewallManager->initialize()) {
        g_logger->error("Error initializing firewall manager. Make sure you have root permissions.");
        return 1;
    }
    
    // Register SIGHUP signal handler
    signal(SIGHUP, reopenLogFile);

    // Write PID to file
    std::ofstream pidFile(PID_FILE);
    if (pidFile.is_open()) {
        pidFile << getpid();
        pidFile.close();
        g_logger->debug("PID " + std::to_string(getpid()) + " written to file " + PID_FILE);
    } else {
        g_logger->error("Unable to write PID file: " + PID_FILE);
    }

    // Log program startup with detailed information
    g_logger->info("========================================");
    g_logger->info("CredBan v" + version + " started");
    g_logger->info("Configuration loaded from: " + configFile);
    g_logger->info("Log level: " + logLevelStr);
    g_logger->info("Credits configuration: Max=" + std::to_string(MAX_CREDITS) + 
                  ", Initial=" + std::to_string(INITIAL_CREDITS) + 
                  ", BanDuration=" + std::to_string(BAN_DURATION) + "s");
    g_logger->info("Monitoring auth log: " + AUTH_LOG_FILE);
    if (trusted_ips.size() > 0) {
        std::string trustedList = "";
        for (const auto& ip : trusted_ips) {
            if (!trustedList.empty()) trustedList += ", ";
            trustedList += ip;
        }
        g_logger->info("Trusted IPs: " + trustedList);
    } else {
        g_logger->info("No trusted IPs configured");
    }
    g_logger->info("========================================");

    // Load credits
    if (!loadCredits(CREDITS_FILE)) {
        g_logger->error("Error loading credits. Initializing empty credits map.");
    }

    // Start periodic cleanup thread
    std::thread cleanupThread(periodicCleanup, CREDITS_FILE, CLEANUP_INTERVAL);
    cleanupThread.detach();
    g_logger->debug("Periodic cleanup thread started with interval of " + std::to_string(CLEANUP_INTERVAL) + " seconds");

    // Open auth log file
    std::ifstream authLogFile(AUTH_LOG_FILE);
    if (!authLogFile.is_open()) {
        g_logger->error("Unable to open auth log file: " + AUTH_LOG_FILE);
        return 1;
    }

    g_logger->info("Started monitoring auth log: " + AUTH_LOG_FILE);

    // Position pointer at the end of the file to read only new lines
    authLogFile.seekg(0, std::ios::end);

    while (true) {
        std::string line;
        while (std::getline(authLogFile, line)) {
            try {
                processLogLine(line);
            } catch (const std::exception& e) {
                g_logger->error("Exception while processing log line: " + std::string(e.what()));
            }
        }

        // Save credits only if modified
        if (creditsChanged) {
            if (!saveCredits(CREDITS_FILE)) {
                g_logger->error("Error saving credits.");
            }
            creditsChanged = false; // Reset variable after saving
        }

        // Wait before checking new logs
        std::this_thread::sleep_for(std::chrono::seconds(LOG_CHECK_INTERVAL));

        // Reset file error states and update position
        if (authLogFile.eof()) {
            authLogFile.clear();
        }
        authLogFile.seekg(0, std::ios::cur);
    }

    authLogFile.close();
    delete g_configManager; // Free configuration manager memory
    delete g_firewallManager; // Free firewall manager memory
    delete g_logger; // Free logger memory
    return 0;
}
