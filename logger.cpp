#include "logger.h"
#include <syslog.h>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <cstring>  // Per strerror
#include <cerrno>   // Per errno

// Costruttore
Logger::Logger(const std::string& logFilePath, LogLevel minLevel, bool enableConsole, bool enableSyslog)
    : logFilePath(logFilePath), minLevel(minLevel), enableConsole(enableConsole), enableSyslog(enableSyslog) {
}

// Distruttore
Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
    
    if (enableSyslog) {
        closelog();
    }
}

// Inizializza il logger
bool Logger::initialize() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Stampa un messaggio sulla console indipendentemente dalla configurazione
    std::cout << "Logger::initialize - Attempting to open log file: " << logFilePath << std::endl;
    
    // Verifica se il file esiste
    bool fileExists = std::filesystem::exists(logFilePath);
    std::cout << "Log file exists: " << (fileExists ? "yes" : "no") << std::endl;
    
    if (fileExists) {
        // Controlla i permessi
        try {
            auto perms = std::filesystem::status(logFilePath).permissions();
            bool canWrite = (perms & std::filesystem::perms::owner_write) != std::filesystem::perms{};
            std::cout << "File is writable: " << (canWrite ? "yes" : "no") << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Error checking permissions: " << e.what() << std::endl;
        }
    }
    
    // Apri il file di log
    logFile.open(logFilePath, std::ios::app);
    if (!logFile.is_open()) {
        std::cout << "Failed to open log file: " << strerror(errno) << std::endl;
        
        // Tenta di creare la directory se non esiste
        auto path = std::filesystem::path(logFilePath);
        auto parent = path.parent_path();
        if (!std::filesystem::exists(parent)) {
            std::cout << "Parent directory doesn't exist, trying to create it" << std::endl;
            try {
                std::filesystem::create_directories(parent);
                logFile.open(logFilePath, std::ios::app);
            } catch (const std::exception& e) {
                std::cout << "Error creating directory: " << e.what() << std::endl;
            }
        }
        
        if (!logFile.is_open()) {
            return false;
        }
    }
    
    // Configura syslog se necessario
    if (enableSyslog) {
        openlog("credban", LOG_PID | LOG_NDELAY, LOG_AUTH);
    }
    
    // Log di avvio
    std::cout << "Log file opened successfully, writing initialization message" << std::endl;
    logFile << getCurrentTimestamp() << " - Logger initialized" << std::endl;
    logFile.flush();
    std::cout << "Initialization message written" << std::endl;
    
    return true;
}

// Formatta il timestamp corrente
std::string Logger::getCurrentTimestamp() {
    auto now = std::time(nullptr);
    auto tm = std::localtime(&now);
    
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Scrive sul syslog
void Logger::writeToSyslog(LogLevel level, const std::string& message) {
    if (!enableSyslog) return;
    
    int priority;
    switch (level) {
        case LogLevel::DEBUG:
            priority = LOG_DEBUG;
            break;
        case LogLevel::INFO:
            priority = LOG_INFO;
            break;
        case LogLevel::WARNING:
            priority = LOG_WARNING;
            break;
        case LogLevel::ERROR:
            priority = LOG_ERR;
            break;
        default:
            priority = LOG_NOTICE;
    }
    
    syslog(priority, "%s", message.c_str());
}

// Cambia il livello minimo di log
void Logger::setMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    minLevel = level;
    
    log(LogLevel::INFO, "Livello di log cambiato a " + levelNames.at(minLevel));
}

// Attiva/disattiva l'output su console
void Logger::setConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex);
    enableConsole = enable;
}

// Attiva/disattiva l'output su syslog
void Logger::setSyslogOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (enable && !enableSyslog) {
        openlog("credban", LOG_PID | LOG_NDELAY, LOG_AUTH);
    } else if (!enable && enableSyslog) {
        closelog();
    }
    
    enableSyslog = enable;
}

// Metodo generico per il logging
void Logger::log(LogLevel level, const std::string& message) {
    if (level < minLevel) return;
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::string timestamp = getCurrentTimestamp();
    std::string fullMessage = timestamp + " [" + levelNames.at(level) + "] " + message;
    
    // Scrivi sul file
    if (logFile.is_open()) {
        logFile << fullMessage << std::endl;
        logFile.flush();
    }
    
    // Scrivi sulla console se abilitato
    if (enableConsole) {
        if (level == LogLevel::ERROR) {
            std::cerr << fullMessage << std::endl;
        } else {
            std::cout << fullMessage << std::endl;
        }
    }
    
    // Scrivi su syslog se abilitato
    if (enableSyslog) {
        writeToSyslog(level, message);
    }
}

// Metodi per i vari livelli di log
void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

// Converte una stringa in LogLevel
LogLevel Logger::stringToLogLevel(const std::string& levelStr) {
    std::string level = levelStr;
    // Converti in minuscolo
    std::transform(level.begin(), level.end(), level.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    if (level == "debug") return LogLevel::DEBUG;
    if (level == "info") return LogLevel::INFO;
    if (level == "warning" || level == "warn") return LogLevel::WARNING;
    if (level == "error" || level == "err") return LogLevel::ERROR;
    
    // Default a INFO
    return LogLevel::INFO;
}

// Riapre il file di log
bool Logger::reopenLogFile() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    logFile.open(logFilePath, std::ios::app);
    if (!logFile.is_open()) {
        return false;
    }
    
    // Usa la scrittura diretta invece del metodo log() per evitare problemi
    logFile << getCurrentTimestamp() << " - Log file reopened" << std::endl;
    logFile.flush();
    
    return true;
} 