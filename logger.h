#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <vector>
#include <sstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <map>

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
};

class Logger {
private:
    std::string logFilePath;
    std::ofstream logFile;
    std::mutex logMutex;
    LogLevel minLevel;
    bool enableConsole;
    bool enableSyslog;
    
    const std::map<LogLevel, std::string> levelNames = {
        {LogLevel::DEBUG, "DEBUG"},
        {LogLevel::INFO, "INFO"},
        {LogLevel::WARNING, "WARN"},
        {LogLevel::ERROR, "ERROR"}
    };
    
    // Formatta il timestamp corrente
    std::string getCurrentTimestamp();
    
    // Scrive sul syslog
    void writeToSyslog(LogLevel level, const std::string& message);

public:
    // Costruttore
    Logger(const std::string& logFilePath, LogLevel minLevel = LogLevel::INFO, 
           bool enableConsole = false, bool enableSyslog = false);
    
    // Distruttore
    ~Logger();
    
    // Inizializza il logger
    bool initialize();
    
    // Cambia il livello minimo di log
    void setMinLevel(LogLevel level);
    
    // Attiva/disattiva l'output su console
    void setConsoleOutput(bool enable);
    
    // Attiva/disattiva l'output su syslog
    void setSyslogOutput(bool enable);
    
    // Metodi di logging per diversi livelli
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    
    // Metodo generico per il logging
    void log(LogLevel level, const std::string& message);
    
    // Converte una stringa in LogLevel
    static LogLevel stringToLogLevel(const std::string& levelStr);
    
    // Riapre il file di log (per rotazione log)
    bool reopenLogFile();
};

#endif // LOGGER_H 