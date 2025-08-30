/*
 * CPE710 Antenna Alignment Tool
 *
 * Signal levels based on "Understanding and implementing Minimum RSSI" Configuration Guide
 * Source: https://www.tp-link.com/nordic/support/faq/4171/
 * 5-level mapping for WiFi signal strength display:
 *
 * > -60 dBm: Very Strong  ▂▄▆█
 * > -70 dBm: Strong       ▂▄▆
 * > -80 dBm: Moderate     ▂▄
 * > -90 dBm: Weak         ▂
 * ≤ -90 dBm: Very Weak
 *
 * Signal bars representation inspired by nmcli dev wifi command
 */

#include <iostream>
#include <string>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <regex>
#include <sstream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <fstream>
#include <array>

#define BUFFER_SIZE 128
#define SIGNAL_VERY_STRONG_THRESHOLD -60
#define SIGNAL_STRONG_THRESHOLD -70
#define SIGNAL_MODERATE_THRESHOLD -80
#define SIGNAL_WEAK_THRESHOLD -90
#define INITIAL_BEST_SIGNAL -999
#define CONNECTION_TIMEOUT 5
#define MEASUREMENT_INTERVAL_SECONDS 1
#define STATUS_UPDATE_INTERVAL 10
#define CPE_HOST "192.168.0.100"
#define CPE_USERNAME "admin"
#define CPE_PASSWORD "9125"
#define CPE_INTERFACE "ath7"

std::string logFileName;

struct SignalData {
    int signalDbm = 0;
    bool valid = false;
};

std::string executeCommand(const std::string &command) {
    std::array<char, BUFFER_SIZE> buffer;
    std::string result;
    std::unique_ptr<FILE, int(*)(FILE *)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

std::string executeSSHCommand(const std::string &host, const std::string &username, const std::string &password,
                              const std::string &command) {
    std::string sshCommand = "sshpass -p '" + password + "' ssh "
                             "-o HostKeyAlgorithms=+ssh-dss -o KexAlgorithms=+diffie-hellman-group1-sha1 "
                             "-o Ciphers=+3des-cbc -o MACs=+hmac-sha1 -o StrictHostKeyChecking=no "
                             "-o UserKnownHostsFile=/dev/null -o LogLevel=QUIET "
                             "-o ConnectTimeout=" + std::to_string(CONNECTION_TIMEOUT) + " "
                             + username + "@" + host + " '" + command + "'";

    try {
        return executeCommand(sshCommand);
    } catch (const std::exception &e) {
        return "";
    }
}

std::string getSignalBars(int signalDbm) {
    if (signalDbm > SIGNAL_VERY_STRONG_THRESHOLD) return "▂▄▆█";
    if (signalDbm > SIGNAL_STRONG_THRESHOLD) return "▂▄▆ ";
    if (signalDbm > SIGNAL_MODERATE_THRESHOLD) return "▂▄  ";
    if (signalDbm > SIGNAL_WEAK_THRESHOLD) return "▂   ";
    return "    ";
}

std::string getSignalQuality(int signalDbm) {
    if (signalDbm > SIGNAL_VERY_STRONG_THRESHOLD) return "VERY STRONG";
    if (signalDbm > SIGNAL_STRONG_THRESHOLD) return "STRONG";
    if (signalDbm > SIGNAL_MODERATE_THRESHOLD) return "MODERATE";
    if (signalDbm > SIGNAL_WEAK_THRESHOLD) return "WEAK";
    return "VERY WEAK";
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string getExperimentPrefix() {
    std::string prefix;
    std::cout << "Enter experiment prefix: ";
    std::getline(std::cin, prefix);
    return prefix;
}

std::string generateLogFileName(const std::string &prefix) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << prefix << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".txt";
    return ss.str();
}

void logResult(const std::string &entry) {
    std::ofstream logFile(logFileName, std::ios::app);
    if (logFile.is_open()) {
        logFile << entry << std::endl;
        logFile.close();
    }
}

void initializeLog() {
    std::ofstream logFile(logFileName);
    if (logFile.is_open()) {
        logFile << "CPE710 Antenna Alignment Log" << std::endl;
        logFile << "Started: " << getCurrentTimestamp() << std::endl;
        logFile << "Format: [Measurement] Timestamp Signal_dBm Quality" << std::endl;
        logFile << std::string(50, '-') << std::endl;
        logFile.close();
    }
}

SignalData parseIwlistScan(const std::string &output) {
    SignalData data;
    std::istringstream stream(output);
    std::string line;
    int strongestSignal = INITIAL_BEST_SIGNAL;

    while (std::getline(stream, line)) {
        if (line.find("Signal level=") != std::string::npos) {
            std::regex signalPattern("Signal level=(-?\\d+) dBm");
            std::smatch match;
            if (std::regex_search(line, match, signalPattern)) {
                int currentSignal = std::stoi(match[1]);
                if (currentSignal > strongestSignal) {
                    strongestSignal = currentSignal;
                    data.signalDbm = currentSignal;
                    data.valid = true;
                }
            }
        }
    }
    return data;
}

void displaySignal(int signalDbm, const std::string &prefix, bool isNewBest = false, bool shouldLog = true) {
    std::string indicator = isNewBest ? " ** NEW BEST **" : "";
    std::string output = prefix + getSignalBars(signalDbm) + " " + std::to_string(signalDbm) + "dBm (" +
                         getSignalQuality(signalDbm) + ")" + indicator;
    std::cout << output << std::endl;
    if (shouldLog) {
        std::string logEntry = prefix + getCurrentTimestamp() + " " + std::to_string(signalDbm) + "dBm " +
                               getSignalQuality(signalDbm) + indicator;
        logResult(logEntry);
    }
}

void displayAssessment(int signalDbm) {
    std::cout << "\nAssessment: " << getSignalQuality(signalDbm);
    if (signalDbm > SIGNAL_VERY_STRONG_THRESHOLD) std::cout << " - No adjustment needed";
    else if (signalDbm > SIGNAL_STRONG_THRESHOLD) std::cout << " - Minor tweaks may help";
    else if (signalDbm > SIGNAL_MODERATE_THRESHOLD) std::cout << " - Consider adjustment";
    else std::cout << " - Adjust antenna azimuth";
    std::cout << std::endl;
}

void displayCurrentBest(int bestSignal, int bestMeasurement, const std::string &bestTimestamp) {
    if (bestSignal == INITIAL_BEST_SIGNAL) return;
    std::cout << "    Current best:" << std::endl
            << "                                Timestamp: " << bestTimestamp << std::endl
            << "                                Measurement No.: [" << bestMeasurement << "]" << std::endl
            << "                                Signal Strength: ";
    displaySignal(bestSignal, "", false, false);
}

void alignmentMode(const std::string &host, const std::string &username, const std::string &password,
                   const std::string &interface) {
    std::cout << "=== ANTENNA ALIGNMENT MODE ===" << std::endl
            << "Adjust antenna azimuth slowly and observe readings" << std::endl
            << "Press Ctrl+C when optimal position found" << std::endl
            << std::string(50, '-') << std::endl;

    int bestSignal = INITIAL_BEST_SIGNAL, bestMeasurement = 0, measurementCount = 0;
    std::string bestTimestamp;

    while (true) {
        measurementCount++;
        std::string output = executeSSHCommand(host, username, password, "iwlist " + interface + " scan");
        SignalData data = parseIwlistScan(output);

        if (data.valid) {
            bool isNewBest = data.signalDbm > bestSignal;
            if (data.signalDbm > bestSignal) {
                bestSignal = data.signalDbm;
                bestMeasurement = measurementCount;
                bestTimestamp = getCurrentTimestamp();
            }
            displaySignal(data.signalDbm, "[" + std::to_string(measurementCount) + "] ", isNewBest);
        } else {
            std::string timeoutMsg = "[" + std::to_string(measurementCount) + "] Connection timeout or no data";
            std::cout << timeoutMsg << std::endl;
            logResult(timeoutMsg + " " + getCurrentTimestamp());
        }

        if (measurementCount % STATUS_UPDATE_INTERVAL == 0) {
            displayCurrentBest(bestSignal, bestMeasurement, bestTimestamp);
        }

        std::this_thread::sleep_for(std::chrono::seconds(MEASUREMENT_INTERVAL_SECONDS));
    }
}

void manualMode(const std::string &host, const std::string &username, const std::string &password,
                const std::string &interface) {
    std::cout << "=== MANUAL MEASUREMENT MODE ===" << std::endl
            << "Press Enter to take measurement, Ctrl+C to exit" << std::endl
            << std::string(50, '-') << std::endl;
    int bestSignal = INITIAL_BEST_SIGNAL, bestMeasurement = 0, measurementCount = 0;
    std::string bestTimestamp;
    std::string input;
    while (true) {
        std::cout << "Press Enter for measurement [" << (measurementCount + 1) << "]...";
        std::getline(std::cin, input);
        measurementCount++;
        std::string output = executeSSHCommand(host, username, password, "iwlist " + interface + " scan");
        SignalData data = parseIwlistScan(output);
        if (data.valid) {
            bool isNewBest = data.signalDbm > bestSignal;
            if (data.signalDbm > bestSignal) {
                bestSignal = data.signalDbm;
                bestMeasurement = measurementCount;
                bestTimestamp = getCurrentTimestamp();
            }
            displaySignal(data.signalDbm, "[" + std::to_string(measurementCount) + "] ", isNewBest);
        } else {
            std::string timeoutMsg = "[" + std::to_string(measurementCount) + "] Connection timeout or no data";
            std::cout << timeoutMsg << std::endl;
            logResult(timeoutMsg + " " + getCurrentTimestamp());
        }
        if (measurementCount % STATUS_UPDATE_INTERVAL == 0) {
            displayCurrentBest(bestSignal, bestMeasurement, bestTimestamp);
        }
    }
}

void singleMeasurement(const std::string &host, const std::string &username, const std::string &password,
                       const std::string &interface) {
    std::cout << "=== SINGLE MEASUREMENT ===" << std::endl;
    std::string output = executeSSHCommand(host, username, password, "iwlist " + interface + " scan");
    SignalData data = parseIwlistScan(output);
    if (data.valid) {
        std::cout << "Timestamp: " << getCurrentTimestamp() << std::endl;
        displaySignal(data.signalDbm, "Signal Strength: ");
        displayAssessment(data.signalDbm);
    } else {
        std::string failMsg = "Failed to get signal data " + getCurrentTimestamp();
        std::cout << failMsg << std::endl;
        logResult(failMsg);
    }
}

int main(int argc, char *argv[]) {
    std::string experimentPrefix = getExperimentPrefix();
    logFileName = generateLogFileName(experimentPrefix);
    initializeLog();
    std::cout << "Logging to: " << logFileName << std::endl << std::endl;
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-a" || arg == "--align") {
            alignmentMode(CPE_HOST, CPE_USERNAME, CPE_PASSWORD, CPE_INTERFACE);
        } else if (arg == "-m" || arg == "--manual") {
            manualMode(CPE_HOST, CPE_USERNAME, CPE_PASSWORD, CPE_INTERFACE);
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "CPE710 Antenna Alignment Tool\nUsage: " << argv[0] << " [options]\nOptions:\n"
                    << "  -a, --align     Real-time alignment mode\n"
                    << "  -m, --manual    Manual measurement mode\n"
                    << "  -h, --help      Show this help\n"
                    << "  (no options)    Single measurement\n\n"
                    << "Signal bars: ▂▄▆█ = Very Strong, ▂▄▆ = Strong, ▂▄ = Moderate, ▂ = Weak\n"
                    << "Targets strongest detected signal for alignment" << std::endl;
            return 0;
        }
    } else {
        singleMeasurement(CPE_HOST, CPE_USERNAME, CPE_PASSWORD, CPE_INTERFACE);
    }
    return 0;
}
