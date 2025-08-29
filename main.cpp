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
#include <vector>

#define BUFFER_SIZE 128
#define SIGNAL_EXCELLENT_THRESHOLD -40
#define SIGNAL_VERY_GOOD_THRESHOLD -50
#define SIGNAL_GOOD_THRESHOLD -60
#define SIGNAL_FAIR_THRESHOLD -70
#define INITIAL_BEST_SIGNAL -999
#define CONSECUTIVE_BEST_REQUIRED 3
#define CONNECTION_TIMEOUT 5
#define MEASUREMENT_INTERVAL_SECONDS 1
#define STATUS_UPDATE_INTERVAL 10
#define DEFAULT_HOST "192.168.0.100"
#define DEFAULT_USERNAME "admin"
#define DEFAULT_PASSWORD "9125"
#define DEFAULT_INTERFACE "ath7"

std::string executeCommand(const std::string& command) {
    std::array<char, BUFFER_SIZE> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

std::string executeSSHCommand(const std::string& host, const std::string& username, const std::string& password, const std::string& command) {
    std::string sshCommand =
        "sshpass -p '" + password + "' ssh "
        "-o HostKeyAlgorithms=+ssh-dss "
        "-o KexAlgorithms=+diffie-hellman-group1-sha1 "
        "-o Ciphers=+3des-cbc "
        "-o MACs=+hmac-sha1 "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o LogLevel=QUIET "
        "-o ConnectTimeout=" + std::to_string(CONNECTION_TIMEOUT) + " "
        + username + "@" + host + " '" + command + "'";

    try {
        return executeCommand(sshCommand);
    } catch (const std::exception& e) {
        return "";
    }
}

struct SignalData {
    int signalDbm = 0;
    std::string essid;
    bool valid = false;
};

SignalData parseIwlistScan(const std::string& output) {
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

void displaySignalData(const SignalData& data, int bestSignal, int measurementCount) {
    if (!data.valid) {
        std::cout << "[" << std::setw(3) << measurementCount << "] No signal data" << std::endl;
        return;
    }

    std::string signalQuality;
    if (data.signalDbm > SIGNAL_EXCELLENT_THRESHOLD) signalQuality = "EXCELLENT";
    else if (data.signalDbm > SIGNAL_VERY_GOOD_THRESHOLD) signalQuality = "VERY GOOD";
    else if (data.signalDbm > SIGNAL_GOOD_THRESHOLD) signalQuality = "GOOD";
    else if (data.signalDbm > SIGNAL_FAIR_THRESHOLD) signalQuality = "FAIR";
    else signalQuality = "POOR";

    std::string indicator = (data.signalDbm >= bestSignal) ? " ** NEW BEST **" : "";

    std::cout << "[" << std::setw(3) << measurementCount << "] "
              << "Signal: " << std::setw(3) << data.signalDbm << "dBm (" << signalQuality << ")"
              << indicator << std::endl;
}

void alignmentMode(const std::string& host, const std::string& username, const std::string& password, const std::string& interface) {
    std::cout << "=== ANTENNA ALIGNMENT MODE ===" << std::endl;
    std::cout << "Adjust antenna azimuth slowly and observe readings" << std::endl;
    std::cout << "Target: Signal > " << SIGNAL_VERY_GOOD_THRESHOLD << "dBm" << std::endl;
    std::cout << "Press Ctrl+C when optimal position found" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    int bestSignal = INITIAL_BEST_SIGNAL;
    int measurementCount = 0;
    int consecutiveBest = 0;

    while (true) {
        measurementCount++;

        std::string command = "iwlist " + interface + " scan";
        std::string output = executeSSHCommand(host, username, password, command);
        SignalData data = parseIwlistScan(output);

        if (data.valid) {
            if (data.signalDbm > bestSignal) {
                bestSignal = data.signalDbm;
                consecutiveBest = 1;
            } else if (data.signalDbm == bestSignal) {
                consecutiveBest++;
            } else {
                consecutiveBest = 0;
            }

            displaySignalData(data, bestSignal, measurementCount);

            if (consecutiveBest >= CONSECUTIVE_BEST_REQUIRED && bestSignal > SIGNAL_VERY_GOOD_THRESHOLD) {
                std::cout << "    *** STABLE OPTIMAL POSITION - Consider locking antenna ***" << std::endl;
            }

        } else {
            std::cout << "[" << std::setw(3) << measurementCount << "] Connection timeout or no data" << std::endl;
        }

        if (measurementCount % STATUS_UPDATE_INTERVAL == 0) {
            std::cout << "    Current best: " << bestSignal << "dBm" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(MEASUREMENT_INTERVAL_SECONDS));
    }
}

void singleMeasurement(const std::string& host, const std::string& username, const std::string& password, const std::string& interface) {
    std::cout << "=== SINGLE MEASUREMENT ===" << std::endl;

    std::string command = "iwlist " + interface + " scan";
    std::string output = executeSSHCommand(host, username, password, command);
    SignalData data = parseIwlistScan(output);

    if (data.valid) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::cout << "Timestamp: " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << std::endl;
        std::cout << "Signal Strength: " << data.signalDbm << " dBm (strongest detected)" << std::endl;

        std::cout << "\nAlignment Assessment:" << std::endl;
        if (data.signalDbm > SIGNAL_EXCELLENT_THRESHOLD) {
            std::cout << "- Signal: EXCELLENT - No adjustment needed" << std::endl;
        } else if (data.signalDbm > SIGNAL_VERY_GOOD_THRESHOLD) {
            std::cout << "- Signal: VERY GOOD - Minor tweaks may help" << std::endl;
        } else if (data.signalDbm > SIGNAL_GOOD_THRESHOLD) {
            std::cout << "- Signal: GOOD - Consider fine adjustment" << std::endl;
        } else {
            std::cout << "- Signal: NEEDS IMPROVEMENT - Adjust antenna azimuth" << std::endl;
        }

    } else {
        std::cout << "Failed to get signal data" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::string host = DEFAULT_HOST;
    std::string username = DEFAULT_USERNAME;
    std::string password = DEFAULT_PASSWORD;
    std::string interface = DEFAULT_INTERFACE;

    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-a" || arg == "--align") {
            alignmentMode(host, username, password, interface);
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "CPE710 Antenna Alignment Tool" << std::endl;
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -a, --align     Real-time alignment mode" << std::endl;
            std::cout << "  -h, --help      Show this help" << std::endl;
            std::cout << "  (no options)    Single measurement" << std::endl;
            std::cout << "\nTargets strongest detected signal for alignment" << std::endl;
            return 0;
        }
    } else {
        singleMeasurement(host, username, password, interface);
    }

    return 0;
}
