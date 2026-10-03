/**
 * ============================================================================
 * Project: Secure ATM PIN Authenticator Device Driver
 * File:    atm_app.cpp
 * Author:  Advanced Systems & Kernel Security Engineering
 * Standard: C++17 (Object-Oriented Architecture)
 * 
 * Description:
 *   Production-grade C++ user-space command-line interface for the Secure ATM
 *   Device Driver with Real-World Customer Database & Card Management:
 *     1. Persistent Customer Database: Pre-registered accounts (e.g., Ayesha)
 *        are saved to disk (atm_accounts.dat) so you NEVER have to re-register!
 *     2. Quick Card Insertion: Pick an existing card from the list or add a new one.
 *     3. Balance Persistence: Cash withdrawals & deposits update the database.
 *     4. 24-Hour Cooldown Security Hold (Accelerated to 30s for Live Demo)
 *     5. Bank Officer Master PUK Override ("778899") for Instant In-Branch Unlock
 *     6. Dual-Engine Architecture (Native Kernel Driver + WSL2 Virtual HSM)
 * ============================================================================
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <cstring>
#include <cerrno>

// POSIX System Headers for Driver Communication & Terminal Control
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace ATM {

/**
 * ANSI Terminal Color Codes
 */
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string RED     = "\033[1;31m";
    const std::string GREEN   = "\033[1;32m";
    const std::string YELLOW  = "\033[1;33m";
    const std::string BLUE    = "\033[1;34m";
    const std::string MAGENTA = "\033[1;35m";
    const std::string CYAN    = "\033[1;36m";
    const std::string WHITE   = "\033[1;37m";
    const std::string BOLD    = "\033[1m";
}

/**
 * Account Record for Stored Bank Customers
 */
struct CustomerAccount {
    std::string cardHolder;
    std::string cardNumber;
    double balance;
    std::string secretPIN;
};

/**
 * Persistent Customer Database
 * Manages saved bank accounts so users don't have to register every time.
 */
class AccountDatabase {
private:
    std::string dbFile_;
    std::vector<CustomerAccount> accounts_;

    void loadDefaults() {
        accounts_.clear();
        accounts_.push_back({"Ayesha", "4532-8801-9923-1044", 15000.00, "2580"});
        accounts_.push_back({"Alice V. Mercer", "5120-1122-3344-5566", 8500.50, "1234"});
        accounts_.push_back({"John Doe", "4000-1234-5678-9010", 3200.00, "9999"});
    }

public:
    explicit AccountDatabase(std::string dbFile = "atm_accounts.dat")
        : dbFile_(std::move(dbFile)) {
        if (!loadFromFile()) {
            loadDefaults();
            saveToFile();
        }
    }

    bool loadFromFile() {
        std::ifstream in(dbFile_);
        if (!in.is_open()) return false;

        accounts_.clear();
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            std::istringstream iss(line);
            std::string holder, cardNum, balanceStr, pin;
            if (std::getline(iss, holder, '|') &&
                std::getline(iss, cardNum, '|') &&
                std::getline(iss, balanceStr, '|') &&
                std::getline(iss, pin)) {
                try {
                    double bal = std::stod(balanceStr);
                    accounts_.push_back({holder, cardNum, bal, pin});
                } catch (...) {}
            }
        }
        return !accounts_.empty();
    }

    void saveToFile() {
        std::ofstream out(dbFile_, std::ios::trunc);
        if (!out.is_open()) return;

        for (const auto& acc : accounts_) {
            out << acc.cardHolder << "|"
                << acc.cardNumber << "|"
                << std::fixed << std::setprecision(2) << acc.balance << "|"
                << acc.secretPIN << "\n";
        }
    }

    const std::vector<CustomerAccount>& getAllAccounts() const {
        return accounts_;
    }

    CustomerAccount* findByCardNumber(const std::string& cardNum) {
        for (auto& acc : accounts_) {
            if (acc.cardNumber == cardNum) return &acc;
        }
        return nullptr;
    }

    void addAccount(const CustomerAccount& acc) {
        accounts_.push_back(acc);
        saveToFile();
    }

    void updateBalance(const std::string& cardNum, double newBalance) {
        for (auto& acc : accounts_) {
            if (acc.cardNumber == cardNum) {
                acc.balance = newBalance;
                saveToFile();
                break;
            }
        }
    }
};

/**
 * Structured representation of Driver State
 */
struct DriverStatus {
    std::string rawStatus;
    std::string stateLabel;
    int failedAttempts = 0;
    int maxAttempts = 3;
    bool isLocked = false;
    bool isAuthenticated = false;
    int cooldownRemaining = 0;
    bool isVirtualMode = false;

    void printSummary() const {
        std::cout << Color::CYAN << "  [HARDWARE & DRIVER DIAGNOSTICS]" << Color::RESET << "\n";
        std::cout << "  ├─ Execution Engine:    "
                  << (isVirtualMode ? (Color::YELLOW + "Virtual Kernel HSM (WSL2 Emulation)")
                                    : (Color::GREEN  + "Native Linux Kernel Module (/dev/atm_auth)"))
                  << Color::RESET << "\n";
        std::cout << "  ├─ Security State:      ";
        if (isLocked) {
            std::cout << Color::RED << "TEMPORARILY LOCKED (24-Hour Security Hold)" << Color::RESET << "\n";
            std::cout << "  ├─ Cooldown Remaining:  " << Color::RED << Color::BOLD
                      << cooldownRemaining << " seconds (Demo Mode)" << Color::RESET << "\n";
        } else if (isAuthenticated) {
            std::cout << Color::GREEN << "AUTHENTICATED (Session Active)" << Color::RESET << "\n";
        } else {
            std::cout << Color::YELLOW << "READY / AWAITING PIN" << Color::RESET << "\n";
        }
        std::cout << "  ├─ Failed Attempts:     " 
                  << (failedAttempts >= maxAttempts ? Color::RED : Color::WHITE)
                  << failedAttempts << " / " << maxAttempts << Color::RESET << "\n";
        std::cout << "  └─ In-Branch PUK Reset: " 
                  << Color::CYAN << "ARMED (Master PUK: 778899)" << Color::RESET << "\n";
    }
};

/**
 * Utilities for Memory Scrubber & Hidden Keystrokes
 */
class SecurityUtils {
public:
    static void secureZero(std::string& sensitiveData) {
        volatile char* p = const_cast<volatile char*>(sensitiveData.data());
        for (size_t i = 0; i < sensitiveData.size(); ++i) {
            p[i] = 0;
        }
        sensitiveData.clear();
    }

    static std::string readMaskedInput(const std::string& prompt) {
        std::cout << prompt << std::flush;
        std::string input;
        struct termios oldSettings, newSettings;

        if (tcgetattr(STDIN_FILENO, &oldSettings) != 0) {
            std::cin >> input;
            return input;
        }

        newSettings = oldSettings;
        newSettings.c_lflag &= ~(ECHO | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

        char ch = 0;
        while (read(STDIN_FILENO, &ch, 1) > 0) {
            if (ch == '\n' || ch == '\r') {
                std::cout << "\n";
                break;
            } else if (ch == 127 || ch == '\b') {
                if (!input.empty()) {
                    input.pop_back();
                    std::cout << "\b \b" << std::flush;
                }
            } else if (ch >= 32 && ch <= 126) {
                input.push_back(ch);
                std::cout << '*' << std::flush;
            }
        }

        tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
        return input;
    }

    static bool constantTimeCompare(const std::string& a, const std::string& b) {
        if (a.length() != b.length()) return false;
        volatile unsigned char diff = 0;
        for (size_t i = 0; i < a.length(); ++i) {
            diff |= (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
        }
        return diff == 0;
    }
};

/**
 * ATMDevice: Hardware Abstraction Layer (HAL)
 */
class ATMDevice {
private:
    std::string devicePath_;
    int fd_;
    bool isVirtualMode_;

    int virtualFailedAttempts_;
    bool virtualIsLocked_;
    bool virtualIsAuthenticated_;
    std::chrono::steady_clock::time_point virtualLockoutTime_;
    int virtualCooldownDurationSec_;
    std::string virtualMasterPin_;
    std::string virtualMasterPuk_;
    std::vector<std::string> virtualKernelLogs_;

    void logKernel(const std::string& msg) {
        virtualKernelLogs_.push_back(msg);
    }

    void evaluateVirtualCooldown() {
        if (virtualIsLocked_) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - virtualLockoutTime_).count();
            if (elapsed >= virtualCooldownDurationSec_) {
                virtualIsLocked_ = false;
                virtualFailedAttempts_ = 0;
                logKernel("[atm_auth: Ring 0 Info] 24-Hour Cooldown hold expired. Account unlocked automatically.");
            }
        }
    }

public:
    explicit ATMDevice(std::string devicePath = "/dev/atm_auth")
        : devicePath_(std::move(devicePath)),
          fd_(-1),
          isVirtualMode_(false),
          virtualFailedAttempts_(0),
          virtualIsLocked_(false),
          virtualIsAuthenticated_(false),
          virtualCooldownDurationSec_(30),
          virtualMasterPin_("2580"),
          virtualMasterPuk_("778899") {}

    ~ATMDevice() {
        closeDevice();
    }

    bool openDevice() {
        if (fd_ >= 0) return true;
        fd_ = ::open(devicePath_.c_str(), O_RDWR);
        if (fd_ < 0) {
            isVirtualMode_ = true;
            return true;
        }
        isVirtualMode_ = false;
        return true;
    }

    void closeDevice() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        if (isVirtualMode_) {
            virtualIsAuthenticated_ = false;
        }
    }

    bool isVirtualMode() const { return isVirtualMode_; }
    const std::string& getDevicePath() const { return devicePath_; }
    const std::vector<std::string>& getKernelLogs() const { return virtualKernelLogs_; }

    bool setCustomPIN(const std::string& newPin, std::string& outMsg) {
        openDevice();

        if (isVirtualMode_) {
            virtualMasterPin_ = newPin;
            virtualFailedAttempts_ = 0;
            virtualIsLocked_ = false;
            virtualIsAuthenticated_ = false;
            logKernel("[atm_auth: Ring 0 Config] Card PIN provisioned into Kernel HSM.");
            outMsg = "PIN verified and active in Kernel HSM.";
            return true;
        }

        std::string payload = "SET_PIN:" + newPin + "\n";
        ssize_t written = ::write(fd_, payload.c_str(), payload.length());
        if (written < 0) {
            outMsg = "Failed to update PIN in driver: " + std::string(std::strerror(errno));
            return false;
        }

        outMsg = "PIN verified and active in Linux Kernel HSM.";
        return true;
    }

    DriverStatus queryStatus() {
        openDevice();
        DriverStatus status;
        status.isVirtualMode = isVirtualMode_;

        if (isVirtualMode_) {
            evaluateVirtualCooldown();

            status.failedAttempts = virtualFailedAttempts_;
            status.maxAttempts = 3;
            status.isLocked = virtualIsLocked_;
            status.isAuthenticated = virtualIsAuthenticated_;

            if (virtualIsLocked_) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - virtualLockoutTime_).count();
                status.cooldownRemaining = (elapsed < virtualCooldownDurationSec_) ? (virtualCooldownDurationSec_ - elapsed) : 0;
                status.stateLabel = "LOCKED";
            } else if (virtualIsAuthenticated_) {
                status.stateLabel = "AUTHENTICATED";
                status.cooldownRemaining = 0;
            } else {
                status.stateLabel = "READY";
                status.cooldownRemaining = 0;
            }

            status.rawStatus = "STATUS=" + status.stateLabel +
                               ";FAILED=" + std::to_string(status.failedAttempts) +
                               ";MAX=3;LOCKED=" + (status.isLocked ? "1" : "0") +
                               ";COOLDOWN=" + std::to_string(status.cooldownRemaining);
            return status;
        }

        char buffer[128];
        std::memset(buffer, 0, sizeof(buffer));
        ssize_t bytesRead = ::pread(fd_, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead < 0) {
            status.rawStatus = "STATUS=READY;FAILED=0;MAX=3;LOCKED=0;COOLDOWN=0";
            return status;
        }

        status.rawStatus = std::string(buffer, bytesRead);
        std::istringstream stream(status.rawStatus);
        std::string token;
        while (std::getline(stream, token, ';')) {
            auto eqPos = token.find('=');
            if (eqPos != std::string::npos) {
                std::string key = token.substr(0, eqPos);
                std::string val = token.substr(eqPos + 1);
                if (!val.empty() && val.back() == '\n') val.pop_back();

                if (key == "STATUS") {
                    status.stateLabel = val;
                    status.isAuthenticated = (val == "AUTHENTICATED");
                } else if (key == "FAILED") {
                    status.failedAttempts = std::stoi(val);
                } else if (key == "MAX") {
                    status.maxAttempts = std::stoi(val);
                } else if (key == "LOCKED") {
                    status.isLocked = (std::stoi(val) == 1);
                } else if (key == "COOLDOWN") {
                    status.cooldownRemaining = std::stoi(val);
                }
            }
        }

        return status;
    }

    bool authenticatePIN(const std::string& pin, std::string& outMessage) {
        openDevice();

        if (isVirtualMode_) {
            evaluateVirtualCooldown();

            if (virtualIsLocked_) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - virtualLockoutTime_).count();
                int rem = (elapsed < virtualCooldownDurationSec_) ? (virtualCooldownDurationSec_ - elapsed) : 0;
                logKernel("[atm_auth: Ring 0 Alert] REJECTION: Security Hold active (" + std::to_string(rem) + "s remaining).");
                outMessage = "SECURITY LOCKOUT: 24-Hour Security Hold Active (" + std::to_string(rem) + "s remaining in Demo).";
                return false;
            }

            bool match = SecurityUtils::constantTimeCompare(pin, virtualMasterPin_);

            if (match) {
                virtualIsAuthenticated_ = true;
                virtualFailedAttempts_ = 0;
                logKernel("[atm_auth: Ring 0 Info] AUTH SUCCESS: PIN verified. Session granted.");
                outMessage = "PIN Accepted. Welcome to your account.";
                return true;
            } else {
                virtualIsAuthenticated_ = false;
                virtualFailedAttempts_++;
                logKernel("[atm_auth: Ring 0 Warning] AUTH FAILURE: Invalid PIN attempt [" +
                          std::to_string(virtualFailedAttempts_) + "/3]");

                if (virtualFailedAttempts_ >= 3) {
                    virtualIsLocked_ = true;
                    virtualLockoutTime_ = std::chrono::steady_clock::now();
                    logKernel("[atm_auth: Ring 0 Alert] *** 3 FAILED ATTEMPTS: 24-HOUR SECURITY HOLD TRIGGERED! ***");
                    outMessage = "CRITICAL: 3 failed attempts reached! 24-Hour Security Hold Initiated (30s Demo Cooldown).";
                } else {
                    outMessage = "Authentication Failed: Incorrect PIN. Attempts remaining: " +
                                 std::to_string(3 - virtualFailedAttempts_);
                }
                return false;
            }
        }

        std::string payload = pin + "\n";
        ssize_t written = ::write(fd_, payload.c_str(), payload.length());

        if (written < 0) {
            DriverStatus cur = queryStatus();
            if (cur.isLocked) {
                outMessage = "SECURITY LOCKOUT: 24-Hour Security Hold Active (" +
                             std::to_string(cur.cooldownRemaining) + "s remaining).";
            } else {
                outMessage = "Kernel Driver Write Error: " + std::string(std::strerror(errno));
            }
            return false;
        }

        DriverStatus currentStatus = queryStatus();
        if (currentStatus.isLocked) {
            outMessage = "CRITICAL: 3 failed attempts! 24-Hour Security Hold Active (" +
                         std::to_string(currentStatus.cooldownRemaining) + "s remaining).";
            return false;
        } else if (currentStatus.isAuthenticated) {
            outMessage = "PIN Accepted. Welcome to your account.";
            return true;
        } else {
            outMessage = "Authentication Failed: Incorrect PIN. Attempts remaining: " +
                         std::to_string(currentStatus.maxAttempts - currentStatus.failedAttempts);
            return false;
        }
    }

    bool submitBankPUK(const std::string& puk, std::string& outMessage) {
        openDevice();

        if (isVirtualMode_) {
            bool match = SecurityUtils::constantTimeCompare(puk, virtualMasterPuk_);
            if (match) {
                virtualIsLocked_ = false;
                virtualFailedAttempts_ = 0;
                virtualIsAuthenticated_ = false;
                logKernel("[atm_auth: Ring 0 Info] BANK OVERRIDE: Master PUK verified. Security hold cleared!");
                outMessage = "Bank Officer Master PUK Accepted. Security Hold Removed Successfully!";
                return true;
            } else {
                logKernel("[atm_auth: Ring 0 Warning] BANK OVERRIDE REJECTED: Invalid Master PUK entered.");
                outMessage = "Invalid Bank PUK! Security authorization rejected.";
                return false;
            }
        }

        std::string payload = "PUK:" + puk + "\n";
        ssize_t written = ::write(fd_, payload.c_str(), payload.length());
        if (written < 0) {
            outMessage = "Invalid Bank PUK! Access Denied (" + std::string(std::strerror(errno)) + ")";
            return false;
        }

        DriverStatus currentStatus = queryStatus();
        if (!currentStatus.isLocked) {
            outMessage = "Bank Officer Master PUK Accepted. Security Hold Removed Successfully!";
            return true;
        } else {
            outMessage = "Invalid Bank PUK! Security Hold remains active.";
            return false;
        }
    }
};

/**
 * CardSession: Models user financial account
 */
class CardSession {
private:
    bool isInserted_;
    std::string cardNumber_;
    std::string accountHolder_;
    double accountBalance_;

public:
    CardSession()
        : isInserted_(false), cardNumber_(""), accountHolder_(""), accountBalance_(0.0) {}

    bool isInserted() const { return isInserted_; }
    const std::string& getCardNumber() const { return cardNumber_; }
    const std::string& getAccountHolder() const { return accountHolder_; }
    double getBalance() const { return accountBalance_; }

    void insertCard(const std::string& cardNum, const std::string& holder, double initialBalance) {
        cardNumber_ = cardNum;
        accountHolder_ = holder;
        accountBalance_ = initialBalance;
        isInserted_ = true;
    }

    void ejectCard() {
        isInserted_ = false;
        cardNumber_ = "";
        accountHolder_ = "";
        accountBalance_ = 0.0;
    }

    bool withdraw(double amount, std::string& error) {
        if (!isInserted_) {
            error = "No card inserted!";
            return false;
        }
        if (amount <= 0) {
            error = "Withdrawal amount must be greater than zero.";
            return false;
        }
        if (amount > accountBalance_) {
            error = "Insufficient funds! Current balance: $" + std::to_string(accountBalance_);
            return false;
        }
        accountBalance_ -= amount;
        return true;
    }

    bool deposit(double amount, std::string& error) {
        if (!isInserted_) {
            error = "No card inserted!";
            return false;
        }
        if (amount <= 0) {
            error = "Deposit amount must be positive.";
            return false;
        }
        accountBalance_ += amount;
        return true;
    }
};

/**
 * ATMController: Main Interactive Application Engine
 */
class ATMController {
private:
    std::shared_ptr<ATMDevice> device_;
    AccountDatabase db_;
    CardSession session_;
    bool authenticatedSession_;

    void printHeader() const {
        std::cout << Color::CYAN << Color::BOLD;
        std::cout << "================================================================\n";
        std::cout << "      SECURE ATM TERMINAL - KERNEL HSM AUTHENTICATOR v1.3       \n";
        std::cout << "================================================================\n";
        std::cout << Color::RESET;
    }

    void pausePrompt() const {
        std::cout << Color::WHITE << "\nPress Enter to return to the main menu..." << Color::RESET;
        std::cin.ignore(10000, '\n');
        std::cin.get();
    }

public:
    explicit ATMController(std::shared_ptr<ATMDevice> device)
        : device_(std::move(device)), authenticatedSession_(false) {}

    void run() {
        bool running = true;

        while (running) {
            DriverStatus status = device_->queryStatus();

            if (!status.isAuthenticated) {
                authenticatedSession_ = false;
            }

            printHeader();

            // Status Indicators
            std::cout << " [HARDWARE]: ";
            if (device_->isVirtualMode()) {
                std::cout << Color::YELLOW << "VIRTUAL KERNEL HSM (WSL2 Active)" << Color::RESET;
            } else {
                std::cout << Color::GREEN << "NATIVE KERNEL DRIVER (/dev/atm_auth)" << Color::RESET;
            }
            std::cout << "\n";

            std::cout << " [SECURITY]: ";
            if (status.isLocked) {
                std::cout << Color::RED << "TEMPORARILY LOCKED (24h Hold - "
                          << status.cooldownRemaining << "s Cooldown Remaining)" << Color::RESET << "\n";
            } else {
                std::cout << Color::GREEN << "OPERATIONAL (Nominal)" << Color::RESET << "\n";
            }

            std::cout << " [CARD]:     "
                      << (session_.isInserted() ? (Color::GREEN + "CARD INSERTED [" + session_.getAccountHolder() + " | " + session_.getCardNumber() + "]")
                                                : (Color::YELLOW + "NO CARD INSERTED"))
                      << Color::RESET << "\n";

            std::cout << " [SESSION]:  "
                      << (authenticatedSession_ ? (Color::GREEN + "AUTHENTICATED (Granted)")
                                                : (Color::WHITE + "UNAUTHENTICATED"))
                      << Color::RESET << "\n";

            std::cout << "----------------------------------------------------------------\n";
            std::cout << Color::BOLD << "MAIN MENU:\n" << Color::RESET;
            std::cout << "  1. Insert Debit Card (Select Registered or Add New)\n";
            std::cout << "  2. Enter PIN & Authenticate (via Kernel HSM)\n";
            std::cout << "  3. Inquire Account Balance\n";
            std::cout << "  4. Cash Withdrawal\n";
            std::cout << "  5. Deposit Funds\n";
            std::cout << "  6. Inspect Hardware & Kernel Diagnostics\n";
            std::cout << "  7. Eject Card / Terminate Session\n";
            std::cout << "  8. " << Color::MAGENTA << "Bank Officer Security Override (Enter Master PUK)" << Color::RESET << "\n";
            std::cout << "  9. Exit Application\n";
            std::cout << "----------------------------------------------------------------\n";
            std::cout << Color::CYAN << "Select an option [1-9]: " << Color::RESET;

            int choice = 0;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                continue;
            }

            switch (choice) {
                case 1: handleInsertCard(); break;
                case 2: handleAuthentication(); break;
                case 3: handleBalanceInquiry(); break;
                case 4: handleWithdrawal(); break;
                case 5: handleDeposit(); break;
                case 6: handleDiagnostics(); break;
                case 7: handleEjectCard(); break;
                case 8: handleBankPUKOverride(); break;
                case 9:
                    std::cout << Color::YELLOW << "\nShutting down Secure ATM Terminal. Goodbye!\n" << Color::RESET;
                    device_->closeDevice();
                    running = false;
                    break;
                default:
                    std::cout << Color::RED << "\nInvalid choice. Please select from 1 to 9.\n" << Color::RESET;
                    pausePrompt();
                    break;
            }
        }
    }

private:
    void handleInsertCard() {
        std::cout << "\n" << Color::BOLD << "--- INSERT DEBIT CARD ---" << Color::RESET << "\n";
        if (session_.isInserted()) {
            std::cout << Color::YELLOW << "A card is already inserted in the terminal ("
                      << session_.getAccountHolder() << ")!\n"
                      << "Please select Option 7 (Eject Card) first to use a different card.\n" << Color::RESET;
            pausePrompt();
            return;
        }

        const auto& accounts = db_.getAllAccounts();

        std::cout << Color::CYAN << "REGISTERED CARDS ON FILE (Pick to Insert Instantly):\n" << Color::RESET;
        for (size_t i = 0; i < accounts.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << Color::BOLD << std::left << std::setw(18) << accounts[i].cardHolder << Color::RESET
                      << " [Card: " << accounts[i].cardNumber << "]"
                      << " [Balance: $" << std::fixed << std::setprecision(2) << accounts[i].balance << "]\n";
        }
        std::cout << "  " << (accounts.size() + 1) << ". " << Color::YELLOW << "+ Issue & Register a Brand New Card" << Color::RESET << "\n";
        std::cout << "----------------------------------------------------------------\n";
        std::cout << Color::CYAN << "Select card to insert [1-" << (accounts.size() + 1) << "]: " << Color::RESET;

        int pick = 0;
        if (!(std::cin >> pick)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << Color::RED << "Invalid selection.\n" << Color::RESET;
            pausePrompt();
            return;
        }

        if (pick >= 1 && pick <= static_cast<int>(accounts.size())) {
            // Instant insertion of existing registered card!
            const auto& selected = accounts[pick - 1];

            std::cout << "Simulating smart card chip insertion for " << selected.cardHolder << "...\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            std::string msg;
            device_->setCustomPIN(selected.secretPIN, msg);

            session_.insertCard(selected.cardNumber, selected.cardHolder, selected.balance);
            authenticatedSession_ = false;

            std::cout << Color::GREEN << "\n[SUCCESS] Card inserted successfully!\n" << Color::RESET;
            std::cout << "  Cardholder:  " << selected.cardHolder << "\n";
            std::cout << "  Card Number: " << selected.cardNumber << "\n";
            std::cout << "  Status:      Card loaded. Please authenticate with your PIN (Option 2).\n";
            pausePrompt();
        } else if (pick == static_cast<int>(accounts.size() + 1)) {
            // Register a new customer card
            handleRegisterNewCard();
        } else {
            std::cout << Color::RED << "Invalid option selected.\n" << Color::RESET;
            pausePrompt();
        }
    }

    void handleRegisterNewCard() {
        std::cout << "\n" << Color::BOLD << "--- REGISTER & ISSUE NEW DEBIT CARD ---" << Color::RESET << "\n";
        std::cin.ignore(10000, '\n');

        std::cout << Color::CYAN << "1. Enter New Cardholder Name: " << Color::RESET;
        std::string holder;
        std::getline(std::cin, holder);
        if (holder.empty()) holder = "Customer";

        std::cout << Color::CYAN << "2. Enter 16-Digit Card Number (Press Enter for auto-generated): " << Color::RESET;
        std::string cardNum;
        std::getline(std::cin, cardNum);
        if (cardNum.empty()) cardNum = "4916-2000-8888-0001";

        std::cout << Color::CYAN << "3. Enter Initial Opening Deposit ($) [Default: 5000.00]: " << Color::RESET;
        std::string balanceStr;
        std::getline(std::cin, balanceStr);
        double initialBalance = 5000.00;
        if (!balanceStr.empty()) {
            try { initialBalance = std::stod(balanceStr); } catch (...) {}
        }

        std::cout << Color::CYAN << "4. Set Your Secret 4-Digit Security PIN:\n" << Color::RESET;
        std::string pin1 = SecurityUtils::readMaskedInput("   Enter New PIN:   ");
        std::string pin2 = SecurityUtils::readMaskedInput("   Confirm New PIN: ");

        if (pin1.empty() || pin1 != pin2) {
            std::cout << Color::RED << "\n[ERROR] PINs did not match or were empty! Card registration aborted.\n" << Color::RESET;
            SecurityUtils::secureZero(pin1);
            SecurityUtils::secureZero(pin2);
            pausePrompt();
            return;
        }

        // Save to persistent database
        CustomerAccount newAcc = {holder, cardNum, initialBalance, pin1};
        db_.addAccount(newAcc);

        // Provision PIN to driver
        std::string msg;
        device_->setCustomPIN(pin1, msg);
        SecurityUtils::secureZero(pin1);
        SecurityUtils::secureZero(pin2);

        session_.insertCard(cardNum, holder, initialBalance);
        authenticatedSession_ = false;

        std::cout << Color::GREEN << "\n[SUCCESS] New card registered in bank database & inserted into ATM!\n" << Color::RESET;
        std::cout << "  Cardholder:      " << holder << "\n";
        std::cout << "  Card Number:     " << cardNum << "\n";
        std::cout << "  Opening Balance: $" << std::fixed << std::setprecision(2) << initialBalance << "\n";
        pausePrompt();
    }

    void handleAuthentication() {
        std::cout << "\n" << Color::BOLD << "--- KERNEL PIN AUTHENTICATION ---" << Color::RESET << "\n";

        if (!session_.isInserted()) {
            std::cout << Color::RED << "Error: Please insert your debit card first (Option 1)!\n" << Color::RESET;
            pausePrompt();
            return;
        }

        if (authenticatedSession_) {
            std::cout << Color::GREEN << "Card is already authenticated for this session.\n" << Color::RESET;
            pausePrompt();
            return;
        }

        DriverStatus status = device_->queryStatus();
        if (status.isLocked) {
            std::cout << Color::RED << "\n[SECURITY REJECTION] Card is placed on a 24-Hour Security Hold!\n"
                      << "Cooldown Remaining: " << status.cooldownRemaining << " seconds (Demo Mode).\n"
                      << "To unlock immediately, visit a branch or use Bank Officer PUK (Option 8).\n"
                      << Color::RESET;
            pausePrompt();
            return;
        }

        std::cout << "Enter your 4-digit PIN for " << session_.getAccountHolder() << ":\n";
        std::string enteredPIN = SecurityUtils::readMaskedInput("  PIN: ");

        if (enteredPIN.empty()) {
            std::cout << Color::RED << "PIN cannot be empty!\n" << Color::RESET;
            pausePrompt();
            return;
        }

        std::cout << "Transmitting to Kernel HSM Subsystem for verification...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::string responseMsg;
        bool success = device_->authenticatePIN(enteredPIN, responseMsg);

        SecurityUtils::secureZero(enteredPIN);

        if (success) {
            authenticatedSession_ = true;
            std::cout << Color::GREEN << "\n[SUCCESS] " << responseMsg << Color::RESET << "\n";
        } else {
            authenticatedSession_ = false;
            std::cout << Color::RED << "\n[FAILED] " << responseMsg << Color::RESET << "\n";
        }

        pausePrompt();
    }

    void handleBankPUKOverride() {
        std::cout << "\n" << Color::MAGENTA << Color::BOLD
                  << "--- BANK OFFICER IN-BRANCH SECURITY OVERRIDE ---" << Color::RESET << "\n";
        std::cout << "This feature simulates a Bank Manager entering a Master PUK to clear a security hold.\n";
        std::cout << "Enter 6-digit Master Bank PUK (Default: 778899):\n";

        std::string enteredPUK = SecurityUtils::readMaskedInput("  Bank PUK: ");
        if (enteredPUK.empty()) {
            std::cout << Color::RED << "PUK cannot be empty!\n" << Color::RESET;
            pausePrompt();
            return;
        }

        std::cout << "Authorizing with Kernel Security Subsystem...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        std::string responseMsg;
        bool success = device_->submitBankPUK(enteredPUK, responseMsg);
        SecurityUtils::secureZero(enteredPUK);

        if (success) {
            std::cout << Color::GREEN << "\n[AUTHORIZED] " << responseMsg << Color::RESET << "\n";
        } else {
            std::cout << Color::RED << "\n[REJECTED] " << responseMsg << Color::RESET << "\n";
        }

        pausePrompt();
    }

    void handleBalanceInquiry() {
        std::cout << "\n" << Color::BOLD << "--- ACCOUNT BALANCE INQUIRY ---" << Color::RESET << "\n";
        if (!ensureAuthenticated()) return;

        std::cout << "  Account Holder:    " << session_.getAccountHolder() << "\n";
        std::cout << "  Card Number:       " << session_.getCardNumber() << "\n";
        std::cout << "  Available Balance: " << Color::GREEN << "$" << std::fixed << std::setprecision(2)
                  << session_.getBalance() << Color::RESET << "\n";

        pausePrompt();
    }

    void handleWithdrawal() {
        std::cout << "\n" << Color::BOLD << "--- CASH WITHDRAWAL ---" << Color::RESET << "\n";
        if (!ensureAuthenticated()) return;

        std::cout << "Enter withdrawal amount ($): ";
        double amount = 0.0;
        if (!(std::cin >> amount)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << Color::RED << "Invalid amount entered.\n" << Color::RESET;
            pausePrompt();
            return;
        }

        std::string error;
        if (session_.withdraw(amount, error)) {
            // Update persistent database
            db_.updateBalance(session_.getCardNumber(), session_.getBalance());

            std::cout << Color::GREEN << "\n[TRANSACTION SUCCESS] Dispensing $"
                      << std::fixed << std::setprecision(2) << amount << " in cash.\n"
                      << "New Balance: $" << session_.getBalance() << Color::RESET << "\n";
        } else {
            std::cout << Color::RED << "\n[TRANSACTION DECLINED] " << error << Color::RESET << "\n";
        }

        pausePrompt();
    }

    void handleDeposit() {
        std::cout << "\n" << Color::BOLD << "--- DEPOSIT FUNDS ---" << Color::RESET << "\n";
        if (!ensureAuthenticated()) return;

        std::cout << "Enter deposit amount ($): ";
        double amount = 0.0;
        if (!(std::cin >> amount)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << Color::RED << "Invalid amount entered.\n" << Color::RESET;
            pausePrompt();
            return;
        }

        std::string error;
        if (session_.deposit(amount, error)) {
            // Update persistent database
            db_.updateBalance(session_.getCardNumber(), session_.getBalance());

            std::cout << Color::GREEN << "\n[DEPOSIT ACCEPTED] Deposited $"
                      << std::fixed << std::setprecision(2) << amount << "\n"
                      << "Updated Balance: $" << session_.getBalance() << Color::RESET << "\n";
        } else {
            std::cout << Color::RED << "\n[DEPOSIT REJECTED] " << error << Color::RESET << "\n";
        }

        pausePrompt();
    }

    void handleDiagnostics() {
        std::cout << "\n" << Color::BOLD << "--- HARDWARE & KERNEL DIAGNOSTICS ---" << Color::RESET << "\n";
        DriverStatus status = device_->queryStatus();
        status.printSummary();

        std::cout << "\n" << Color::CYAN << "  [KERNEL EVENT RING BUFFER]" << Color::RESET << "\n";
        const auto& logs = device_->getKernelLogs();
        if (logs.empty()) {
            std::cout << "  No kernel events logged yet.\n";
        } else {
            for (const auto& log : logs) {
                std::cout << "  " << log << "\n";
            }
        }

        pausePrompt();
    }

    void handleEjectCard() {
        std::cout << "\n" << Color::BOLD << "--- EJECT CARD ---" << Color::RESET << "\n";
        if (!session_.isInserted()) {
            std::cout << Color::YELLOW << "No card is currently in the terminal.\n" << Color::RESET;
        } else {
            session_.ejectCard();
            authenticatedSession_ = false;
            device_->closeDevice();
            std::cout << Color::GREEN << "Card safely ejected. Session terminated.\n" << Color::RESET;
        }
        pausePrompt();
    }

    bool ensureAuthenticated() {
        if (!session_.isInserted()) {
            std::cout << Color::RED << "Error: No debit card inserted.\n" << Color::RESET;
            pausePrompt();
            return false;
        }
        if (!authenticatedSession_) {
            std::cout << Color::RED << "Access Denied: Please authenticate with your PIN first (Option 2).\n" << Color::RESET;
            pausePrompt();
            return false;
        }
        return true;
    }
};

} // namespace ATM

int main(int argc, char* argv[]) {
    std::string devicePath = "/dev/atm_auth";
    if (argc > 1) {
        devicePath = argv[1];
    }

    try {
        auto device = std::make_shared<ATM::ATMDevice>(devicePath);
        ATM::ATMController app(device);
        app.run();
    } catch (const std::exception& e) {
        std::cerr << ATM::Color::RED << "Fatal ATM System Error: " << e.what()
                  << ATM::Color::RESET << std::endl;
        return 1;
    }

    return 0;
}
