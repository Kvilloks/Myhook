#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <ctime>
#include <string>
#include <cctype>

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"winhttp.lib")

std::mutex g_LogMutex;

// --- Вспомогательные утилиты логирования ---
void LogWithTime(const std::string& text)
{
    std::lock_guard<std::mutex> lock(g_LogMutex);
    std::ofstream f("C:\\temp\\_netuniversal.log", std::ios::app | std::ios::binary);

    std::time_t now = std::time(nullptr);
    char timebuf[32]; timebuf[0]=0;
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    f << "[" << timebuf << "] [PID:" << pid << "/TID:" << tid << "] " << text << std::endl;
}

std::string HexDump(const char* data, int len, int maxLen = 256)
{
    std::ostringstream oss;
    int n = (len < maxLen) ? len : maxLen;
    for (int i = 0; i < n; ++i) {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        oss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)byte << ' ';
    }
    oss << " |";
    for (int i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        oss << (std::isprint(c) ? (char)c : '.');
    }
    oss << '|';
    if (len > maxLen) oss << " ...(" << len << " total)";
    return oss.str();
}

bool LooksLikeJson(const char* data, int len) {
    // Грубая эвристика
    int i = 0; while (i < len && std::isspace((unsigned char)data[i])) ++i;
    return i < len && (data[i] == '{' || data[i] == '[');
}

void LogApiCall(const char* api, const void* buf, int size, const char* note = nullptr)
{
    std::ostringstream oss;
    oss << "[API] " << api;
    if(note) oss << " [" << note << "]";
    oss << ", size=" << size << "\n";
    if(buf && size > 0) {
        if (LooksLikeJson((const char*)buf, size)) {
            oss << std::string((const char*)buf, size);
        } else {
            oss << HexDump((const char*)buf, size);
        }
    }
    LogWithTime(oss.str());
}

// ------------------ СЕТЕВЫЕ API -------------------
// typedef'ы для реальных функций (MinHook подцепит)
typedef int (WSAAPI* Send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI* Recv_t)(SOCKET, char*, int, int);
Send_t fpSend = nullptr;
Recv_t fpRecv = nullptr;

typedef BOOL (WINAPI* WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
WinHttpReadData_t fpWinHttpReadData = nullptr;
typedef BOOL (WINAPI* InternetReadFile_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
InternetReadFile_t fpInternetReadFile = nullptr;

// --- Хуки ---

int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    if (buf && len > 0)
        LogApiCall("send", buf, len, "WS2_32");
    return fpSend ? fpSend(s, buf, len, flags) : SOCKET_ERROR;
}

int WSAAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
    int n = fpRecv ? fpRecv(s, buf, len, flags) : SOCKET_ERROR;
    if (buf && n > 0)
        LogApiCall("recv", buf, n, "WS2_32");
    return n;
}

BOOL WINAPI MyWinHttpReadData(HINTERNET h, LPVOID buf, DWORD buflen, LPDWORD bytesRead)
{
    BOOL res = fpWinHttpReadData ? fpWinHttpReadData(h, buf, buflen, bytesRead) : FALSE;
    if(res && buf && bytesRead && *bytesRead)
        LogApiCall("WinHttpReadData", buf, *bytesRead, "WINHTTP");
    return res;
}

BOOL WINAPI MyInternetReadFile(HINTERNET h, LPVOID buf, DWORD buflen, LPDWORD bytesRead)
{
    BOOL res = fpInternetReadFile ? fpInternetReadFile(h, buf, buflen, bytesRead) : FALSE;
    if(res && buf && bytesRead && *bytesRead)
        LogApiCall("InternetReadFile", buf, *bytesRead, "WININET");
    return res;
}

// ----------- Инициализация хуков (пример для MinHook) -------------

void SetHooks()
{
    MH_Initialize();

    HMODULE hWs2     = GetModuleHandleA("ws2_32.dll");
    HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
    HMODULE hInet    = GetModuleHandleA("wininet.dll");

    if (hWs2) {
        void* pSend = GetProcAddress(hWs2, "send");
        void* pRecv = GetProcAddress(hWs2, "recv");
        if(pSend) MH_CreateHook(pSend, &MySend, reinterpret_cast<void**>(&fpSend));
        if(pRecv) MH_CreateHook(pRecv, &MyRecv, reinterpret_cast<void**>(&fpRecv));
    }
    if (hWinHttp) {
        void* pReadData = GetProcAddress(hWinHttp, "WinHttpReadData");
        if(pReadData) MH_CreateHook(pReadData, &MyWinHttpReadData, reinterpret_cast<void**>(&fpWinHttpReadData));
    }
    if (hInet) {
        void* pInetRead = GetProcAddress(hInet, "InternetReadFile");
        if(pInetRead) MH_CreateHook(pInetRead, &MyInternetReadFile, reinterpret_cast<void**>(&fpInternetReadFile));
    }
    MH_EnableHook(MH_ALL_HOOKS);
}

void RemoveHooks()


