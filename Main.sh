// === UNIVERSAL NETWORK HOOK ANALYZER ===
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <wininet.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <ctime>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

std::mutex g_LogMutex;

// --- Ключевые фильтры (можно редактировать) ---
std::vector<std::string> g_Keywords = {"paradox", "api", "login", "v3", ".top", "Infinity", "account"};

// --- Логирование ---
void LogWithTime(const std::string& text)
{
    std::lock_guard<std::mutex> lock(g_LogMutex);
    std::ofstream f("C:\\temp\\unihook.log", std::ios::app | std::ios::binary);
    if(!f) return;
    std::time_t now = std::time(nullptr);
    char timebuf[32];
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    f << "[" << timebuf << "] [PID:" << pid << "/TID:" << tid << "] " << text << std::endl;
}

std::string HexDump(const char* data, int len, int maxLen = 512)
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
        oss << (isprint(c) ? (char)c : '.');
    }
    oss << '|';
    if (len > maxLen) oss << " ...(" << len << " total)";
    return oss.str();
}

bool LooksLikeJson(const char* data, int len)
{
    for(int i = 0; i < len && i < 16; ++i)
        if(data[i] == '{' || data[i] == '[') return true;
    return false;
}

bool PassesFilter(const char* data, int len)
{
    if (g_Keywords.empty())
        return true;
    std::string buf(data, data + ((len > 4096) ? 4096 : len));
    std::transform(buf.begin(), buf.end(), buf.begin(), ::tolower);
    for (auto& kw : g_Keywords)
        if (buf.find(kw) != std::string::npos)
            return true;
    return false;
}

void LogApiCall(const char* api, const void* buf, int size, const char* note = nullptr)
{
    if (!buf || size <= 0) return;
    if (!PassesFilter((const char*)buf, size)) return;
    std::ostringstream oss;
    oss << "[API] " << api;
    if (note) oss << " [" << note << "]";
    oss << ", size=" << size << "\n";
    if (LooksLikeJson((const char*)buf, size))
        oss << "[JSON detected]\n" << std::string((const char*)buf, ((size > 4096) ? 4096 : size)) << "\n";
    else
        oss << HexDump((const char*)buf, size);
    LogWithTime(oss.str());
}

// --- Хуки для WinHTTP ---
typedef BOOL (WINAPI* WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
WinHttpReadData_t TrueWinHttpReadData = nullptr;
BOOL WINAPI MyWinHttpReadData(HINTERNET h, LPVOID buf, DWORD buflen, LPDWORD bytesRead)
{
    BOOL res = TrueWinHttpReadData ? TrueWinHttpReadData(h, buf, buflen, bytesRead) : FALSE;
    if(res && buf && bytesRead && *bytesRead)
        LogApiCall("WinHttpReadData", buf, *bytesRead, "HTTP RESPONSE");
    return res;
}

// --- Хуки для WinINet ---
typedef BOOL (WINAPI* InternetReadFile_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
InternetReadFile_t TrueInternetReadFile = nullptr;
BOOL WINAPI MyInternetReadFile(HINTERNET h, LPVOID buf, DWORD buflen, LPDWORD bytesRead)
{
    BOOL res = TrueInternetReadFile ? TrueInternetReadFile(h, buf, buflen, bytesRead) : FALSE;
    if(res && buf && bytesRead && *bytesRead)
        LogApiCall("InternetReadFile", buf, *bytesRead, "HTTP RESPONSE");
    return res;
}

// --- Сокет, RAW TCP ---
typedef int (WSAAPI* Send_t)(SOCKET, const char*, int, int);
Send_t TrueSend = nullptr;
int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    if(buf && len > 0)
        LogApiCall("send", buf, len, "SOCKET OUT");
    return TrueSend ? TrueSend(s, buf, len, flags) : SOCKET_ERROR;
}

typedef int (WSAAPI* Recv_t)(SOCKET, char*, int, int);
Recv_t TrueRecv = nullptr;
int WSAAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
    int ret = TrueRecv ? TrueRecv(s, buf, len, flags) : SOCKET_ERROR;
    if(ret > 0 && buf)
        LogApiCall("recv", buf, ret, "SOCKET IN");
    return ret;
}

// Пример установки хуков через MinHook — оставь реально инициализацию!
#include "MinHook.h" // включи MinHook

void SetupHooks()
{
    MH_Initialize();

    // WinHTTP
    HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryA("winhttp.dll");
    if (hWinHttp) {
        void* p = GetProcAddress(hWinHttp, "WinHttpReadData");
        if (p) MH_CreateHook(p, MyWinHttpReadData, (void**)&TrueWinHttpReadData);
    }

    // WinINet
    HMODULE hWinINet = GetModuleHandleA("wininet.dll");
    if (!hWinINet) hWinINet = LoadLibraryA("wininet.dll");
    if (hWinINet) {
        void* p = GetProcAddress(hWinINet, "InternetReadFile");
        if (p) MH_CreateHook(p, MyInternetReadFile, (void**)&TrueInternetReadFile);
    }

    // WS2_32
    HMODULE hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) hWS2 = LoadLibraryA("ws2_32.dll");
    if (hWS2) {
        void* p1 = GetProcAddress(hWS2, "send");
        void* p2 = GetProcAddress(hWS2, "recv");
        if (p1) MH_CreateHook(p1, MySend, (void**)&TrueSend);
        if (p2) MH_CreateHook(p2, MyRecv, (void**)&TrueRecv);
    }

    MH_EnableHook(MH_ALL_HOOKS);
}

// --- Удалить хуки ---
void RemoveHooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

// --- DllMain: запуск и снятие хуков ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if(reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        SetupHooks();
    } else if(reason == DLL_PROCESS_DETACH) {
        RemoveHooks();
    }
    return TRUE;
}
