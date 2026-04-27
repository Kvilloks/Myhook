#include "pch.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "MinHook.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

std::mutex g_LogMutex;

// --- Типы функций ---
typedef int (WSAAPI* Send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI* Recv_t)(SOCKET, char*, int, int);
typedef int (WSAAPI* SendTo_t)(SOCKET, const char*, int, int, const sockaddr*, int);
typedef int (WSAAPI* RecvFrom_t)(SOCKET, char*, int, int, sockaddr*, int*);

// WinINet
typedef BOOL (WINAPI* HttpSendRequestA_t)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI* HttpSendRequestW_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI* InternetReadFile_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* InternetWriteFile_t)(HINTERNET, LPCVOID, DWORD, LPDWORD);

// WinHTTP
typedef BOOL (WINAPI* WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI* WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* WinHttpWriteData_t)(HINTERNET, LPCVOID, DWORD, LPDWORD);

// --- Оригиналы ---
Send_t fpSend = nullptr;
Recv_t fpRecv = nullptr;
SendTo_t fpSendTo = nullptr;
RecvFrom_t fpRecvFrom = nullptr;

HttpSendRequestA_t fpHttpSendRequestA = nullptr;
HttpSendRequestW_t fpHttpSendRequestW = nullptr;
InternetReadFile_t fpInternetReadFile = nullptr;
InternetWriteFile_t fpInternetWriteFile = nullptr;

WinHttpSendRequest_t fpWinHttpSendRequest = nullptr;
WinHttpReadData_t fpWinHttpReadData = nullptr;
WinHttpWriteData_t fpWinHttpWriteData = nullptr;

// --- Логирование ---
void Log(const std::string& text)
{
    std::lock_guard<std::mutex> lock(g_LogMutex);
    std::ofstream f("C:\\temp\\netlog.txt", std::ios::app);
    f << text << std::endl;
}

std::string HexDump(const char* data, int len, int maxLen = 128)
{
    std::ostringstream oss;
    int n = (len < maxLen) ? len : maxLen;
    for (int i = 0; i < n; ++i)
    {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        oss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)byte << ' ';
    }
    oss << " |";
    for (int i = 0; i < n; ++i)
    {
        unsigned char c = static_cast<unsigned char>(data[i]);
        oss << (isprint(c) ? (char)c : '.');
    }
    oss << '|';
    if (len > maxLen) oss << " ...";
    return oss.str();
}

// --- Сетки ---
int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    if (buf && len > 0)
        Log("[send] len=" + std::to_string(len) + " data=" + HexDump(buf, len));
    return fpSend ? fpSend(s, buf, len, flags) : SOCKET_ERROR;
}

int WSAAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
    int ret = fpRecv ? fpRecv(s, buf, len, flags) : SOCKET_ERROR;
    if (ret > 0 && buf)
        Log("[recv] len=" + std::to_string(ret) + " data=" + HexDump(buf, ret));
    return ret;
}

int WSAAPI MySendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (buf && len > 0)
        Log("[sendto] len=" + std::to_string(len) + " data=" + HexDump(buf, len));
    return fpSendTo ? fpSendTo(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
}

int WSAAPI MyRecvFrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    int ret = fpRecvFrom ? fpRecvFrom(s, buf, len, flags, from, fromlen) : SOCKET_ERROR;
    if (ret > 0 && buf)
        Log("[recvfrom] len=" + std::to_string(ret) + " data=" + HexDump(buf, ret));
    return ret;
}

// --- WinINet ---
BOOL WINAPI MyHttpSendRequestA(HINTERNET h, LPCSTR headers, DWORD headersLen, LPVOID optional, DWORD optionalLen)
{
    std::ostringstream oss;
    oss << "[HttpSendRequestA] Headers: ";
    if(headers && headersLen) 
        oss << std::string(headers, headersLen < 4096 ? headersLen : 4096);
    else if(headers) 
        oss << headers;
    if(optional && optionalLen > 0)
        oss << "\nBody: " << HexDump((const char*)optional, optionalLen);
    Log(oss.str());
    return fpHttpSendRequestA ? fpHttpSendRequestA(h, headers, headersLen, optional, optionalLen) : FALSE;
}

BOOL WINAPI MyHttpSendRequestW(HINTERNET h, LPCWSTR headers, DWORD headersLen, LPVOID optional, DWORD optionalLen)
{
    std::ostringstream oss;
    // преобразуем wchar_t* в std::string для логов
    if (headers && headersLen)
    {
        std::wstring ws(headers, headersLen / sizeof(wchar_t));
        std::string s(ws.begin(), ws.end());
        oss << "[HttpSendRequestW] Headers: " << s;
    }
    else if (headers)
    {
        std::wstring ws(headers);
        std::string s(ws.begin(), ws.end());
        oss << "[HttpSendRequestW] Headers: " << s;
    }
    if(optional && optionalLen > 0)
        oss << "\nBody: " << HexDump((const char*)optional, optionalLen);
    Log(oss.str());
    return fpHttpSendRequestW ? fpHttpSendRequestW(h, headers, headersLen, optional, optionalLen) : FALSE;
}

BOOL WINAPI MyInternetReadFile(HINTERNET h, LPVOID buf, DWORD len, LPDWORD read)
{
    BOOL res = fpInternetReadFile ? fpInternetReadFile(h, buf, len, read) : FALSE;
    if(res && read && *read > 0 && buf)
        Log("[InternetReadFile] " + HexDump((const char*)buf, *read));
    return res;
}

BOOL WINAPI MyInternetWriteFile(HINTERNET h, LPCVOID buf, DWORD len, LPDWORD written)
{
    if(buf && len > 0)
        Log("[InternetWriteFile] " + HexDump((const char*)buf, len));
    return fpInternetWriteFile ? fpInternetWriteFile(h, buf, len, written) : FALSE;
}

// --- WinHTTP ---
BOOL WINAPI MyWinHttpSendRequest(HINTERNET h, LPCWSTR hdrs, DWORD hdrsLen, LPVOID opt, DWORD optLen, DWORD totLen, DWORD_PTR ctx)
{
    std::ostringstream oss;
    if (hdrs && hdrsLen)
    {
        std::wstring ws(hdrs, hdrsLen / sizeof(wchar_t));
        std::string s(ws.begin(), ws.end());
        oss << "[WinHttpSendRequest] Headers: " << s;
    }
    else if (hdrs)
    {
        std::wstring ws(hdrs);
        std::string s(ws.begin(), ws.end());
        oss << "[WinHttpSendRequest] Headers: " << s;
    }
    if(opt && optLen > 0)
        oss << "\nBody: " << HexDump((const char*)opt, optLen);
    Log(oss.str());
    return fpWinHttpSendRequest ? fpWinHttpSendRequest(h, hdrs, hdrsLen, opt, optLen, totLen, ctx) : FALSE;
}

BOOL WINAPI MyWinHttpReadData(HINTERNET h, LPVOID buf, DWORD len, LPDWORD read)
{
    BOOL res = fpWinHttpReadData ? fpWinHttpReadData(h, buf, len, read) : FALSE;
    if(res && read && *read > 0 && buf)
        Log("[WinHttpReadData] " + HexDump((const char*)buf, *read));
    return res;
}

BOOL WINAPI MyWinHttpWriteData(HINTERNET h, LPCVOID buf, DWORD len, LPDWORD written)
{
    if(buf && len > 0)
        Log("[WinHttpWriteData] " + HexDump((const char*)buf, len));
    return fpWinHttpWriteData ? fpWinHttpWriteData(h, buf, len, written) : FALSE;
}

// --- Установка хуков ---
void SetHooks()
{
    if (MH_Initialize() != MH_OK) { Log("[error] MH_Initialize failed"); return; }

    HMODULE hWs2      = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) hWs2   = LoadLibraryA("ws2_32.dll");

    HMODULE hInet     = GetModuleHandleA("wininet.dll");
    if (!hInet) hInet = LoadLibraryA("wininet.dll");

    HMODULE hHttp     = GetModuleHandleA("winhttp.dll");
    if (!hHttp) hHttp = LoadLibraryA("winhttp.dll");

    // --- Сокеты ---
    void *pSend     = GetProcAddress(hWs2, "send");
    void *pRecv     = GetProcAddress(hWs2, "recv");
    void *pSendTo   = GetProcAddress(hWs2, "sendto");
    void *pRecvFrom = GetProcAddress(hWs2, "recvfrom");

    if (pSend   && MH_CreateHook(pSend,    &MySend,    reinterpret_cast<void**>(&fpSend))     != MH_OK) Log("[error] hook send failed");
    if (pRecv   && MH_CreateHook(pRecv,    &MyRecv,    reinterpret_cast<void**>(&fpRecv))     != MH_OK) Log("[error] hook recv failed");
    if (pSendTo && MH_CreateHook(pSendTo,  &MySendTo,  reinterpret_cast<void**>(&fpSendTo))   != MH_OK) Log("[error] hook sendto failed");
    if (pRecvFrom && MH_CreateHook(pRecvFrom, &MyRecvFrom, reinterpret_cast<void**>(&fpRecvFrom)) != MH_OK) Log("[error] hook recvfrom failed");

    // --- WinINet ---
    void *pHttpSendA  = GetProcAddress(hInet, "HttpSendRequestA");
    void *pHttpSendW  = GetProcAddress(hInet, "HttpSendRequestW");
    void *pInetRead   = GetProcAddress(hInet, "InternetReadFile");
    void *pInetWrite  = GetProcAddress(hInet, "InternetWriteFile");

    if (pHttpSendA && MH_CreateHook(pHttpSendA, &MyHttpSendRequestA, reinterpret_cast<void**>(&fpHttpSendRequestA)) != MH_OK) Log("[error] hook HttpSendRequestA failed");
    if (pHttpSendW && MH_CreateHook(pHttpSendW, &MyHttpSendRequestW, reinterpret_cast<void**>(&fpHttpSendRequestW)) != MH_OK) Log("[error] hook HttpSendRequestW failed");
    if (pInetRead  && MH_CreateHook(pInetRead,  &MyInternetReadFile,  reinterpret_cast<void**>(&fpInternetReadFile))  != MH_OK) Log("[error] hook InternetReadFile failed");
    if (pInetWrite && MH_CreateHook(pInetWrite, &MyInternetWriteFile, reinterpret_cast<void**>(&fpInternetWriteFile)) != MH_OK) Log("[error] hook InternetWriteFile failed");

    // --- WinHTTP ---
    void *pHttpSendReq  = GetProcAddress(hHttp, "WinHttpSendRequest");
    void *pHttpReadData = GetProcAddress(hHttp, "WinHttpReadData");
    void *pHttpWriteData= GetProcAddress(hHttp, "WinHttpWriteData");

    if (pHttpSendReq && MH_CreateHook(pHttpSendReq, &MyWinHttpSendRequest, reinterpret_cast<void**>(&fpWinHttpSendRequest)) != MH_OK) Log("[error] hook WinHttpSendRequest failed");
    if (pHttpReadData && MH_CreateHook(pHttpReadData, &MyWinHttpReadData, reinterpret_cast<void**>(&fpWinHttpReadData)) != MH_OK) Log("[error] hook WinHttpReadData failed");
    if (pHttpWriteData && MH_CreateHook(pHttpWriteData, &MyWinHttpWriteData, reinterpret_cast<void**>(&fpWinHttpWriteData)) != MH_OK) Log("[error] hook WinHttpWriteData failed");

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Log("[error] MH_EnableHook(MH_ALL_HOOKS) failed");
        MH_Uninitialize();
    }
}

void RemoveHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        SetHooks();
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        break;
    }
    return TRUE;
}
