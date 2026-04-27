#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "MinHook.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// Mutex для потокобезопасности лога
std::mutex g_LogMutex;

typedef int (WSAAPI* Send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* Recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* SendTo_t)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
typedef int (WSAAPI* RecvFrom_t)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

Send_t      fpSend     = nullptr;
Recv_t      fpRecv     = nullptr;
SendTo_t    fpSendTo   = nullptr;
RecvFrom_t  fpRecvFrom = nullptr;

void Log(const std::string& text)
{
    std::lock_guard<std::mutex> lock(g_LogMutex);
    std::ofstream f("C:\\temp\\netlog.txt", std::ios::app);
    f << text << std::endl;
}

std::string HexDump(const char* data, int len, int maxLen = 64)
{
    std::ostringstream oss;
    int n = (len < maxLen) ? len : maxLen;
    for (int i = 0; i < n; i++)
    {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (unsigned int)byte << ' ';
    }
    // ASCII-представление
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

// TCP
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

// UDP
int WSAAPI MySendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    if (buf && len > 0)
        Log("[sendto] len=" + std::to_string(len) + " data=" + HexDump(buf, len));
    return fpSendTo ? fpSendTo(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
}

int WSAAPI MyRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int ret = fpRecvFrom ? fpRecvFrom(s, buf, len, flags, from, fromlen) : SOCKET_ERROR;
    if (ret > 0 && buf)
        Log("[recvfrom] len=" + std::to_string(ret) + " data=" + HexDump(buf, ret));
    return ret;
}

void SetHooks()
{
    if (MH_Initialize() != MH_OK)
    {
        Log("[error] MH_Initialize failed");
        return;
    }

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2)
        hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2)
    {
        Log("[error] LoadLibrary(ws2_32.dll) failed");
        return;
    }

    // send / recv
    void* pSend     = GetProcAddress(hWs2, "send");
    void* pRecv     = GetProcAddress(hWs2, "recv");
    void* pSendTo   = GetProcAddress(hWs2, "sendto");
    void* pRecvFrom = GetProcAddress(hWs2, "recvfrom");

    if (pSend)    { if (MH_CreateHook(pSend,    &MySend,    reinterpret_cast<void**>(&fpSend))    != MH_OK) Log("[error] MH_CreateHook(send) failed"); }
    else Log("[error] GetProcAddress(send) failed");
    if (pRecv)    { if (MH_CreateHook(pRecv,    &MyRecv,    reinterpret_cast<void**>(&fpRecv))    != MH_OK) Log("[error] MH_CreateHook(recv) failed"); }
    else Log("[error] GetProcAddress(recv) failed");

    if (pSendTo)  { if (MH_CreateHook(pSendTo,  &MySendTo,  reinterpret_cast<void**>(&fpSendTo))  != MH_OK) Log("[error] MH_CreateHook(sendto) failed"); }
    else Log("[error] GetProcAddress(sendto) failed");
    if (pRecvFrom){ if (MH_CreateHook(pRecvFrom,&MyRecvFrom,reinterpret_cast<void**>(&fpRecvFrom))!= MH_OK) Log("[error] MH_CreateHook(recvfrom) failed"); }
    else Log("[error] GetProcAddress(recvfrom) failed");

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
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
