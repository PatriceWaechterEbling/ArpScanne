// ArpScanne.cpp : Ce fichier contient la fonction 'main'.
// L'exécution du programme commence et se termine à cet endroit.
// basé sur une démo de microsoft
//© Patrice Waechter-Ebling 2022

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define HOST_NAME_MAX 0xFF

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma warning(disable: 4996)
#pragma warning(disable: 6328)
#pragma warning(disable: 6001)
#pragma warning(disable: 4477)
#pragma warning(disable: 6054)

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
int i;
unsigned int j;
unsigned long status = 0;
PMIB_IPNET_TABLE2 pipTable = NULL;
MIB_IPNET_ROW2 ipRow;

void AspectPowerShellConsole()
{
    char fill = (char)0x00;
    COORD tl = { 0,0 };
    CONSOLE_SCREEN_BUFFER_INFO s;
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(console, BACKGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED |FOREGROUND_BLUE| FOREGROUND_INTENSITY);
    GetConsoleScreenBufferInfo(console, &s);
    DWORD written, cells = s.dwSize.X * s.dwSize.Y;
    FillConsoleOutputCharacter(console, fill, cells, tl, &written);
    FillConsoleOutputAttribute(console, s.wAttributes, cells, tl, &written);
    SetConsoleCursorPosition(console, tl);
}
void PurgerTableARP() {
    status = GetIpNetTable2(AF_INET, &pipTable);
    if (status != NO_ERROR) {
        printf("IPv4 table a retourné %ld comme erreur\n", status);
        exit(1);
    }
    for (i = 0; (unsigned)i < pipTable->NumEntries; i++) {
        printf("\rLecture: %s ", inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr));
        FlushIpNetTable2(AF_UNSPEC,pipTable->Table->InterfaceIndex);
    }
    FreeMibTable(pipTable);
    pipTable = NULL;

}
void GetClasseIP(char* Segment) {
    char classes[5] = { 'A','B','C','D','E' };
    for (int x = 0; x < 5; x++) {
        if (Segment[x] == '.') {
            int pos = x;
            char dom[5];
            for (int y = 0; y < pos; y++) {
                dom[y] = Segment[y];
            }
            printf("Classe ");
            if (atoi(dom) < 128) { std::cout << classes[0]; }
            if ((Segment[0] == 1) && (Segment[1] == 0) && (Segment[3] == '.')) { std::cout << classes[1]; }
            if ((atoi(dom) >= 128) && (atoi(dom) < 224)) { std::cout << classes[2]; }
            if ((atoi(dom) >= 224) && (atoi(dom) < 244)) { std::cout << classes[3]; }
            if ((atoi(dom) >= 244) && (atoi(dom) < 254)) { std::cout << classes[4]; }
            std::cout << std::endl;
        }
    }
}
int scanneIPv4(char* argv)
{
    struct in_addr addr;
    WSADATA wsaData;
    DWORD dwError;
    int i = 0;
    struct hostent* remoteHost;
    char** pAlias;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { return -3; }
    if (isalpha(argv[0])) {
        printf("Test de %s: ", argv);
        remoteHost = gethostbyname(argv);
    }
    else {
        printf("Test de %s: ", argv);
        addr.s_addr = inet_addr(argv);
        if (addr.s_addr == INADDR_NONE)
        {
            printf("Format IPv4 ilegal!\n");
            return -2;
        }
        else
            remoteHost = gethostbyaddr((char*)&addr, 4, AF_INET);
        if (remoteHost == NULL) {
            dwError = WSAGetLastError();
            if (dwError != 0)
            {
                if (dwError == WSAHOST_NOT_FOUND)
                {
                    printf("Destinataire non trouve!\n");
                    return -6;
                }
                else if (dwError == WSANO_DATA)
                {
                    printf("Introuvable!\r");
                    return -5;
                }
                else
                {
                    printf("Erreur %ld\n", dwError);
                    return dwError;
                }
            }
        }
        else
        {
            printf("==> Poste: %s ", remoteHost->h_name);
            for (pAlias = remoteHost->h_aliases; *pAlias != 0; pAlias++)
            {
                printf("\tPseudo #%d: %s\t", ++i, *pAlias);
            }
            i = 0;
            while (remoteHost->h_addr_list[i] != 0) {
                addr.s_addr = *(u_long*)remoteHost->h_addr_list[i++];
                printf("[IP #%d][ %s ]", i, inet_ntoa(addr));
            }
            printf(" ");
            switch (remoteHost->h_addrtype)
            {
            case AF_INET:printf("IPv4"); break;
            case AF_INET6:printf("IPv6"); break;
            case AF_NETBIOS:printf("NetBios"); break;
            default:
                printf(" %d\n", remoteHost->h_addrtype);
                break;
            }
            printf(" %doctets ", remoteHost->h_length);
        }
        GetClasseIP(inet_ntoa(addr));
     }
    return 1;
}
void DecodeInfo() 
{
    switch (pipTable->Table[i].InterfaceLuid.Info.IfType) {
        case IF_TYPE_OTHER:printf("Inconnu "); break;
        case IF_TYPE_ETHERNET_CSMACD:printf("Ethernet "); break;
        case IF_TYPE_ISO88025_TOKENRING:printf("Token ring "); break;
        case IF_TYPE_PPP:printf("PPP "); break;
        case IF_TYPE_SOFTWARE_LOOPBACK:printf("Software loopback "); break;
        case IF_TYPE_ATM:printf("ATM "); break;
        case IF_TYPE_IEEE80211:printf("802.11 WiFi "); break;
        case IF_TYPE_TUNNEL:printf("Tunnel ");break;
        case IF_TYPE_IEEE1394:printf("IEEE 1394 (Firewire) ");break;
        default:
            printf("Unknown: %ld\n",
                pipTable->Table[i].InterfaceLuid.Info.IfType);
            break;
    }
        if (pipTable->Table[i].PhysicalAddressLength == 0)printf("\n");
        for (j = 0; j < pipTable->Table[i].PhysicalAddressLength; j++) {
            if (j == (pipTable->Table[i].PhysicalAddressLength - 1))
                printf("%.2X", (int)pipTable->Table[i].PhysicalAddress[j]);
            else
                printf("%.2X-", (int)pipTable->Table[i].PhysicalAddress[j]);
        }
        printf("\n%lu octets ", pipTable->Table[i].PhysicalAddressLength);
        scanneIPv4(inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr));

}
int main()
{
    AspectPowerShellConsole();
    SetConsoleTitleA("Explorateur reseau LAN v0.2");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), BACKGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("Explorateur reseau LAN v0.2\n%c Patrice Waechter-Ebling 2022\n", 0xb8);
    PurgerTableARP();
    status = GetIpNetTable2(AF_INET, &pipTable);
    if (status != NO_ERROR) {
        printf("IPv4 table a retourné %ld comme erreur\n", status);
        exit(1);
    }
    printf("Il y a %d entrées dans la table IPv4.\n\n", pipTable->NumEntries);

    for (i = 0; (unsigned)i < pipTable->NumEntries; i++) {
        printf("IPv4 %s ", inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr));
        switch (pipTable->Table[i].State) {
        case NlnsStale:{printf("Dynamique ");DecodeInfo();}break;
        case NlnsReachable: {printf("En Ligne ");DecodeInfo();}break;
        case NlnsPermanent:{printf("Statique ");DecodeInfo();}break;
        default:
            printf("\r");break;
        }
    }
    FreeMibTable(pipTable);
    pipTable = NULL;
    exit(0);
}