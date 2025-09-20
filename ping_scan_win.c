// ping_scan_win.c
// Descobre IPs ativos via ICMP (ping) no Windows
// Compilar (Visual Studio):
// cl ping_scan_win.c /link Iphlpapi.lib
// Para Compilar (MinGW):
// gcc -o ping_scan_win.exe ping_scan_win.c -lIphlpapi -lws2_32

#include <windows.h>   // Tipos e funções do Windows (HANDLE, DWORD)
#include <stdio.h>     // Entrada/saída padrão (printf, fprintf)
#include <stdlib.h>    // Funções gerais (malloc, free, atoi)
#include <string.h>    // Manipulação de strings (strlen, snprintf)
#include <iphlpapi.h>  // API de rede do Windows
#include <icmpapi.h>   // Funções para ICMP (ping)
#include <ws2tcpip.h>  // Funções de IP (InetPtonA)

#pragma comment(lib, "Iphlpapi.lib")  // Biblioteca necessária para ICMP
#pragma comment(lib, "Ws2_32.lib")    // Biblioteca para rede Windows

int main(int argc, char **argv) {

    // Verifica se o usuário forneceu os argumentos corretos
    if (argc < 4) {
        printf("Uso: %s BASE START END\n", argv[0]);
        printf("Exemplo: %s 192.168.1 1 254\n", argv[0]);
        return 1;
    }

    // Captura os argumentos
    const char *base = argv[1];       // Base do IP, ex: "192.168.1"
    int start = atoi(argv[2]);        // Número inicial da faixa
    int end   = atoi(argv[3]);        // Número final da faixa

    // Ajusta limites válidos
    if (start < 1) start = 1;
    if (end > 254) end = 254;

    // Cria um handle ICMP para enviar pacotes ping
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Erro ao criar handle ICMP\n");
        return 1;
    }

    // Dados que serão enviados no pacote ICMP
    char sendData[32] = "ping_scan_win";

    // Calcula o tamanho do buffer de resposta (estrutura + dados)
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData);

    // Aloca memória para receber a resposta do ping
    void *replyBuffer = malloc(replySize);
    if (!replyBuffer) {
        fprintf(stderr, "Erro de memoria\n");
        IcmpCloseHandle(hIcmp);  // Fecha o handle ICMP antes de sair
        return 1;
    }

    // Informar ao usuário o início do scan
    printf("Escaneando %s.%d..%d\n", base, start, end);

    // Loop para testar todos os IPs da faixa
    for (int i = start; i <= end; i++) {
        char ip[64];

        // Monta o IP completo (ex: 192.168.1.1)
        snprintf(ip, sizeof(ip), "%s.%d", base, i);

        // Converte IP string para o formato binário usado pela API
        struct in_addr destAddr;
        if (InetPtonA(AF_INET, ip, &destAddr) != 1) {
            fprintf(stderr, "IP invalido: %s\n", ip);
            continue; // pula para o próximo IP se inválido
        }

        // Envia o ping ICMP
        DWORD ret = IcmpSendEcho(
            hIcmp,                      // Handle ICMP
            destAddr.S_un.S_addr,        // Endereço IP destino
            sendData,                    // Dados enviados
            (WORD)strlen(sendData),      // Tamanho dos dados
            NULL,                        // Nenhuma opção extra
            replyBuffer,                 // Buffer de resposta
            replySize,                   // Tamanho do buffer
            1000                         // Timeout em ms (1 segundo)
        );

        // Se a função retornar > 0, pelo menos uma resposta foi recebida
        if (ret > 0) {
            // Converte buffer genérico em estrutura de resposta ICMP
            PICMP_ECHO_REPLY pReply = (PICMP_ECHO_REPLY)replyBuffer;

            // Se Status == 0, significa que o host respondeu corretamente
            if (pReply->Status == 0) {
                // Exibe no terminal o host ativo e o tempo de resposta
                printf("[+] Host ativo: %s (tempo %dms)\n", ip, pReply->RoundTripTime);
            }
        }
    }

    // Libera memória do buffer de resposta
    free(replyBuffer);

    // Fecha o handle ICMP, liberando recursos do Windows
    IcmpCloseHandle(hIcmp);

    return 0;
}
// Fim do arquivo ping_scan_win.c