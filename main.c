#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

int main(int argc, char **argv)
{
    inquiry_info *devices = NULL;
    int max_rsp, num_rsp;
    int dev_id, sock, len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    printf("=== Bluetooth Device Scanner ===\n");
    
    // Получаем ID первого доступного адаптера
    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth adapter found");
        return 1;
    }
    
    // Открываем сокет
    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Could not open socket");
        return 1;
    }
    
    printf("Adapter ID: %d\n", dev_id);
    printf("Starting discovery...\n");
    
    len = 8;          // Продолжительность сканирования в интервалах по 1.28 секунд
    max_rsp = 255;    // Максимальное количество устройств
    flags = IREQ_CACHE_FLUSH;
    devices = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
    
    // Выполняем сканирование
    num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &devices, flags);
    if (num_rsp < 0) {
        perror("Inquiry failed");
        close(sock);
        free(devices);
        return 1;
    }
    
    printf("\nFound %d devices:\n", num_rsp);
    
    // Выводим информацию об устройствах
    for (i = 0; i < num_rsp; i++) {
        ba2str(&(devices+i)->bdaddr, addr);
        memset(name, 0, sizeof(name));
        
        // Получаем имя устройства
        if (hci_read_remote_name(sock, &(devices+i)->bdaddr, sizeof(name), 
                                 name, 0) < 0) {
            strcpy(name, "[unknown]");
        }
        
        printf("%d. %s - %s\n", i+1, addr, name);
    }
    
    // Очистка
    free(devices);
    close(sock);
    
    return 0;
}