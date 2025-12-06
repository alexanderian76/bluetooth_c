#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    running = 0;
}

void print_mac(const uint8_t *addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

int main() {
    signal(SIGINT, signal_handler);
    
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth adapter");
        return 1;
    }
    
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Can't open HCI socket");
        return 1;
    }
    
    printf("Bluetooth packet sniffer started on hci%d\n", dev_id);
    printf("Press Ctrl+C to stop\n\n");
    
    // Set filter to get all packets
    struct hci_filter flt;
      
    hci_filter_clear(&flt);
    
    // Разрешаем все типы пакетов кроме SCO
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_set_ptype(HCI_ACLDATA_PKT, &flt);
    hci_filter_set_ptype(HCI_COMMAND_PKT, &flt);
    
    // Разрешаем все события
    hci_filter_all_events(&flt);
    
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("Can't set filter");
        close(sock);
        return 1;
    }
    
    unsigned char buf[HCI_MAX_EVENT_SIZE];
    int packet_count = 0;
    
    while (running) {
        int len = read(sock, buf, sizeof(buf));
        if (len > 0) {
            packet_count++;
            printf("Packet %d: Type=0x%02X, Size=%d\n", 
                   packet_count, buf[0], len);
            
            // Basic packet type detection
            switch (buf[0]) {
                case HCI_EVENT_PKT:
                    printf("  HCI Event\n");
                    break;
                case HCI_ACLDATA_PKT:
                    printf("  ACL Data\n");
                    break;
                case HCI_SCODATA_PKT:
                    printf("  SCO Voice\n");
                    break;
                case HCI_COMMAND_PKT:
                    printf("  HCI Command\n");
                    break;
                default:
                    printf("  Unknown\n");
            }
        }
        usleep(10000); // 10ms delay
    }
    
    printf("\nTotal packets captured: %d\n", packet_count);
    close(sock);
    return 0;
}