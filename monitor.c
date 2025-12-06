#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

// Структура для отслеживания соединений
typedef struct {
    uint16_t handle;
    uint8_t bdaddr[6];
    unsigned long packets;
    unsigned long bytes;
    time_t last_seen;
    char type;  // 'A' = ACL, 'S' = SCO, 'E' = eSCO
} connection_t;

// Статистика
typedef struct {
    unsigned long total_packets;
    unsigned long hci_events;
    unsigned long acl_packets;
    unsigned long sco_packets;
    unsigned long esco_packets;
    unsigned long cmd_packets;
    unsigned long adv_packets;
    unsigned long conn_packets;
    unsigned long data_bytes;
    connection_t connections[256];
    int conn_count;
} traffic_stats_t;

volatile sig_atomic_t running = 1;
traffic_stats_t stats = {0};

void signal_handler(int sig) {
    printf("\nОстановка мониторинга...\n");
    running = 0;
}

// Функции для работы с соединениями
connection_t* find_connection(uint16_t handle) {
    for (int i = 0; i < stats.conn_count; i++) {
        if (stats.connections[i].handle == handle) {
            return &stats.connections[i];
        }
    }
    return NULL;
}

connection_t* add_connection(uint16_t handle, const uint8_t *bdaddr, char type) {
    if (stats.conn_count >= 256) return NULL;
    
    connection_t *conn = &stats.connections[stats.conn_count];
    conn->handle = handle;
    memcpy(conn->bdaddr, bdaddr, 6);
    conn->packets = 0;
    conn->bytes = 0;
    conn->last_seen = time(NULL);
    conn->type = type;
    
    stats.conn_count++;
    return conn;
}

void update_connection(uint16_t handle, size_t bytes) {
    connection_t *conn = find_connection(handle);
    if (conn) {
        conn->packets++;
        conn->bytes += bytes;
        conn->last_seen = time(NULL);
    }
}

void print_mac(const uint8_t *addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

void print_stats() {
    printf("\n=== Bluetooth Traffic Statistics ===\n");
    printf("Всего пакетов: %lu\n", stats.total_packets);
    printf("  HCI Events:      %lu\n", stats.hci_events);
    printf("  ACL Data:        %lu\n", stats.acl_packets);
    printf("  SCO Voice:       %lu\n", stats.sco_packets);
    printf("  eSCO Voice:      %lu\n", stats.esco_packets);
    printf("  HCI Commands:    %lu\n", stats.cmd_packets);
    printf("  Advertising:     %lu\n", stats.adv_packets);
    printf("  Connection:      %lu\n", stats.conn_packets);
    printf("Всего байт данных: %lu\n", stats.data_bytes);
    
    if (stats.conn_count > 0) {
        printf("\n=== Активные соединения ===\n");
        for (int i = 0; i < stats.conn_count; i++) {
            connection_t *conn = &stats.connections[i];
            printf("  Handle: 0x%04X, Type: %c, ", conn->handle, conn->type);
            printf("MAC: ");
            print_mac(conn->bdaddr);
            printf(", Packets: %lu, Bytes: %lu\n",
                   conn->packets, conn->bytes);
        }
    }
    printf("===================================\n");
}

void analyze_packet(const uint8_t *packet, size_t len) {
    if (len < 1) return;
    
    uint8_t pkt_type = packet[0];
    stats.total_packets++;
    
    switch (pkt_type) {
        case HCI_EVENT_PKT:
            stats.hci_events++;
            if (len > 1) {
                uint8_t event = packet[1];
                
                // Обработка событий соединения
                if (event == 0x03) { // Connection Complete
                    if (len >= 11) {
                        uint16_t handle = (packet[3] << 8) | packet[2];
                        uint8_t link_type = packet[10];
                        char conn_type = 'U';
                        
                        if (link_type == 0x01) conn_type = 'A'; // ACL
                        else if (link_type == 0x02) conn_type = 'S'; // SCO
                        else if (link_type == 0x03) conn_type = 'E'; // eSCO
                        
                        add_connection(handle, packet + 4, conn_type);
                        stats.conn_packets++;
                        
                        printf("[CONNECT] Handle: 0x%04X, Type: %c, MAC: ",
                               handle, conn_type);
                        print_mac(packet + 4);
                        printf("\n");
                    }
                }
                else if (event == 0x05) { // Disconnection Complete
                    if (len >= 4) {
                        uint16_t handle = (packet[3] << 8) | packet[2];
                        printf("[DISCONNECT] Handle: 0x%04X, Reason: 0x%02X\n",
                               handle, packet[4]);
                    }
                }
                else if (event == 0x3E) { // LE Meta Event
                    if (len > 2 && packet[2] == 0x02) { // LE Advertising Report
                        stats.adv_packets++;
                    }
                }
            }
            break;
            
        case HCI_ACLDATA_PKT:
            stats.acl_packets++;
            if (len >= 4) {
                uint16_t handle = (packet[2] << 8) | packet[1];
                uint16_t length = (packet[4] << 8) | packet[3];
                stats.data_bytes += length;
                update_connection(handle & 0x0FFF, length);
                
                // Вывод информации о больших пакетах данных (например, аудио)
                if (length > 100) {
                    printf("[ACL_DATA] Handle: 0x%04X, Size: %d bytes\n",
                           handle & 0x0FFF, length);
                }
            }
            break;
            
        case HCI_SCODATA_PKT:
            stats.sco_packets++;
            if (len >= 3) {
                uint16_t handle = packet[1] & 0x0FFF;
                uint8_t length = packet[2];
                stats.data_bytes += length;
                update_connection(handle, length);
                
                // Голосовые пакеты (обычно 20-60 байт)
                printf("[SCO_VOICE] Handle: 0x%04X, Size: %d bytes\n",
                       handle, length);
            }
            break;
            
        case HCI_COMMAND_PKT:
            stats.cmd_packets++;
            break;
            
        default:
            // eSCO пакеты могут иметь разные идентификаторы
            if (pkt_type == 0x08 || pkt_type == 0x09 || 
                pkt_type == 0x0A || pkt_type == 0x0B) {
                stats.esco_packets++;
                if (len >= 3) {
                    uint16_t handle = packet[1] & 0x0FFF;
                    uint8_t length = packet[2];
                    stats.data_bytes += length;
                    update_connection(handle, length);
                    
                    printf("[ESCO_VOICE] Type: 0x%02X, Handle: 0x%04X, Size: %d bytes\n",
                           pkt_type, handle, length);
                }
            }
    }
}

void enable_le_scan(int sock) {
    // Включаем LE сканирование для захвата Advertising пакетов
    struct hci_request rq;
    le_set_scan_enable_cp scan_cp;
    uint8_t status;
    
    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = 0x01;
    scan_cp.filter_dup = 0x00;
    
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_ENABLE;
    rq.cparam = &scan_cp;
    rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;
    
    if (hci_send_req(sock, &rq, 1000) < 0) {
        printf("Внимание: LE сканирование недоступно (может быть уже включено)\n");
    } else {
        printf("LE сканирование включено\n");
    }
}

// Альтернативная функция для включения классического сканирования
void enable_inquiry_scan(int sock) {
    // Используем Inquiry команду для поиска устройств
    printf("Запуск поиска классических Bluetooth устройств...\n");
    
    inquiry_info *ii = NULL;
    int max_rsp = 255;
    int num_rsp;
    int flags = IREQ_CACHE_FLUSH;
    char addr[19] = {0};
    
    ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
    if (!ii) {
        perror("Ошибка выделения памяти");
        return;
    }
    
    num_rsp = hci_inquiry(hci_get_route(NULL), 5, max_rsp, NULL, &ii, flags);
    if (num_rsp < 0) {
        perror("Ошибка поиска устройств");
    } else {
        printf("Найдено классических устройств: %d\n", num_rsp);
        for (int i = 0; i < num_rsp; i++) {
            ba2str(&ii[i].bdaddr, addr);
            printf("  %d. %s\n", i+1, addr);
        }
    }
    
    free(ii);
}

int main() {
    signal(SIGINT, signal_handler);
    
    printf("=== Bluetooth Traffic Monitor ===\n");
    printf("Отслеживание всех типов Bluetooth трафика\n");
    printf("Включая ACL, SCO, eSCO и Advertising пакеты\n");
    printf("Нажмите Ctrl+C для остановки\n\n");
    
    // Находим Bluetooth адаптер
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        fprintf(stderr, "Ошибка: Bluetooth адаптер не найден\n");
        return 1;
    }
    
    // Получаем информацию об адаптере
    struct hci_dev_info di;
    if (hci_devinfo(dev_id, &di) < 0) {
        perror("Ошибка получения информации об адаптере");
        return 1;
    }
    
    printf("Адаптер: hci%d (%s)\n", dev_id, di.name);
    printf("MAC: ");
    print_mac(di.bdaddr.b);
    printf("\nПоддержка: ");
    
    // Проверяем возможности адаптера
    if (di.features[0] & 0x80) printf("3-х slot ");
    if (di.features[0] & 0x40) printf("5-х slot ");
    if (di.features[4] & 0x08) printf("eSCO ");
    if (di.features[4] & 0x80) printf("AFH ");
    printf("\n\n");
    
    // Открываем сокет
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Ошибка открытия сокета HCI");
        return 1;
    }
    
    // Включаем различные режимы сканирования
    enable_le_scan(sock);
    enable_inquiry_scan(sock);
    
    // Настраиваем фильтр для захвата ВСЕХ пакетов
    struct hci_filter flt;
    hci_filter_clear(&flt);
    
    // Разрешаем ВСЕ типы пакетов
    flt.type_mask |= (1 << HCI_EVENT_PKT) |
                     (1 << HCI_ACLDATA_PKT) |
                     (1 << HCI_SCODATA_PKT) |
                     (1 << HCI_COMMAND_PKT);
    
    // Разрешаем ВСЕ события
    memset(flt.event_mask, 0xFF, sizeof(flt.event_mask));
    
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("Ошибка установки фильтра");
        close(sock);
        return 1;
    }
    
    // Устанавливаем неблокирующий режим
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Буфер для пакетов
    unsigned char buf[HCI_MAX_EVENT_SIZE];
    
    printf("Начало мониторинга трафика...\n");
    printf("Сейчас можете подключить устройство и передавать данные\n");
    printf("(музыка, файлы и т.д.)\n\n");
    
    time_t last_stats_update = time(NULL);
    time_t start_time = time(NULL);
    
    // Главный цикл мониторинга
    while (running) {
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("Ошибка select");
            break;
        }
        
        if (ret > 0 && FD_ISSET(sock, &readfds)) {
            int len = read(sock, buf, sizeof(buf));
            
            if (len > 0) {
                analyze_packet(buf, len);
                
                // Обновляем статистику каждые 5 секунд
                time_t now = time(NULL);
                if (now - last_stats_update >= 5) {
                    printf("\n");
                    print_stats();
                    printf("\nМониторинг продолжается... (Ctrl+C для остановки)\n");
                    last_stats_update = now;
                }
            }
        }
        
        // Небольшая пауза
        usleep(1000);
    }
    
    // Закрываем сокет
    close(sock);
    
    // Выводим итоговую статистику
    time_t end_time = time(NULL);
    printf("\n\n=== Итоговая статистика ===\n");
    printf("Время работы: %ld секунд\n", end_time - start_time);
    print_stats();
    
    // Расчет скорости
    if (end_time - start_time > 0) {
        float bytes_per_sec = (float)stats.data_bytes / (end_time - start_time);
        float packets_per_sec = (float)stats.total_packets / (end_time - start_time);
        
        printf("\nСредняя скорость:\n");
        printf("  Данные: %.2f байт/сек (%.2f КБ/сек)\n", 
               bytes_per_sec, bytes_per_sec / 1024);
        printf("  Пакеты: %.2f пакетов/сек\n", packets_per_sec);
    }
    
    return 0;
}