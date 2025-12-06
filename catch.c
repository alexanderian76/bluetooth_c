#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

// Константы для Bluetooth
#define BT_ADDR_STR_LEN 18
#define MAX_NAME_LEN 248

// Статистика
typedef struct {
    unsigned long total_packets;
    unsigned long hci_events;
    unsigned long acl_packets;
    unsigned long sco_packets;
    unsigned long cmd_packets;
    unsigned long adv_packets;
    unsigned long conn_packets;
    unsigned long unknown_packets;
} packet_stats_t;

volatile sig_atomic_t running = 1;
packet_stats_t stats = {0};

// Обработчик сигналов
void signal_handler(int sig) {
    printf("\nЗавершение работы...\n");
    running = 0;
}

// Форматированный вывод MAC адреса
void print_mac_address(const uint8_t *addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

// HEX дамп данных
void hex_dump(const uint8_t *data, size_t length, int indent) {
    char indent_str[32];
    memset(indent_str, ' ', indent);
    indent_str[indent] = '\0';
    
    for (size_t i = 0; i < length; i += 16) {
        printf("%s", indent_str);
        // HEX часть
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }
        
        printf(" ");
        
        // ASCII часть
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                unsigned char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            } else {
                printf(" ");
            }
            if (j == 7) printf(" ");
        }
        printf("\n");
    }
}

// Расшифровка типов Advertising данных
void decode_ad_data(uint8_t type, const uint8_t *data, uint8_t len) {
    switch (type) {
        case 0x01: // Flags
            printf("Flags: ");
            if (len >= 1) {
                uint8_t flags = data[0];
                printf("(0x%02X) ", flags);
                if (flags & 0x01) printf("LE Limited Discoverable ");
                if (flags & 0x02) printf("LE General Discoverable ");
                if (flags & 0x04) printf("BR/EDR Not Supported ");
                if (flags & 0x08) printf("Simultaneous LE and BR/EDR ");
                if (flags & 0x10) printf("Reserved ");
            }
            break;
            
        case 0x02: // Incomplete List of 16-bit UUIDs
            printf("Incomplete 16-bit UUIDs: ");
            for (int i = 0; i < len; i += 2) {
                if (i + 1 < len) {
                    printf("%04X ", (data[i+1] << 8) | data[i]);
                }
            }
            break;
            
        case 0x03: // Complete List of 16-bit UUIDs
            printf("Complete 16-bit UUIDs: ");
            for (int i = 0; i < len; i += 2) {
                if (i + 1 < len) {
                    printf("%04X ", (data[i+1] << 8) | data[i]);
                }
            }
            break;
            
        case 0x08: // Shortened Local Name
            printf("Short Name: \"");
            for (int i = 0; i < len; i++) {
                printf("%c", isprint(data[i]) ? data[i] : '.');
            }
            printf("\"");
            break;
            
        case 0x09: // Complete Local Name
            printf("Complete Name: \"");
            for (int i = 0; i < len; i++) {
                printf("%c", isprint(data[i]) ? data[i] : '.');
            }
            printf("\"");
            break;
            
        case 0x0A: // TX Power Level
            if (len >= 1) {
                int8_t power = (int8_t)data[0];
                printf("TX Power: %d dBm", power);
            }
            break;
            
        case 0x0D: // Class of Device
            if (len >= 3) {
                uint32_t cod = (data[2] << 16) | (data[1] << 8) | data[0];
                printf("Class of Device: 0x%06X", cod);
                
                // Основные классы устройств
                uint8_t major_class = (cod >> 8) & 0x1F;
                printf(" (");
                switch (major_class) {
                    case 0x00: printf("Miscellaneous"); break;
                    case 0x01: printf("Computer"); break;
                    case 0x02: printf("Phone"); break;
                    case 0x03: printf("LAN/Network"); break;
                    case 0x04: printf("Audio/Video"); break;
                    case 0x05: printf("Peripheral"); break;
                    case 0x06: printf("Imaging"); break;
                    case 0x1F: printf("Uncategorized"); break;
                    default: printf("Unknown class");
                }
                printf(")");
            }
            break;
            
        case 0x0E: // Simple Pairing Hash C
            printf("Simple Pairing Hash C: ");
            for (int i = 0; i < len; i++) {
                printf("%02X", data[i]);
            }
            break;
            
        case 0x0F: // Simple Pairing Randomizer R
            printf("Simple Pairing Randomizer R: ");
            for (int i = 0; i < len; i++) {
                printf("%02X", data[i]);
            }
            break;
            
        case 0x10: // Device ID
            printf("Device ID: ");
            for (int i = 0; i < len; i++) {
                printf("%02X", data[i]);
            }
            break;
            
        case 0x16: // 16-bit UUID Service Data
            if (len >= 2) {
                uint16_t uuid = (data[1] << 8) | data[0];
                printf("16-bit UUID Service Data: UUID=%04X, Data: ", uuid);
                for (int i = 2; i < len; i++) {
                    printf("%02X ", data[i]);
                }
            }
            break;
            
        case 0xFF: // Manufacturer Specific Data
            if (len >= 2) {
                uint16_t company_id = (data[1] << 8) | data[0];
                printf("Manufacturer Data: Company=0x%04X (%s), Data: ",
                       company_id,
                       company_id == 0x004C ? "Apple" :
                       company_id == 0x0006 ? "Microsoft" :
                       company_id == 0x000D ? "Texas Instruments" :
                       company_id == 0x000F ? "Broadcom" : "Unknown");
                for (int i = 2; i < len; i++) {
                    printf("%02X ", data[i]);
                }
            }
            break;
            
        default:
            printf("Type 0x%02X: ", type);
            for (int i = 0; i < len; i++) {
                printf("%02X ", data[i]);
            }
    }
}

// Анализ Advertising данных
void analyze_advertising_data(const uint8_t *data, size_t length) {
    size_t offset = 0;
    int field_num = 1;
    
    while (offset < length) {
        uint8_t field_len = data[offset];
        
        if (field_len == 0 || offset + field_len >= length) {
            break;
        }
        
        if (field_len < 1) {
            offset++;
            continue;
        }
        
        uint8_t field_type = data[offset + 1];
        
        printf("        Field %d: ", field_num++);
        decode_ad_data(field_type, data + offset + 2, field_len - 1);
        printf("\n");
        
        offset += field_len + 1;
    }
}

// Анализ HCI Event пакетов
void analyze_hci_event(const uint8_t *data, size_t length) {
    if (length < 2) return;
    
    uint8_t event_code = data[0];
    uint8_t param_len = data[1];
    
    printf("        Event Code: 0x%02X - ", event_code);
    
    // Расшифровка типов событий
    switch (event_code) {
        case 0x01: // Inquiry Complete
            stats.conn_packets++;
            printf("Inquiry Complete\n");
            break;
            
        case 0x02: // Inquiry Result
            stats.conn_packets++;
            printf("Inquiry Result\n");
            if (param_len >= 1) {
                uint8_t num_responses = data[2];
                printf("          Responses: %d\n", num_responses);
                
                const uint8_t *ptr = data + 3;
                for (int i = 0; i < num_responses; i++) {
                    if (ptr + 6 <= data + length) {
                        printf("          Device %d: MAC: ", i + 1);
                        print_mac_address(ptr);
                        printf(", Page Scan Mode: 0x%02X, "
                               "Class: 0x%02X%02X%02X, Clock offset: 0x%04X\n",
                               ptr[6],
                               ptr[9], ptr[8], ptr[7],
                               (ptr[11] << 8) | ptr[10]);
                        ptr += 14;
                    }
                }
            }
            break;
            
        case 0x03: // Connection Complete
            stats.conn_packets++;
            printf("Connection Complete\n");
            if (param_len >= 11) {
                printf("          Handle: 0x%04X, "
                       "MAC: ", (data[3] << 8) | data[2]);
                print_mac_address(data + 4);
                printf("\n          Link Type: %s, "
                       "Encryption: %s\n",
                       data[10] == 0x01 ? "ACL" : 
                       data[10] == 0x02 ? "SCO" : "eSCO",
                       data[11] == 0x01 ? "Enabled" : "Disabled");
            }
            break;
            
        case 0x04: // Connection Request
            stats.conn_packets++;
            printf("Connection Request\n");
            if (param_len >= 10) {
                printf("          MAC: ");
                print_mac_address(data + 2);
                printf(", Class: 0x%02X%02X%02X, "
                       "Link Type: %s\n",
                       data[9], data[8], data[7],
                       data[10] == 0x01 ? "ACL" : "SCO");
            }
            break;
            
        case 0x05: // Disconnection Complete
            stats.conn_packets++;
            printf("Disconnection Complete\n");
            if (param_len >= 4) {
                printf("          Handle: 0x%04X, Reason: 0x%02X\n",
                       (data[3] << 8) | data[2], data[4]);
            }
            break;
            
        case 0x0E: // Command Complete
            printf("Command Complete\n");
            if (param_len >= 3) {
                uint16_t opcode = (data[4] << 8) | data[3];
                printf("          OpCode: 0x%04X (OGF: 0x%02X, OCF: 0x%03X), "
                       "Status: 0x%02X\n",
                       opcode, opcode >> 10, opcode & 0x03FF, data[5]);
            }
            break;
            
        case 0x0F: // Command Status
            printf("Command Status\n");
            if (param_len >= 4) {
                uint16_t opcode = (data[5] << 8) | data[4];
                printf("          OpCode: 0x%04X, Status: 0x%02X\n",
                       opcode, data[3]);
            }
            break;
            
        case 0x13: // Number of Completed Packets
            printf("Number of Completed Packets\n");
            break;
            
        case 0x3E: // LE Meta Event
            printf("LE Meta Event\n");
            if (param_len >= 1) {
                uint8_t subevent = data[2];
                printf("          Subevent: 0x%02X - ", subevent);
                
                switch (subevent) {
                    case 0x01: // LE Connection Complete
                        stats.conn_packets++;
                        printf("LE Connection Complete\n");
                        if (param_len >= 17) {
                            printf("            Handle: 0x%04X, Role: %s\n",
                                   (data[4] << 8) | data[3],
                                   data[5] == 0x00 ? "Master" : "Slave");
                            printf("            Peer MAC: ");
                            print_mac_address(data + 6);
                            printf("\n            Interval: %d ms, "
                                   "Latency: %d, Timeout: %d ms\n",
                                   ((data[14] << 8) | data[13]) * 1.25,
                                   (data[16] << 8) | data[15],
                                   ((data[18] << 8) | data[17]) * 10);
                        }
                        break;
                        
                    case 0x02: // LE Advertising Report
                        stats.adv_packets++;
                        printf("LE Advertising Report\n");
                        if (param_len >= 2) {
                            uint8_t num_reports = data[3];
                            printf("            Reports: %d\n", num_reports);
                            
                            const uint8_t *ptr = data + 4;
                            for (int i = 0; i < num_reports; i++) {
                                if (ptr + 9 <= data + length) {
                                    uint8_t event_type = ptr[0];
                                    uint8_t addr_type = ptr[1];
                                    uint8_t data_len = ptr[8];
                                    
                                    printf("            [Device %d]\n", i + 1);
                                    printf("              Event Type: 0x%02X, "
                                           "Addr Type: %s\n",
                                           event_type,
                                           addr_type == 0 ? "Public" :
                                           addr_type == 1 ? "Random" : "Other");
                                    printf("              MAC: ");
                                    print_mac_address(ptr + 2);
                                    printf("\n              RSSI: %d dBm\n",
                                           (int8_t)ptr[9 + data_len]);
                                    
                                    if (data_len > 0) {
                                        printf("              Advertising Data:\n");
                                        analyze_advertising_data(ptr + 9, data_len);
                                    }
                                    
                                    ptr += 10 + data_len;
                                }
                            }
                        }
                        break;
                        
                    case 0x03: // LE Connection Update Complete
                        stats.conn_packets++;
                        printf("LE Connection Update Complete\n");
                        break;
                        
                    default:
                        printf("Unknown LE Subevent\n");
                }
            }
            break;
            
        default:
            printf("Unknown Event (0x%02X)\n", event_code);
    }
    
    // Вывод полного дампа параметров события
    if (param_len > 0 && param_len <= length - 2) {
        printf("        Parameters (%d bytes):\n", param_len);
        hex_dump(data + 2, param_len, 10);
    }
}

// Анализ ACL Data пакетов
void analyze_acl_data(const uint8_t *data, size_t length) {
    if (length < 4) return;
    
    uint16_t handle = (data[1] << 8) | data[0];
    uint16_t data_len = (data[3] << 8) | data[2];
    uint8_t pb_flag = (handle >> 12) & 0x03;
    uint8_t bc_flag = (handle >> 14) & 0x03;
    handle = handle & 0x0FFF;
    
    printf("        Handle: 0x%04X, Length: %d\n", handle, data_len);
    printf("        PB Flag: 0x%01X (", pb_flag);
    switch (pb_flag) {
        case 0x00: printf("Continuation fragment"); break;
        case 0x01: printf("First fragment"); break;
        case 0x02: printf("Last fragment"); break;
        case 0x03: printf("Complete L2CAP"); break;
    }
    printf(")\n");
    
    printf("        BC Flag: 0x%01X (", bc_flag);
    switch (bc_flag) {
        case 0x00: printf("Point-to-point"); break;
        case 0x01: printf("Broadcast active slaves"); break;
        case 0x02: printf("Broadcast park slaves"); break;
        case 0x03: printf("Reserved"); break;
    }
    printf(")\n");
    
    // Анализ L2CAP заголовка (если есть)
    if (data_len >= 4 && length >= 8) {
        uint16_t l2cap_len = (data[5] << 8) | data[4];
        uint16_t cid = (data[7] << 8) | data[6];
        
        printf("        L2CAP Length: %d, CID: 0x%04X (", l2cap_len, cid);
        
        switch (cid) {
            case 0x0001: printf("Signaling Channel"); break;
            case 0x0002: printf("Connectionless Data"); break;
            case 0x0003: printf("AMP Manager"); break;
            case 0x0004: printf("ATT"); break;
            case 0x0005: printf("LE Signaling"); break;
            case 0x0006: printf("Security Manager"); break;
            case 0x0007: printf("BR/EDR Security Manager"); break;
            default:
                if (cid >= 0x0040 && cid <= 0xFFFF) {
                    printf("Dynamically Allocated");
                } else {
                    printf("Reserved");
                }
        }
        printf(")\n");
        
        // Анализ ATT протокола (если CID = 0x0004)
        if (cid == 0x0004 && data_len >= 5 && length >= 9) {
            uint8_t att_opcode = data[8];
            printf("        ATT OpCode: 0x%02X - ", att_opcode);
            
            switch (att_opcode) {
                case 0x01: printf("Error Response"); break;
                case 0x02: printf("Exchange MTU Request"); break;
                case 0x03: printf("Exchange MTU Response"); break;
                case 0x04: printf("Find Information Request"); break;
                case 0x05: printf("Find Information Response"); break;
                case 0x08: printf("Read By Type Request"); break;
                case 0x09: printf("Read By Type Response"); break;
                case 0x0A: printf("Read Request"); break;
                case 0x0B: printf("Read Response"); break;
                case 0x0C: printf("Read Blob Request"); break;
                case 0x12: printf("Write Request"); break;
                case 0x13: printf("Write Response"); break;
                case 0x52: printf("Handle Value Notification"); break;
                default: printf("Unknown ATT OpCode");
            }
            printf("\n");
        }
    }
    
    // Вывод данных ACL пакета
    if (data_len > 0 && length >= 4 + data_len) {
        printf("        ACL Data (%d bytes):\n", data_len);
        hex_dump(data + 4, data_len, 10);
    }
}

// Анализ SCO Data пакетов
void analyze_sco_data(const uint8_t *data, size_t length) {
    if (length < 3) return;
    
    uint16_t handle = data[0] & 0x0FFF;
    uint8_t packet_status = (data[0] >> 4) & 0x03;
    uint8_t data_len = data[1];
    
    printf("        Handle: 0x%04X, Length: %d\n", handle, data_len);
    printf("        Packet Status: 0x%01X (", packet_status);
    switch (packet_status) {
        case 0x00: printf("Correctly received"); break;
        case 0x01: printf("Possibly invalid"); break;
        case 0x02: printf("No reception"); break;
        case 0x03: printf("Lost packet"); break;
    }
    printf(")\n");
    
    // Вывод голосовых данных
    if (data_len > 0 && length >= 2 + data_len) {
        printf("        Voice Data (%d bytes):\n", data_len);
        hex_dump(data + 2, data_len, 10);
    }
}

// Анализ HCI Command пакетов
void analyze_hci_command(const uint8_t *data, size_t length) {
    if (length < 3) return;
    
    uint16_t opcode = (data[2] << 8) | data[1];
    uint8_t ogf = opcode >> 10;
    uint16_t ocf = opcode & 0x03FF;
    uint8_t param_len = data[3];
    
    printf("        OpCode: 0x%04X (OGF: 0x%02X, OCF: 0x%03X)\n", 
           opcode, ogf, ocf);
    
    printf("        OGF Group: ");
    switch (ogf) {
        case OGF_LINK_CTL:        printf("Link Control"); break;
        case OGF_LINK_POLICY:     printf("Link Policy"); break;
        case OGF_HOST_CTL:        printf("Host Controller"); break;
        case OGF_INFO_PARAM:      printf("Informational Parameters"); break;
        case OGF_STATUS_PARAM:    printf("Status Parameters"); break;
        case OGF_TESTING_CMD:     printf("Testing Commands"); break;
        case OGF_LE_CTL:          printf("LE Controller"); break;
        case OGF_VENDOR_CMD:      printf("Vendor Specific"); break;
        default:                  printf("Reserved");
    }
    printf("\n");
    
    // Расшифровка конкретных команд
    printf("        Command: ");
    if (ogf == OGF_LINK_CTL) {
        switch (ocf) {
            case OCF_INQUIRY: printf("Inquiry"); break;
            case OCF_INQUIRY_CANCEL: printf("Inquiry Cancel"); break;
            case OCF_CREATE_CONN: printf("Create Connection"); break;
            case OCF_DISCONNECT: printf("Disconnect"); break;
            default: printf("Unknown Link Control Command");
        }
    } else if (ogf == OGF_LE_CTL) {
        switch (ocf) {
            case OCF_LE_SET_SCAN_PARAMETERS: printf("LE Set Scan Parameters"); break;
            case OCF_LE_SET_SCAN_ENABLE: printf("LE Set Scan Enable"); break;
            case OCF_LE_CREATE_CONN: printf("LE Create Connection"); break;
            case OCF_LE_CONN_UPDATE: printf("LE Connection Update"); break;
            default: printf("Unknown LE Command");
        }
    } else {
        printf("Unknown Command");
    }
    printf("\n");
    
    printf("        Parameter Length: %d\n", param_len);
    
    // Вывод параметров команды
    if (param_len > 0 && length >= 4 + param_len) {
        printf("        Parameters:\n");
        hex_dump(data + 4, param_len, 10);
    }
}

// Основная функция анализа пакетов
void analyze_packet(const uint8_t *packet, size_t length) {
    if (length < 1) return;
    
    uint8_t pkt_type = packet[0];
    const uint8_t *data = packet + 1;
    size_t data_len = length - 1;
    
    stats.total_packets++;
    
    // Получение времени
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    // Вывод заголовка пакета
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║ Пакет #%06lu | Время: %02d:%02d:%02d | Размер: %4zu байт ║\n",
           stats.total_packets, t->tm_hour, t->tm_min, t->tm_sec, length);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // Анализ в зависимости от типа пакета
    switch (pkt_type) {
        case HCI_EVENT_PKT:
            stats.hci_events++;
            printf("║ Тип: HCI Event Packet (0x%02X)                              ║\n", pkt_type);
            printf("╚═══════════════════════════════════════════════════════════════╝\n");
            analyze_hci_event(data, data_len);
            break;
            
        case HCI_ACLDATA_PKT:
            stats.acl_packets++;
            printf("║ Тип: ACL Data Packet (0x%02X)                               ║\n", pkt_type);
            printf("╚═══════════════════════════════════════════════════════════════╝\n");
            analyze_acl_data(data, data_len);
            break;
            
        case HCI_SCODATA_PKT:
            stats.sco_packets++;
            printf("║ Тип: SCO Data Packet (0x%02X)                               ║\n", pkt_type);
            printf("╚═══════════════════════════════════════════════════════════════╝\n");
            analyze_sco_data(data, data_len);
            break;
            
        case HCI_COMMAND_PKT:
            stats.cmd_packets++;
            printf("║ Тип: HCI Command Packet (0x%02X)                            ║\n", pkt_type);
            printf("╚═══════════════════════════════════════════════════════════════╝\n");
            analyze_hci_command(data, data_len);
            break;
            
        default:
            stats.unknown_packets++;
            printf("║ Тип: Unknown Packet (0x%02X)                                ║\n", pkt_type);
            printf("╚═══════════════════════════════════════════════════════════════╝\n");
            printf("        Raw Data (%zu bytes):\n", length);
            hex_dump(packet, length, 8);
    }
    
    // Вывод полного дампа пакета
    printf("\n        Full Packet Dump:\n");
    hex_dump(packet, length, 8);
    printf("\n");
}

// Вывод статистики
void print_statistics() {
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                       СТАТИСТИКА                               ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║ Всего пакетов:           %10lu                          ║\n", stats.total_packets);
    printf("║ HCI Events:              %10lu                          ║\n", stats.hci_events);
    printf("║ ACL Data пакетов:        %10lu                          ║\n", stats.acl_packets);
    printf("║ SCO Voice пакетов:       %10lu                          ║\n", stats.sco_packets);
    printf("║ HCI Commands:            %10lu                          ║\n", stats.cmd_packets);
    printf("║ Advertising пакетов:     %10lu                          ║\n", stats.adv_packets);
    printf("║ Connection пакетов:      %10lu                          ║\n", stats.conn_packets);
    printf("║ Неизвестных пакетов:     %10lu                          ║\n", stats.unknown_packets);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
}

// Основная функция
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║             Bluetooth Packet Analyzer v1.0                    ║\n");
    printf("║         Полный анализ содержимого всех пакетов                ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    // Поиск Bluetooth адаптера
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        fprintf(stderr, "Ошибка: Bluetooth адаптер не найден\n");
        return 1;
    }
    
    // Получение информации об адаптере
    struct hci_dev_info di;
    if (hci_devinfo(dev_id, &di) < 0) {
        perror("Ошибка получения информации об адаптере");
        return 1;
    }
    
    printf("Адаптер: hci%d - %s\n", dev_id, di.name);
    printf("MAC адрес: ");
    print_mac_address(di.bdaddr.b);
    printf("\n\nНажмите Ctrl+C для остановки\n");
    
    // Открытие сокета
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Ошибка открытия сокета HCI");
        return 1;
    }
    
    // Настройка фильтра
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_all_ptypes(&flt);
    hci_filter_all_events(&flt);
    
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("Ошибка установки фильтра");
        close(sock);
        return 1;
    }
    
    // Буфер для пакетов
    unsigned char buf[HCI_MAX_EVENT_SIZE];
    
    printf("\nНачало захвата пакетов...\n");
    printf("════════════════════════════════════════════════════════════════\n");
    
    // Главный цикл захвата пакетов
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
                
                // Вывод промежуточной статистики каждые 20 пакетов
                if (stats.total_packets % 20 == 0) {
                    printf("[Статистика] Пакетов: %lu\n", stats.total_packets);
                }
            } else if (len == 0) {
                printf("Соединение закрыто\n");
                break;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    perror("Ошибка чтения");
                    break;
                }
            }
        }
        
        // Небольшая пауза для снижения нагрузки
        usleep(1000);
    }
    
    // Закрытие сокета
    close(sock);
    
    // Вывод финальной статистики
    print_statistics();
    
    printf("\nАнализатор завершил работу. Всего проанализировано %lu пакетов.\n",
           stats.total_packets);
    
    return 0;
}