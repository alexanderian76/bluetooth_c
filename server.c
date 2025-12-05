#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <pthread.h>

#define BUFFER_SIZE 1024

// Функция для приема данных
void *receive_thread(void *arg) {
    int client_sock = *(int*)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;
    
    printf("Receive thread started\n");
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        bytes_read = read(client_sock, buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("Received: %s\n", buffer);
        } else if (bytes_read == 0) {
            printf("Connection closed\n");
            break;
        } else {
            perror("Read failed");
            break;
        }
    }
    
    return NULL;
}

int main(int argc, char **argv)
{
    struct sockaddr_rc addr = { 0 };
    int sock, client, status;
    char dest[18] = "74:42:18:35:B6:44"; // Замените на MAC адрес устройства
    char buffer[BUFFER_SIZE];
    pthread_t thread_id;
    
    if (argc > 1) {
        strncpy(dest, argv[1], 18);
    } else {
        printf("Usage: %s <bluetooth address>\n", argv[0]);
        printf("Using default address: %s\n", dest);
    }
    
    printf("=== Bluetooth Client ===\n");
    printf("Connecting to %s...\n", dest);
    
    // Создаем RFCOMM сокет
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    // Настраиваем соединение
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t) 1; // Стандартный канал для SPP
    str2ba(dest, &addr.rc_bdaddr);
    
    // Подключаемся к устройству
    status = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (status < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }
    
    printf("Connected successfully!\n");
    
    // Создаем поток для приема данных
    if (pthread_create(&thread_id, NULL, receive_thread, &sock) != 0) {
        perror("Thread creation failed");
        close(sock);
        return 1;
    }
    
    // Основной цикл для отправки данных
    printf("Type messages to send (type 'quit' to exit):\n");
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        memset(buffer, 0, sizeof(buffer));
        fgets(buffer, sizeof(buffer), stdin);
        
        // Убираем символ новой строки
        buffer[strcspn(buffer, "\n")] = 0;
        
        if (strcmp(buffer, "quit") == 0) {
            break;
        }
        
        // Отправляем данные
        status = write(sock, buffer, strlen(buffer));
        if (status < 0) {
            perror("Write failed");
            break;
        }
        
        printf("Sent: %s\n", buffer);
    }
    
    // Ожидаем завершения потока
    pthread_join(thread_id, NULL);
    
    // Закрываем соединение
    close(sock);
    printf("Disconnected\n");
    
    return 0;
}