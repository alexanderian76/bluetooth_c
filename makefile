all:
	gcc -Wall -Wextra -g main.c -lbluetooth
	
server: server_build server_run

server_build:
	gcc -Wall -Wextra -g server.c -lbluetooth -o server
	
server_run:
	./server

run:
	./a.out