#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cmath>
#include"../lib/dfhell.h"
const char *port = "5000";
#define MAX 1024

void exchange_dh_key(int sockfd, mpz_t s);

int main(int argc, char *argv[])
{
	// if(argc != 2)
	// {
	// 	printf("Using:./server port\nExample:./server 5005\n\n");
	// 	return -1;
	// }

	// 第1步：创建服务端的socket。
	int listenfd;
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		return -1;
	}

	//第2步：把服务端用于通信的地址和端口绑定到socket上。
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	// servaddr.sin_addr.s_addr = inet_addr("192.168.190.134);
	servaddr.sin_port = htons(atoi(port));

	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("bind");
		close(listenfd);
		return -1;
	}

	//第3步，把socket设置为监听模式。
	int clientfd;
	int socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in clientaddr;
	clientfd = accept(listenfd, (struct sockaddr *)&clientaddr, (socklen_t *)&socklen);
	
	if (listen(listenfd, 5) != 0)
	{
		perror("listen");
		close(listenfd);
		return -1;
	}
    mpz_t dh_s;
    mpz_init(dh_s);
    // 根据DH协议交换信息，得到密钥dh_s
    exchange_dh_key(clientfd, dh_s);

    // 将密钥保存为unsigned char数组类型
    unsigned char key[32];
    //mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("DH得出密钥为：%Zd\n\n", dh_s);
    mpz_clear(dh_s); // 清除dh_s
    printf("*************************************DH结束************************************\n\n\n");


    close(listenfd);
    return 0;
	}
// 	//第4步：接受客户端的连接。
// 	

// 	printf("客户端（%s）已连接。\n", inet_ntoa(clientaddr.sin_addr));

// 	//第5步：与客户端通信，接受客户端发过来的报文后，回复ok。
// 	char buffer[1024];
// 	while (1)
// 	{
// 		int iret;
// 		memset(buffer, 0, sizeof(buffer));
// 		if ((iret = recv(clientfd, buffer, sizeof(buffer), 0)) <= 0)
// 		{
// 			printf("iret = %d\n", iret);
// 			break;
// 		}
// 		printf("接收：%s\n", buffer);

// 		strcpy(buffer, "ok");
// 		if ((iret = send(clientfd, buffer, strlen(buffer), 0)) <= 0)
// 		{
// 			perror("send");
// 			break;
// 		}
// 		printf("发送：%s\n", buffer);
// 	}

// 	//第6步：关闭socket，释放资源。
// 	close(listenfd);
// 	close(clientfd);
// }

void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key server_dh_key;
    mpz_t client_pub_key; // 客户端公钥
    char buf[MAX];
    mpz_inits(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
              server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
    mpz_set_ui(server_dh_key.g, (unsigned long int)5); // g = 5
    // 从客户端接收p
    bzero(buf, MAX);
	int iret;
    printf("等待从客户端接收p...\n\n");
	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		read(sockfd, buf, sizeof(buf));
    	mpz_set_str(server_dh_key.p, buf + 3, 16); // 将p写入server_dh_key.p
    	gmp_printf("p = %Zd\n\n", server_dh_key.p);
	}
    

    // 用于防止中间人攻击
    mpz_t temp;
    mpz_init_set_str(temp, "123456789", 16);

    // 生成服务器私钥
    printf("将生成服务器端私钥与公钥(回车继续)...\n\n");
    generate_pri_key(server_dh_key.pri_key);
    gmp_printf("服务器的私钥为%Zd\n\n", server_dh_key.pri_key);
    // calc the public key B of server
    mpz_powm(server_dh_key.pub_key, server_dh_key.g, server_dh_key.pri_key,
             server_dh_key.p);
    gmp_printf("服务器的公钥为%Zd\n\n", server_dh_key.pub_key);

    // 将服务器公钥发送给客户端
    bzero(buf, MAX);
    printf("按下回车发送公钥给客户端，并接收客户端公钥...\n");
    getchar();
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, server_dh_key.pub_key);
    write(sockfd, buf, sizeof(buf));

    // 接收客户端公钥
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(client_pub_key, buf + 3, 16);
    gmp_printf("客户端公钥为%Zd\n\n", client_pub_key);

    // 服务器计算DH协议生成的密钥s
    printf("按下回车计算服务器端经过DH协议得到的密钥...\n");
    getchar();
    mpz_powm(server_dh_key.k, client_pub_key, server_dh_key.pri_key,
             server_dh_key.p);
    mpz_set(s, server_dh_key.k);

    mpz_clears(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
               server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
}
