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
#include "../lib/dfhell.h"
#define MAX 1024
const char *ip = "127.0.0.1";
const char *port = "5000";
void exchangeDhKey(int sockfd, mpz_t s);
int main(int argc, char *argv[])
{
	// if(argc != 3)
	// {
	// 	printf("Using:./client ip port\nExample:./client 127.0.0.1 5005\n\n");
	// 	return -1;
	// }

	//第1步：创建客户端的socket。
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		return -1;
	}

	//第2步：向服务器发起连接请求。
	struct hostent *h;
	if ((h = gethostbyname(ip)) == 0)
	{
		printf("gethostbyname failed.\n");
		close(sockfd);
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(port));
	memcpy(&servaddr.sin_addr, h->h_addr, h->h_length);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect");
		close(sockfd);
		return -1;
	}

	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	//第3步：与服务端通信，发送一个报文后等待回复，然后再发下一个报文。
	int iret;
	mpz_t dh;
	mpz_init(dh);
	exchangeDhKey(sockfd, dh);
	gmp_printf("DH协商密钥为：%Zd\n\n", dh);
	//第4步：关闭socket，释放资源。
	close(sockfd);
}
void exchangeDhKey(int sockfd, mpz_t s) //客户端交换
{
	DH_key client_dh_key; // 客户端生成的密钥
	mpz_t server_pub_key; // 服务器公钥
	char buf[MAX];
	// 初始化mpz_t类型变量
	mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
			  client_dh_key.pub_key, client_dh_key.k, server_pub_key, NULL);
	printf("生成大素数p=...\n");
	generate_p(client_dh_key.p);
	gmp_printf("p = %Zd\n\n", client_dh_key.p);
	mpz_set_ui(client_dh_key.g, (unsigned long int)5); // base g = 5
	// 将p发送给服务器
	bzero(buf, MAX);
	memcpy(buf, "pri", 3);
	int iret = 0;
	mpz_get_str(buf + 3, 16, client_dh_key.p);
	if (iret = send(sockfd, buf, strlen(buf), 0) <= 0)
	{
		perror("send");
	}
	// 生成客户端的私钥a
	printf("即将生成客户端私钥与公钥...\n");
	generate_pri_key(client_dh_key.pri_key);
	gmp_printf("客户端的私钥为%Zd\n\n", client_dh_key.pri_key);

	// 计算客户端的公钥A
	mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
			 client_dh_key.p);
	gmp_printf("客户端的公钥为%Zd\n\n", client_dh_key.pub_key);

	// 接收服务器的公钥B
	bzero(buf, MAX);
	printf("等待接收服务器的公钥, 并发送客户端公钥...\n\n");

	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	// read(sockfd, buf, sizeof(buf));
	mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key

	gmp_printf("服务器的公钥为%Zd\n\n", server_pub_key);

	// 将客户端公钥发送给服务器
	bzero(buf, MAX);
	memcpy(buf, "pub", 3);
	mpz_get_str(buf + 3, 16, client_dh_key.pub_key); // 按16进制将公钥传递给buf
	if (iret = send(sockfd, buf, strlen(buf), 0) <= 0)
	{
		perror("send");
	}
	// printf("发送：%s\n", buffer);
	// 客户端计算DH协议得到的密钥s
	printf("计算客户端经过DH协议得到的密钥...\n");
	// getchar();
	mpz_powm(client_dh_key.k, server_pub_key, client_dh_key.pri_key,
			 client_dh_key.p);
	mpz_set(s, client_dh_key.k); // 将密钥传递给s

	// 清除mpz_t变量
	mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
			   client_dh_key.pub_key, client_dh_key.k, server_pub_key, NULL);
}