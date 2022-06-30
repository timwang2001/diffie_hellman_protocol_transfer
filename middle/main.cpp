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
#include <iterator>
#include <sstream>
#include <iomanip>
#include "../lib/dfhell.h"
#include "../lib/socket.h"
#include "../aes_gcm/aes_256_gcm.cpp"
#define MAX 1024
const char *port = "5000";

void exchangewithclient(int sockfd, mpz_t s);
void exchangewithserver(int sockfd, mpz_t s); //客户端交换

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Using:./middle serverip  port\n\n");
		return -1;
	}

	// 第1步：创建服务端的socket。
	int listenfd, clientfd;
	clientfd = bindandlisten(listenfd, argv[2]); //建立socket绑定port端口
	mpz_t dh_s;
	mpz_init(dh_s);
	// 根据DH协议交换信息，得到密钥dh_s
	exchangewithclient(clientfd, dh_s);
	// 将密钥保存为unsigned char数组类型S
	char ckey[32];				 // client key
	mpz_get_str(ckey, 16, dh_s); // 将dh_s写入key
	gmp_printf("与client协商DH得出密钥为：%Zd\n", dh_s);
	mpz_clear(dh_s); // 清除dh_s
	int iret;
	char buff[MAX];
	if ((iret = recv(clientfd, buff, sizeof(buff), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	byte ivcc[16];
	for (int i = 0; i < 16; i++)
		ivcc[i] = buff[i];

	SecByteBlock ivc(ivcc, AES::BLOCKSIZE); //中间人与client之间的
	unsigned char tt[MAX];
	for (int i = 0; i < strlen(ckey); i++)
		tt[i] = ckey[i];
	SecByteBlock aeskeyc(tt, AES::MAX_KEYLENGTH); // client & middle
	//*********************************************************************/
	int sockfd;
	connect(sockfd, argv[1], port);
	//与服务端通信，发送一个报文后等待回复再发下一个报文。
	mpz_t dh;
	mpz_init(dh);
	exchangewithserver(sockfd, dh);
	gmp_printf("与服务器中间人DH协商密钥为：%Zd\n", dh);
	char keys[32];			   // server key
	mpz_get_str(keys, 16, dh); // 将dh_s写入key
	//关闭socket
	SecByteBlock ivs = generateiv(); //中间人与server之间的
	while (1)
	{
		string s = string(ivs.begin(), ivs.end());
		int l = s.length();
		int i;
		for (i = 0; i < s.length(); i++)
			buff[i] = s[i];
		buff[i] = '\0';
		if (strlen(buff) == (long int)16)
			break;
	}
	//发送ivs
	if (iret = send(sockfd, buff, 17, 0) <= 0)
	{
		perror("send");
	}
	// iv
	unsigned char t[MAX];
	for (int i = 0; i < strlen(keys); i++)
		t[i] = keys[i];
	SecByteBlock aeskeys(t, AES::MAX_KEYLENGTH);

	iret = 0;
	memset(buff,0,sizeof(buff));
	printf("\n***********start transfer**************\n");

	while (1)
	{
		memset(buff, 0, sizeof(buff));
		if ((iret = recv(clientfd, buff, sizeof(buff), 0)) <= 0)
		//<0：出错 =0：对方调用close，关闭连接
		{
			printf("iret = %d\n", iret);
			break;
		}
		string temp;
		temp.assign(buff, strlen(buff));
		string recoverd = " "; // from client
		recoverd = test_aes_256_gcm_encrypt_decrypt(temp, aeskeyc, ivc, 0);
		// received --
		recoverd = recoverd + "hacked";
		temp = test_aes_256_gcm_encrypt_decrypt(recoverd, aeskeys, ivs, 1); // encrypt
		const char *ciphers = temp.data();
		if (iret = send(sockfd, ciphers, (int)strlen(ciphers), 0) <= 0)
		{
			perror("send");
			break;
		}
	}
	close(listenfd);
	close(sockfd);
	return 0;
}

void exchangewithclient(int sockfd, mpz_t s)
{
	DH_key server_dh_key;
	mpz_t client_pub_key; // 客户端公钥
	char buf[MAX];
	mpz_inits(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
			  server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
	mpz_set_ui(server_dh_key.g, (unsigned long int)5); // g = 5
	//  从客户端接收p
	bzero(buf, MAX);
	int iret = 0;
	bzero(buf, MAX);
	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	mpz_set_str(server_dh_key.p, buf + 3, 16); // 将p写入server_dh_key.p
	gmp_printf("p = %Zd\n\n", server_dh_key.p);
	// 生成服务器私钥
	generate_pri_key(server_dh_key.pri_key);
	gmp_printf("服务器的私钥为%Zd\n", server_dh_key.pri_key);
	// calc the public key B of server
	mpz_powm(server_dh_key.pub_key, server_dh_key.g, server_dh_key.pri_key,
			 server_dh_key.p);
	gmp_printf("服务器的公钥为%Zd\n", server_dh_key.pub_key);
	// 将服务器公钥发送给客户端
	bzero(buf, MAX);
	memcpy(buf, "pub", 3);
	mpz_get_str(buf + 3, 16, server_dh_key.pub_key);
	if (iret = send(sockfd, buf, strlen(buf), 0) <= 0)
	{
		perror("send");
	}
	// 接收客户端公钥
	bzero(buf, MAX);
	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	mpz_set_str(client_pub_key, buf + 3, 16);
	gmp_printf("客户端公钥为%Zd\n", client_pub_key);
	// 服务器计算DH协议生成的密钥s
	mpz_powm(server_dh_key.k, client_pub_key, server_dh_key.pri_key,
			 server_dh_key.p);
	mpz_set(s, server_dh_key.k);
	mpz_clears(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
			   server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
}

void exchangewithserver(int sockfd, mpz_t s) //客户端交换
{
	DH_key client_dh_key; // 客户端生成的密钥
	mpz_t server_pub_key; // 服务器公钥
	char buf[MAX];
	// 初始化mpz_t类型变量
	mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
			  client_dh_key.pub_key, client_dh_key.k, server_pub_key, NULL);
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
	generate_pri_key(client_dh_key.pri_key);
	gmp_printf("客户端的私钥为%Zd\n", client_dh_key.pri_key);
	// 计算客户端的公钥A
	mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
			 client_dh_key.p);
	gmp_printf("客户端的公钥为%Zd\n", client_dh_key.pub_key);
	// 接收服务器的公钥B
	bzero(buf, MAX);
	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key
	gmp_printf("服务器的公钥为%Zd\n", server_pub_key);
	// 将客户端公钥发送给服务器
	bzero(buf, MAX);
	memcpy(buf, "pub", 3);
	mpz_get_str(buf + 3, 16, client_dh_key.pub_key); // 按16进制将公钥传递给buf
	if (iret = send(sockfd, buf, strlen(buf), 0) <= 0)
	{
		perror("send");
	}
	mpz_powm(client_dh_key.k, server_pub_key, client_dh_key.pri_key,
			 client_dh_key.p);
	mpz_set(s, client_dh_key.k); // 将密钥传递给s
	// 清除mpz_t变量
	mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
			   client_dh_key.pub_key, client_dh_key.k, server_pub_key, NULL);
}