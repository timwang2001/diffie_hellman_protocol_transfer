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
#include <iostream>
#include <iterator>
#include <sstream>
#include <iomanip>

#include "../lib/dfhell.h"
#include "../lib/socket.h"
#include "../aes_gcm/aes_256_gcm.cpp"

const char *port = "5000";
#define MAX 1024
using namespace std;
void exchange_dh_key(int sockfd, mpz_t s);

// int recvn(int s, char *recvbuf, unsigned int fixedlen)
// {
// 	int iResult; //存储单次recv操作的返回值
// 	int cnt;	 //统计相对于固定长度，还有多少没有接收
// 	cnt = fixedlen;
// 	while (cnt > 0)
// 	{
// 		iResult = recv(s, recvbuf, cnt, 0);
// 		if (iResult < 0)
// 		{
// 			//数据接收出现错误，返回失败
// 			return -1;
// 		}
// 		if (iResult == 0)
// 		{
// 			//对方关闭连接，返回已接收到的小于fixedlen的字节数
// 			cout << "连接关闭" << endl;
// 			return fixedlen - cnt;
// 		}
// 		cout << "接收到的字节数" << iResult << endl;
// 		//接收缓存指针后移
// 		recvbuf += iResult;
// 		//更新cnt
// 		cnt -= iResult;
// 	}
// 	return fixedlen;
// }

void printhex(char* temp)
{
	std::stringstream ss;
	for (int i = 0; i<7; i++)
	{
		
		int tm = temp[i];
		ss << std::hex << std::setw(2) << std::setfill('0') << tm;//见下文注释
		ss << " ";
	}
	string c = ss.str();
	string d;
	transform(c.begin(), c.end(), back_inserter(d), ::toupper);//将小写转化为大写
	std::cout << "string is : " << d << std::endl;
}

int main(int argc, char *argv[])
{
	// if(argc != 2)
	// {
	// 	printf("Using:./server port\nExample:./server 5005\n\n");
	// 	return -1;
	// }

	// 第1步：创建服务端的socket。
	int listenfd, clientfd;
	clientfd = bindandlisten(listenfd, port); //建立socket绑定port端口
	mpz_t dh_s;
	mpz_init(dh_s);
	// 根据DH协议交换信息，得到密钥dh_s
	exchange_dh_key(clientfd, dh_s);
	// 将密钥保存为unsigned char数组类型
	char key[32];
	mpz_get_str(key, 16, dh_s); // 将dh_s写入key
	gmp_printf("DH得出密钥为：%Zd\n", dh_s);
	mpz_clear(dh_s); // 清除dh_s

	int iret = 0;
	char buff[MAX];
	if ((iret = recv(clientfd, buff, sizeof(buff), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	char ivc[16];
	for (int i = 0; i < 17; i++)
		ivc[i] = buff[i];
	printf("%s\n%ld\n", ivc, strlen(ivc));
	unsigned char t[MAX];
	for (int i = 0; i < strlen(ivc); i++)
		t[i] = ivc[i];
	SecByteBlock iv(t, AES::BLOCKSIZE);
	printf("\n***********start transfer**************\n");
	for (int i = 0; i < strlen(key); i++)
		t[i] = key[i];
	SecByteBlock aeskey(t, AES::MAX_KEYLENGTH);
	while (1)
	{
		memset(buff, 0, sizeof(buff));
		if ((iret = recv(clientfd, buff, sizeof(buff), 0)) <= 0)
		//<0：出错 =0：对方调用close，关闭连接
		{
			printf("iret = %d\n", iret);
			break;
		}
		string temp = buff;
		printf("%s-len=%d\n", buff, strlen(buff));
		printhex(buff);
		aes_256_gcm_decrypt(temp,aeskey,iv);

	}
	close(listenfd);
	return 0;
}

void exchange_dh_key(int sockfd, mpz_t s)
{
	DH_key server_dh_key;
	mpz_t client_pub_key; // 客户端公钥
	char buf[MAX];
	mpz_inits(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
			  server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
	mpz_set_ui(server_dh_key.g, (unsigned long int)5); // g = 5
	//  从客户端接收p
	bzero(buf, MAX);

	// printf("等待从客户端接收p...\n\n");

	int iret = 0;
	bzero(buf, MAX);
	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	mpz_set_str(server_dh_key.p, buf + 3, 16); // 将p写入server_dh_key.p
	gmp_printf("p = %Zd\n\n", server_dh_key.p);

	// 生成服务器私钥
	// printf("将生成服务器端私钥与公钥\n\n");
	generate_pri_key(server_dh_key.pri_key);
	gmp_printf("服务器的私钥为%Zd\n", server_dh_key.pri_key);
	// calc the public key B of server
	mpz_powm(server_dh_key.pub_key, server_dh_key.g, server_dh_key.pri_key,
			 server_dh_key.p);
	gmp_printf("服务器的公钥为%Zd\n", server_dh_key.pub_key);

	// 将服务器公钥发送给客户端
	bzero(buf, MAX);
	// printf("发送公钥给客户端，并接收客户端公钥...\n");
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
	// printf("DH协议得到的密钥\n");
	// getchar();
	mpz_powm(server_dh_key.k, client_pub_key, server_dh_key.pri_key,
			 server_dh_key.p);
	mpz_set(s, server_dh_key.k);
	mpz_clears(server_dh_key.p, server_dh_key.g, server_dh_key.pri_key,
			   server_dh_key.pub_key, server_dh_key.k, client_pub_key, NULL);
}
