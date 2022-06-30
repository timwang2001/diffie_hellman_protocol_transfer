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
const char *ip = "127.0.0.1";
const char *port = "5000";
void exchangeDhKey(int sockfd, mpz_t s);


int main(int argc, char *argv[])
{
	if(argc != 3)
	{
		printf("Using:./client ip port\nExample:./client 127.0.0.1 5005\n\n");
		return -1;
	}
	//创建客户端的socket。
	int sockfd;
	//connect(sockfd, ip, port);
	connect(sockfd, argv[1], argv[2]);
	
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	//与服务端通信，发送一个报文后等待回复再发下一个报文。
	int iret;
	mpz_t dh;
	mpz_init(dh);
	exchangeDhKey(sockfd, dh);
	gmp_printf("DH协商密钥为：%Zd\n", dh);
	char key[32];
	mpz_get_str(key, 16, dh); // 将dh_s写入key
	//关闭socket
	char buff[MAX];
	SecByteBlock iv = generateiv();
	while(1)
	{
		string s = string(iv.begin(), iv.end());
		int l=s.length();
		int i;
		for(i=0;i<s.length();i++)
			buff[i]=s[i];
		buff[i] = '\0';
		if(strlen(buff)==(long int)16) break;
		
	}
	//发送iv
	if (iret = send(sockfd, buff, 17, 0) <= 0)
	{
		perror("send");
	}
	printf("\n***********start transfer**************\n");
	unsigned char t[MAX];
	for(int i=0;i<strlen(key);i++)
		t[i]=key[i];
	SecByteBlock aeskey(t,AES::MAX_KEYLENGTH);
	// test transfer for MITM verify
    string test_msg="test_transfer";
    memset(buff,0,MAX);
    memcpy(buff,test_msg.c_str(),sizeof(test_msg));
    string temp_test = test_aes_256_gcm_encrypt_decrypt(buff,aeskey,iv,1);
    const char* ciphers_test = temp_test.data();
    if (iret = send(sockfd, ciphers_test, (int)strlen(ciphers_test), 0) <= 0)
    {
        perror("send");
        exit(0);
    }
    // test end
    while(1)
	{
		bzero(buff, MAX);
		scanf("%s",&buff);
		string temp = test_aes_256_gcm_encrypt_decrypt(buff,aeskey,iv,1);
		const char* ciphers = temp.data();
		if (iret = send(sockfd, ciphers, (int)strlen(ciphers), 0) <= 0)
		{
			perror("send");
			break;
		}

	}
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