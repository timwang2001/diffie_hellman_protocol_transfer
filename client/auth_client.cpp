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
void printhex(const char* temp);


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
	int iret=0;
	mpz_t dh;
	mpz_init(dh);
	exchangeDhKey(sockfd, dh);
	gmp_printf("DH协商密钥为：%Zd\n", dh);
	char key[32];
	mpz_get_str(key, 16, dh); // 将dh_s写入key
	//关闭socket
    cout<<"waiting for auth"<<endl;
    //预共享密钥实现，接收server发送的iv并使用DH密钥加密并回送给服务器
	char buff[MAX];
	if ((iret = recv(sockfd, buff, sizeof(buff), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	byte ivc[16];
	for (int i = 0; i < 16; i++)
		ivc[i] = buff[i];
	//freopen("iv.txt", "wb", stdout);
	// printf("%s\n%ld\n", ivc, strlen(ivc));
	//printf("%s", ivc);
	//fclose(stdout);
	SecByteBlock iv(ivc, AES::BLOCKSIZE);

	unsigned char t[MAX];
	for(int i=0;i<strlen(key);i++)
		t[i]=key[i];
	SecByteBlock aeskey(t,AES::MAX_KEYLENGTH);
    bzero(buff, MAX);
    memcpy(buff,iv,16);
	string encrypted_iv=aes_256_gcm_encrypt(buff,aeskey,iv);
    const char* iv_ciphers = encrypted_iv.data();
    // cout<<strlen(ciphers)<<endl;
    // printhex(ciphers);
    if (iret = send(sockfd, iv_ciphers, (int)strlen(iv_ciphers), 0) <= 0)
    {
        perror("send");
        exit(0);
    }
    printf("\n***********start transfer**************\n");
	while(1)
	{
		bzero(buff, MAX);
		scanf("%s",&buff);
		// printf("%s",buff);
		//将发送aes加密后的buff
		//string temp = aes_256_gcm_encrypt(buff,aeskey,iv);
		// printf("\n");
		string temp = test_aes_256_gcm_encrypt_decrypt(buff,aeskey,iv,1);
		// printf("-len=");
		//printf("%s",temp);
		const char* ciphers = temp.data();
		// cout<<strlen(ciphers)<<endl;
		// printhex(ciphers);
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
	// printf("生成大素数p=...\n");
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
	// printf("即将生成客户端私钥与公钥...\n");
	generate_pri_key(client_dh_key.pri_key);
	gmp_printf("客户端的私钥为%Zd\n", client_dh_key.pri_key);

	// 计算客户端的公钥A
	mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
			 client_dh_key.p);
	gmp_printf("客户端的公钥为%Zd\n", client_dh_key.pub_key);

	// 接收服务器的公钥B
	bzero(buf, MAX);
	// printf("等待接收服务器的公钥, 并发送客户端公钥...\n\n");

	if ((iret = recv(sockfd, buf, sizeof(buf), 0)) <= 0)
	{
		printf("iret = %d\n", iret);
	}
	// read(sockfd, buf, sizeof(buf));
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
	// printf("发送：%s\n", buffer);
	// 客户端计算DH协议得到的密钥s
	// printf("计算客户端经过DH协议得到的密钥...\n");
	// getchar();
	mpz_powm(client_dh_key.k, server_pub_key, client_dh_key.pri_key,
			 client_dh_key.p);
	mpz_set(s, client_dh_key.k); // 将密钥传递给s

	// 清除mpz_t变量
	mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
			   client_dh_key.pub_key, client_dh_key.k, server_pub_key, NULL);
}
void printhex(const char* temp)//以hex方式输出字符串
{
	std::stringstream ss;
	for (int i = 0; i<strlen(temp); i++)
	{
		int tm = temp[i];
		ss << std::hex << std::setw(2) << std::setfill('0') << tm;//见下文注释
		//ss << "";
	}
	string c = ss.str();
	string d;
	transform(c.begin(), c.end(), back_inserter(d), ::toupper);//将小写转化为大写
	std::cout << "string is : " << d << std::endl;
}