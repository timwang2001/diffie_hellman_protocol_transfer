int bindandlisten(int listenfd,const char* port)
{
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
	if (listen(listenfd, 5) != 0)
	{
		perror("listen");
		close(listenfd);
		return -1;
	}
	
	int clientfd;
	int socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in clientaddr;
	clientfd = accept(listenfd, (struct sockaddr *)&clientaddr, (socklen_t *)&socklen);
	printf("客户端（%s）已连接。\n", inet_ntoa(clientaddr.sin_addr));
	return clientfd;
}

int connect(int &sockfd,const char* ip,const char* port)
{
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
	return 0;
}