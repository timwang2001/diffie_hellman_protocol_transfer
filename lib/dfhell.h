int IsPrime(int a, int b)//判断两个数是否互素
{
	int temp;
	while (b != 0)
	{
		temp = b;
		b = a % b;
		a = temp;
	}

	if (a == 1)
		return 1;
	else
		return 0;
}


void Euler(int n, int* s, int& sum)//得到欧拉函数的值和取值集合
{
	int i, flag;
	for (i = 1; i < n; i++)
	{
		flag = IsPrime(i, n);
		if (flag == 1)
		{
			s[sum] = i;
			sum++;
		}
	}
}


int power(long int x, long int y, long int n)//快速幂取余(x^y%n)
{
	long int t = 1;
	while (y > 0)
	{
		if (y % 2 == 1)
		{
			y -= 1;
			t = t * x % n;
		}
		else {
			y /= 2;
			x = x * x % n;
		}
	}
	return t % n;
}


void root(int n, int sum, int s[])//根据互素集合利用遍历的方法求本原根
{
	int i, j;
	int flag[100], k;
	for (i = 0; i < sum; i++)
	{
		k = 0;
		for (j = 1; j < sum + 1; j++)
		{
			//这里要利用快速幂取余，否则数值太大会溢出
			flag[j - 1] = power(s[i], j, n);
		}
		sort(flag, sum);

		for (j = 0; j < sum; j++)
		{
			if (flag[j] != s[j])
				k = 1;
		}
		if (k == 0)
			cout << s[i] << " ";
	}
}


bool is_prime(int number)//判断素数
{
	int i;
	for (i = 2; i <= sqrt(number); i++)
	{
		if (number % i == 0)
			return false;
	}
	if (i > sqrt(number))
		return true;

}