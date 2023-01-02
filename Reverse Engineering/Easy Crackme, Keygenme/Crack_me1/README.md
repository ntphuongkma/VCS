# Crack_me1 writeup
## Description
Chạy thử chương trình, yêu cầu nhập mật khẩu => flag

![start](./start.jpg)

## Analysis with IDA
Ném vào ida để phân tích chương trình
```
passwd = 0;
  memset(v9, 0, sizeof(v9));
  v12 = 335;
  memset(v10, 0, sizeof(v10));
  strcpy(
    Format,
    "Do you remember the good old days?! I don't know how about you,but I don't. Please help me to recover my memory, it'"
    "s password protected, and that's sad :(\n");
  v11 = &unk_5E4BE8;
  printf(Format, v4);
  printf("Enter password: ", v5);
  scanf("%300[^\n]s", (char)&passwd);
  v20 = &passwd;
  v16 = v9;
  v20 += strlen(v20);
  v15 = ++v20 - v9;
  v17 = v20 - v9;
  v19 = &passwd;
  v14 = v9;
  v19 += strlen(v19);
  v13 = ++v19 - v9;
  if ( (unsigned int)(v19 - v9) >= 294 )
  {
    if ( check(&passwd) )
    {
      v18 = v17 / 3;
      for ( i = 0; i < v17; ++i )
        v10[i % v18] ^= v9[i - 1];
      for ( i = 0; i < v12; ++i )
        byte_5E4020[i] ^= v10[i % v18];
      printf("\n\nCongratulation! Here is your memo :> \n\n", v6);
      printf("%s", (char)byte_5E4020);
    }
    else
    {
      printf("\nInvalid password\n", v6);
    }
    getchar();
    getchar();
    return 0;
  }
  else
  {
    printf("oh, no!", v6);
    return 0;
  }
```
