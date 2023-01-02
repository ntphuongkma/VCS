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

Nhận thấy chương trình yêu cầu nhập mật khẩu có độ dài >= 294. Sau đó sẽ gọi đến hàm ``` check ``` để kiểm tra mật khẩu nhập vào có đúng hay không. Rồi từ mật khẩu tính toán để gen ra flag.

Check main:
```
  v3 = &unk_5E4BE8;
  if ( (int)strlen(a1) < 55 )
    return 0;
  for ( i = 0; i < 122; ++i )
  {
    if ( !(unsigned __int8)check2(*v3, &a1[v3[1]], v3 + 2) )
      return 0;
    v3 += 3;
  }
  return 1;
```
Check2 main:
```
  v8 = 221;
  v5 = (LPVOID)sub_5E1000((int)&unk_5E4288, 0xDDu, 5);
  v7 = 278;
  v6 = (LPVOID)sub_5E1000((int)&unk_5E4170, 0x116u, 6);
  if ( !v5 || !v6 )
    return 0;
  switch ( a1 )
  {
    case 1:
      dwSize = 97;
      lpAddress = (LPVOID)sub_5E1000((int)&unk_5E4B80, 0x61u, 1);
      break;
    case 2:
      dwSize = 142;
      lpAddress = (LPVOID)sub_5E1000((int)&unk_5E4AF0, 0x8Eu, 2);
      break;
    case 3:
      dwSize = 1685;
      lpAddress = (LPVOID)sub_5E1000((int)&unk_5E4458, 0x695u, 3);
      break;
    case 4:
      dwSize = 235;
      lpAddress = (LPVOID)sub_5E1000((int)&unk_5E4368, 0xEBu, 4);
      break;
    default:
      return 0;
  }
  if ( !lpAddress )
    return 0;
  v11 = ((int (__cdecl *)(int, int, char *))lpAddress)(a2, a3, v4);
  VirtualFree(lpAddress, dwSize, 0x8000u);
  VirtualFree(v5, v8, 0x8000u);
  VirtualFree(v6, v7, 0x8000u);
  return v11;
 ```
 
Hàm sub_521000 alloc 1 vùng nhớ có size = dwSize sau đó từ địa chỉ a1 để tính toán và sẽ trả về địa chỉ của vùng nhớ vừa được alloc. Các func từ 1 đến 4 tương ứng với các case trong hàm ``` check2 ``` 
 
 ### Func1
 ```
 bool __cdecl sub_810000(char *a1, unsigned __int8 *a2)
{
  char v2; // cl

  v2 = *a1 % 2;
  if ( !v2 && (*a1 ^ 0x20) == *a2 )
    return 1;
  return v2 == 1 && (*a1 ^ 0x52) == *a2;
}
```
### Func2
```
bool __cdecl sub_9D0000(char *a1, unsigned __int16 *a2)
{
  int i; // [esp+0h] [ebp-Ch]
  unsigned __int16 v4; // [esp+8h] [ebp-4h]

  v4 = a1[1] | (unsigned __int16)(*a1 << 8);
  for ( i = 1; i <= 5; ++i )
    v4 = (((int)v4 >> (16 - i)) | (v4 << i)) ^ 0x1693;
  return *a2 == v4;
}
```
### Func3
```
bool __cdecl sub_6D0000(char *a1, unsigned __int8 *a2)
{
  char v3[68]; // [esp+0h] [ebp-64h] BYREF
  int v4; // [esp+44h] [ebp-20h]
  int v5; // [esp+48h] [ebp-1Ch]
  int v7; // [esp+50h] [ebp-14h]
  int i; // [esp+54h] [ebp-10h]
  int v9; // [esp+58h] [ebp-Ch]
  unsigned __int8 v10; // [esp+5Ch] [ebp-8h]
  unsigned __int8 v11; // [esp+5Dh] [ebp-7h]
  unsigned __int8 v12; // [esp+5Eh] [ebp-6h]
  char v13; // [esp+5Fh] [ebp-5h]
  char v14; // [esp+60h] [ebp-4h]
  char v15; // [esp+61h] [ebp-3h]
  char v16; // [esp+62h] [ebp-2h]

  v9 = 0;
  i = 0;
  v7 = 3;
  v5 = 0;
  v4 = 0;
  qmemcpy(v3, "ABDCEHGFIJKLUNOPYRTSMVWXQZajcdefohibkmlngpqrstuv4xzy8123w56709+0", 64);
  while ( v7-- )
  {
    *(&v14 + v9++) = *a1++;
    if ( v9 == 3 )
    {
      v10 = (v14 & 0xFC) >> 2;
      if ( v3[v10] != *a2 )
        return 0;
      v11 = ((v15 & 0xF0) >> 4) + 16 * (v14 & 3);
      if ( v3[v11] != a2[1] )
        return 0;
      v12 = ((v16 & 0xC0) >> 6) + 4 * (v15 & 0xF);
      if ( v3[v12] != a2[2] )
        return 0;
      v13 = v16 & 0x3F;
      if ( v3[v16 & 0x3F] != a2[3] )
        return 0;
      v9 = 0;
    }
  }
  if ( v9 <= 0 )
    return 1;
  for ( i = v9; i < 3; ++i )
    *(&v14 + i) = 0;
  v10 = (v14 & 0xFC) >> 2;
  if ( v3[v10] != *a2 )
    return 0;
  v11 = ((v15 & 0xF0) >> 4) + 16 * (v14 & 3);
  if ( v3[v11] != a2[1] )
    return 0;
  v12 = ((v16 & 0xC0) >> 6) + 4 * (v15 & 0xF);
  if ( v3[v12] != a2[2] )
    return 0;
  v13 = v16 & 0x3F;
  return v3[v16 & 0x3F] == a2[3];
}
```
Func3 sử dụng Base64 
### Func4
```
int __cdecl sub_810000(char *a1, int a2, int a3)
{
  char v4[256]; // [esp+0h] [ebp-11Ch] BYREF
  int (__cdecl *v5)(char *, char *, int); // [esp+100h] [ebp-1Ch]
  void (__cdecl *v6)(char *, char *); // [esp+104h] [ebp-18h]
  char v7[8]; // [esp+108h] [ebp-14h] BYREF
  char v8[11]; // [esp+110h] [ebp-Ch] BYREF

  strcpy(v8, "susan");
  v6 = *(void (__cdecl **)(char *, char *))(a3 + 4);
  v5 = *(int (__cdecl **)(char *, char *, int))(a3 + 8);
  v6(v8, v4);
  v7[0] = *a1;
  v7[1] = a1[1];
  v7[2] = a1[2];
  v7[3] = a1[3];
  v7[4] = 0;
  return v5(v4, v7, a2);
}
```
Func4 sử dụng thuật toán RC4
### Script to get password
```
from Crypto.Cipher import ARC4
from pwn import p32
from base64 import *

code = [(1, 0, 3435973748), (1, 1, 3435973704), (1, 2, 3435973691), (2, 136, 3435930753), (3, 111, 1868116835), (2, 132, 3435921665), (2, 10, 3435966261), (1, 208, 3435973683), (3, 15, 1987595620), (4, 18, 447815901), (1, 262, 3435973644), (3, 232, 893535338), (2, 29, 3435930022), (2, 31, 3435956926), (1, 33, 3435973708), (2, 34, 3435925030), (1, 36, 3435973685), (1, 93, 3435973691), (3, 43, 1966687594), (4, 22, 233652104), (3, 235, 2052469610), (2, 50, 3435966261), (2, 48, 3435933611), (2, 8, 3435935361), (3, 52, 1969450090), (1, 55, 3435973632), (2, 56, 3435936805), (3, 83, 1733445193), (1, 62, 3435973665), (1, 63, 3435973716), (1, 146, 3435973687), (1, 134, 3435973748), (4, 265, 335361728), (1, 74, 3435973632), (1, 269, 3435973714), (4, 77, 1136278977), (3, 284, 1870082660), (4, 58, 212890573), (4, 86, 112817101), (3, 90, 2037199441), (4, 271, 279852747), (1, 94, 3435973693), (2, 95, 3435929857), (4, 104, 112535432), (1, 186, 3435973700), (4, 154, 112868060), (3, 108, 1833584201), (4, 4, 1135501960), (4, 114, 251470017), (2, 199, 3435955773), (1, 122, 3435973675), (4, 123, 230172552), (1, 198, 3435973646), (1, 131, 3435973675), (1, 3, 3435973633), (4, 147, 331096968), (4, 169, 1135753096), (3, 12, 1131235162), (4, 138, 297547470), (4, 142, 297563099), (4, 175, 179644369), (2, 68, 3435963685), (1, 151, 3435973687), (2, 152, 3435933441), (4, 97, 50150620), (1, 158, 3435973714), (4, 159, 989691355), (4, 70, 397485771), (1, 167, 3435973683), (1, 47, 3435973632), (1, 135, 3435973704), (1, 173, 3435973683), (1, 174, 3435973710), (4, 201, 16590535), (2, 179, 3435962658), (1, 181, 3435973632), (4, 182, 1135099089), (3, 101, 1935225681), (1, 187, 3435973687), (1, 188, 3435973681), (4, 210, 212431836), (3, 191, 943871066), (2, 194, 3435929985), (1, 218, 3435973710), (4, 127, 397684937), (4, 118, 263725517), (4, 251, 296580045), (2, 205, 3435931302), (1, 207, 3435973632), (2, 75, 3435932709), (1, 209, 3435973681), (2, 189, 3435930275), (3, 275, 2037204809), (2, 196, 3435963430), (3, 239, 1819101034), (4, 220, 230454221), (1, 238, 3435973632), (4, 228, 212805574), (3, 26, 1429811546), (1, 46, 3435973685), (4, 224, 213808076), (1, 219, 3435973685), (2, 242, 3435963532), (4, 244, 129184392), (2, 37, 3435936167), (4, 64, 95696776), (1, 255, 3435973693), (3, 256, 1800811089), (3, 259, 1833588836), (4, 39, 1018830279), (2, 263, 3435922987), (4, 163, 16590535), (1, 168, 3435973710), (1, 270, 3435973693), (3, 248, 1733445193), (4, 214, 45428872), (2, 278, 3435955749), (4, 280, 217915612), (2, 81, 3435963048), (3, 287, 861301859), (3, 290, 1800034385), (1, 293, 3435973646)]

def rFunc1(x):
    x = x & 0xFF
    if((x ^ 0x20) % 2 == 0):
        return (x ^ 0x20)
    elif((x ^ 0x52) % 2 == 1):
        return (x ^ 0x52)

def rFunc2(x):
    def Func2(inp):
        out = ((inp >> 8) & 0xFF) | ((inp << 8) & 0xFFFF)
        for i in range(1,6):
            out = ((out >> (16 - i)) | (out << i)) ^ 0x1693
            out &= 0xffff
        return out 
    for i in range(0xffff):
        if Func2(i) == x&0xffff:
            return [(i&0xff), ((i>>8)&0xff)]
            

def rFunc4(x):
    key = b'susan'
    cipher = ARC4.new(key)
    return cipher.decrypt(p32(x))

def rFunc3(x):
    my_base64chars  = "ABDCEHGFIJKLUNOPYRTSMVWXQZajcdefohibkmlngpqrstuv4xzy8123w56709+0"
    std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    decodeTrans = str.maketrans(my_base64chars, std_base64chars)
    def my_b64decode(s):
        return b64decode(p32(s).decode().translate(decodeTrans).encode())
    return my_b64decode(x)
    
password = [""]*300

for f,i,inp in code:
    if f == 1:
        password[i] = chr(rFunc1(inp))
    elif f == 2:
        password[i] = chr(rFunc2(inp)[0])
        password[i+1] = chr(rFunc2(inp)[1])
    elif f == 3:
        password[i] = rFunc3(inp).decode()
    elif f == 4:
        password[i] = rFunc4(inp).decode()

for p in password:
    print(p, end = "")
```
### Flag
![flag](./flag.jpg)
```
Flag: vcstraining{Aw3s0me_D4ta_tran5Form4t1oN_Kak4}
```
