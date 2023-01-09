# HiddenTreasure writeup
## Analysis with IDA
Đầu tiên, mở file zip ta có được 2 file: 1 file .bmp (file ảnh được hiện thị bằng cách bit lưu trữ - bitmap) và 1 file .exe.
Ném vào IDA phân tích mã giả C của chương trình, ta thấy chương trình lấy input là ảnh và chuỗi string để chèn thông tin và giấu vào ảnh. 
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // kr00_4
  HANDLE FileW; // eax
  void *v5; // ebx
  HANDLE FileMappingW; // eax
  void *v8; // esi
  _BYTE *v9; // ebx
  unsigned int v10; // eax
  unsigned int v11; // esi
  char v12; // cl
  const void *v13; // edi
  DWORD v14; // edx
  unsigned int v15; // ebx
  int v16; // ecx
  char *v17; // eax
  int v18; // edx
  int v19; // eax
  int v20; // edi
  int v21; // edx
  char v22; // al
  HANDLE v23; // [esp+4h] [ebp-128h]
  HANDLE hObject; // [esp+8h] [ebp-124h]
  int v25; // [esp+Ch] [ebp-120h]
  char *v26; // [esp+10h] [ebp-11Ch]
  int v27; // [esp+14h] [ebp-118h]
  char *lpBaseAddress; // [esp+18h] [ebp-114h]
  _BYTE *v29; // [esp+1Ch] [ebp-110h]
  DWORD FileSize; // [esp+20h] [ebp-10Ch]
  int v31; // [esp+20h] [ebp-10Ch]
  unsigned int v32; // [esp+24h] [ebp-108h]
  int v33; // [esp+24h] [ebp-108h]
  char Dest[256]; // [esp+28h] [ebp-104h] BYREF

  if ( argc == 3 )
  {
    memset(Dest, 0, sizeof(Dest));
    wcstombs(Dest, (const wchar_t *)argv[2], 0x100u);     //argv[2]: string
    v3 = strlen(Dest);
    if ( v3 )
    {
      FileW = CreateFileW((LPCWSTR)argv[1], 0xC0000000, 1u, 0, 3u, 0x80u, 0);     //argv[1]: ảnh
      v5 = FileW;
      v23 = FileW;
      if ( FileW != (HANDLE)-1 )
      {
        FileSize = GetFileSize(FileW, 0);
        if ( FileSize == -1
          || (FileMappingW = CreateFileMappingW(v5, 0, 4u, 0, 0, 0), v8 = FileMappingW, (hObject = FileMappingW) == 0) )
        {
          CloseHandle(v5);
          return 0;
        }
        lpBaseAddress = (char *)MapViewOfFile(FileMappingW, 6u, 0, 0, 0);
        if ( lpBaseAddress )
        {
          v9 = malloc(8 * v3);
          v10 = 0;
          v29 = v9;
          v11 = 0;
          v32 = 0;
          do
          {
            v12 = Dest[v10];
            v9[v11] = v12 & 1;
            v9[v11 + 1] = (v12 >> 1) & 1;
            v9[v11 + 2] = (v12 >> 2) & 1;
            v9[v11 + 3] = (v12 >> 3) & 1;
            v9[v11 + 4] = (v12 >> 4) & 1;
            v9[v11 + 5] = (v12 >> 5) & 1;
            v9[v11 + 6] = (v12 >> 6) & 1;
            v10 = v32 + 1;
            v9[v11 + 7] = (v12 >> 7) & 1;
            v11 += 8;
            v32 = v10;
          }
          while ( v10 < v3 );       //Tách các bit của input string và lưu vào mảng
          v13 = lpBaseAddress;
          if ( *(_WORD *)lpBaseAddress == 'MB' && FileSize >= *(_DWORD *)(lpBaseAddress + 2) )  //Check signature của file .bmp rồi thực hiện kỹ thuật giấu tin vào ảnh
          {
            v14 = *(_DWORD *)(lpBaseAddress + 10);
            if ( v14 < FileSize && v11 < *(_DWORD *)(lpBaseAddress + 34) )
            {
              v15 = 0;
              v16 = *(_DWORD *)(lpBaseAddress + 18);
              v27 = *(_DWORD *)(lpBaseAddress + 22);
              v17 = &lpBaseAddress[v14];
              v18 = 0;
              v25 = v16;
              v26 = v17;
              *((_WORD *)lpBaseAddress + 3) = v11;
              v33 = 0;
              if ( v11 )
              {
                v19 = 0;
                v31 = 0;
                do
                {
                  if ( v18 >= v27 )
                    break;
                  v20 = 0;
                  if ( v15 < v11 )
                  {
                    do
                    {
                      if ( v20 >= v16 )
                        break;
                      v21 = v19 + v20++;
                      v22 = v29[v15++];
                      v26[2 * v21 + v21] = v22;
                      v19 = v31;
                      v16 = v25;
                    }
                    while ( v15 < v11 );
                    v18 = v33;
                  }
                  ++v18;
                  v19 += 3 * v16;
                  v33 = v18;
                  v31 = v19;
                }
                while ( v15 < v11 );
                v13 = lpBaseAddress;
              }
              v9 = v29;
            }
          }
          free(v9);
          UnmapViewOfFile(v13);
          CloseHandle(hObject);
          CloseHandle(v23);
        }
        else
        {
          CloseHandle(v8);
          CloseHandle(v5);
        }
      }
    }
  }
  return 0;
}
```
Chương trình kiểm tra header file và size có phù hợp để chèn chuỗi vào ảnh không rồi sau đó chèn các bit từ bitmap và chèn chúng vào phần data của ảnh
## Script to get flag
```
from pwn import u32
#python3
#open file inside-the-mind-of-a-hacker-memory.bmp for reading
f = open("inside-the-mind-of-a-hacker-memory.bmp", "rb")
#read the file
data = f.read()
binaryString = ""
#raster data offset
rasterOffset = u32(data[10:14])
widthSize = u32(data[18:22])
heightSize = u32(data[22:26])
#data
data = data[rasterOffset:]
v19 = 0
count = 0
i = 0
while count < 256*8:
    if(i >= heightSize):
        break
    j = 0
    while count < 256*8:
        if(j >= widthSize):
            break
        pj = v19 + j
        j += 1
        binaryString += str(data[2*pj +pj])
        count += 1
    i += 1
    v19 += 3*widthSize

#convert binary string to string
flag = ""
for i in range(0, len(binaryString), 8):
    try:
        flag += chr(int("".join(reversed(binaryString[i:i+8])), 2))
    except:
        break
#print "here is your flag: " + flag
print("flag:"+flag)
```
```
Flag: flag{dont_forget_the_treasure}
```
