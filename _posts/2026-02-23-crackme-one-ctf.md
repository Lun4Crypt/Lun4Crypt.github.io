---
title: "CrackMeOne CTF 2026"
date: 2026-02-23 20:00:00 +0700
categories: [Reverse]
tags: [ctf, reverse, crackme]
image:
  path: /assets/img/221804609.png
---

# RecordPlayer 
## Tổng quan

Đây là 1 challenge khá thú vị với mình, khi chạy chương trình ta thấy giao diện của 1 trình phát nhạc. Khi nhấn **Play**, chương trình phát một file WAV được nhúng trong resource. Tuy nhiên âm thanh phát ra bị biến dạng. Nhiệm vụ của ta là phải fix sao cho âm thanh được phát đúng và lấy flag. Bài này thì có khá là nhiều hướng giải, nhưng mà mình lười nên mình chỉ giải theo 1 cách và cũng là cách mà mình nghĩ nhanh nhất để solve bài này ><

### Phân tích logic của chương trình

<img width="812" height="376" alt="image" src="https://github.com/user-attachments/assets/e94c8ea0-9945-438c-ad3a-6c6ce6f7c9c2" />

Để ý kĩ hint của tác giả thì mình biết được rằng cả 2 công tắc trên giao diện đều bị hỏng, và mình phải sửa 2 công tắc này hoạt động.
Mình phân tích chương trình bằng IDA, tìm đến hàm xử lý 2 công tắc này
Sau 7749 lần ngồi tìm và đọc code đến khùng =))) thì mình tìm thấy hàm ```sub_140003860``` là hàm xử lý các nút bấm giao diện
```C
case 1001:
      sub_140003C20((void *)(a1 + 88), &unk_14000665A, 0);
      v4 = *(_QWORD *)(a1 + 80);
      if ( *(_BYTE *)(v4 + 28) )
      {
        sub_1400027A0(v4);
      }
      else
      {
        sub_140001F50(v4, 141);
        LOBYTE(v5) = 1;
        sub_140003A00(*(_QWORD *)(a1 + 80), v5);
        LOBYTE(v6) = 1;
        sub_140003A20(*(_QWORD *)(a1 + 80), v6);
        sub_1400020F0(*(_QWORD *)(a1 + 80));
      }
```
Ở đây mình thấy có 2 hàm xử lý 2 công tắc như ở hint đã đề cập là hàm ```sub_140003A20``` và ``` sub_140003A00```, mình sẽ phân tích sâu hơn 2 hàm này để xem chúng được xử lý như nào
#### Phân tích hàm sub_140003A00
Quan sát hàm ta thấy hàm thực hiện biến đổi giá trị từ `0/1` thành `+1/-1`
```c
result = 2 * (a2 ^ 1u) - 1;
```
- Nếu `a2 = 1` 
  → result = -1 (phát ngược)
- Nếu `a2 = 0`    
  → result = +1 (phát xuôi)
Hàm này chỉ quyết định nhạc chạy xuôi hay chạy ngược. Nhìn lại hàm ```sub_140003860```  thì mình thấy chương trình đang truyền giá trị `a2 = 1` dẫn đến việc âm thanh phát ra bị hỏng
#### Phân tích hàm sub_140003A20
Nó đơn giản chỉ là ghi giá trị vào một biến trong struct của player.
```c
*(_BYTE *)(a1 + 29) = a2;
```
- Nếu truyền vào `1` → bật chế độ pitch effect -> âm thanh bị hỏng
- Nếu truyền vào `0` → tắt chế độ đó, âm thanh phát bình thường.
Trong hàm ```sub_140003860```, nó cũng truyền `1`.
=> Kết quả là khi nhấn Play, chương trình đang phát ngược nhạc và bật pitch effect => âm thanh bị hỏng
Vậy ý tưởng ở đây để cho âm thanh chạy đúng và lấy được flag thì ta chỉ cần patch giá trị truyền vào từ 1 -> 0 ở cả 2 hàm
Trước:
```asm
mov     dl, 1
mov     rcx, [rbx+50h]
call    sub_140003A00
mov     dl, 1
mov     rcx, [rbx+50h]
call    sub_140003A20
```
Sau:
```asm
mov     dl, 0
mov     rcx, [rbx+50h]
call    sub_140003A00
mov     dl, 0
mov     rcx, [rbx+50h]
call    sub_140003A20
```
lưu lại và chạy lại chương trình mà mình đã patch thì ta sẽ lấy được flag
<img width="610" height="554" alt="image" src="https://github.com/user-attachments/assets/d9c361c2-3baa-43c8-a796-47a7f5cf5f64" />
```
CMO{y0u_g0t_r1ckr0ll3d}
```
