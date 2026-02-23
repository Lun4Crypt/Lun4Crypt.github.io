---
title: "CrackMeOne CTF 2026 - RecordPlayer Writeup"
date: 2026-02-23 20:00:00 +0700
categories: [Reverse]
tags: [ctf, reverse, crackme]
image:
  path: /assets/img/221804609.png
---

# 🎧 RecordPlayer – Reverse Writeup

> _“When the music plays correctly, the truth reveals itself.”_

---

# 🧠 Challenge Overview

RecordPlayer mô phỏng một trình phát nhạc với các nút điều khiển bị “hỏng”.  

Khi nhấn **Play**, chương trình phát một file WAV được nhúng trong resource.  
Tuy nhiên:

- Âm thanh bị phát **ngược**
- Pitch bị **biến dạng**
- Flag không xuất hiện

💡 Khi âm thanh được phát **đúng cách**, chương trình sẽ sinh ra flag.

---

# 🔍 High-Level Analysis

Luồng xử lý chính:

```
PCM Stream
   ↓
Direction Control (Forward / Reverse)
   ↓
Pitch Toggle (Raw / Interpolated)
   ↓
Sliding Window (23 bytes)
   ↓
XOR với Key
   ↓
FNV-1a Hash Check
   ↓
Nếu hash khớp → In Flag
```

Ta có 2 hướng tiếp cận:

1. 🐍 Giải offline bằng Python
2. 🩹 Patch trực tiếp binary

---

# 🧩 Phân tích chi tiết

---

## 1️⃣ Direction Control – `sub_140003A00`

```cpp
__int64 __fastcall sub_140003A00(__int64 a1, unsigned __int8 a2)
{
    __int64 result;
    result = 2 * (a2 ^ 1u) - 1;
    *(_DWORD *)(a1 + 24) = result;
    return result;
}
```

### Công thức

```
direction = 2 * (a2 ^ 1) - 1
```

### Bảng giá trị

| a2 | direction | Ý nghĩa |
|----|-----------|----------|
| 0  | 1         | Đọc xuôi |
| 1  | -1        | Đọc ngược |

⚠ Khi nhấn PLAY mặc định:

```
a2 = 1 → direction = -1
```

→ Âm thanh bị phát ngược.

---

## 2️⃣ Pitch Toggle – `sub_140003A20`

| Giá trị | Hành vi |
|----------|----------|
| 1 | Bật nội suy (âm thanh méo) |
| 0 | Đọc raw PCM |

⚠ PLAY mặc định truyền giá trị `1`

→ Âm thanh bị biến dạng.

---

## 3️⃣ Core Logic – `sub_140002310`

Chương trình thực hiện kiểm tra flag bằng cơ chế:

### 🔹 Sliding Window (23 bytes)

- Trượt trên luồng PCM
- Mỗi byte đưa vào ring buffer

### 🔹 XOR với key

```
candidate[i] = window[i] ^ key[i]
```

### 🔹 Kiểm tra Hash

Thuật toán: **FNV-1a 32-bit**

Expected hash:

```
0x18940A3D
```

Khi hash khớp → callback hiển thị flag.

---

# 🐍 Cách 1 – Giải Offline

## Hàm FNV-1a

```python
def fnv1a_32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xffffffff
    return h
```

---

## Script tìm flag

```python
with open("pcm.bin", "rb") as f:
    pcm = f.read()

key = bytes([
    0x30, 0x2B, 0x3D, 0xFC, 0xF6, 0xB6, 0x06, 0x3B,
    0x0E, 0xB1, 0xED, 0xC0, 0xE1, 0x48, 0x07, 0x0C,
    0x0B, 0xBB, 0xF4, 0xF9, 0x48, 0x01, 0x19
])

expected_hash = 0x18940A3D

for i in range(len(pcm) - 23 + 1):
    window = pcm[i:i+23]
    candidate = bytes(window[j] ^ key[j] for j in range(23))

    if fnv1a_32(candidate) == expected_hash:
        print(f"[+] Found at Offset: {i}")
        print(f"[+] Flag: {candidate.decode()}")
        break
```

---

# 🩹 Cách 2 – Patch Binary

Thay vì brute offline, ta có thể ép chương trình tự in flag.

---

## ✂ Sửa Direction

Tìm:

```
sub_140003A00(..., 1)
```

Sửa thành:

```
sub_140003A00(..., 0)
```

→ direction luôn = 1 (đọc xuôi)

---

## ✂ Tắt Pitch

Tìm:

```
sub_140003A20(..., 1)
```

Sửa thành:

```
sub_140003A20(..., 0)
```

→ Đọc raw PCM

---

## 🚀 Sau khi patch

- PCM đọc xuôi
- Không bị méo
- Sliding window khớp hash
- Callback in flag được trigger

---

# 🎯 Final Result

```
Offset: 132300
Flag: CMO{y0u_g0t_r1ckr0ll3d}
```

---

