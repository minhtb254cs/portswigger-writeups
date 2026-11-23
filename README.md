# PortSwigger Web Security Academy — Write-ups

Write-up các lab trên [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs).
Mục tiêu không chỉ là giải được lab, mà hiểu **vì sao lỗ hổng tồn tại**, **vì sao payload hoạt động**, và **cách vá**.

> Mỗi bài viết theo khung: **Mục tiêu → Recon → Exploit → Mô phỏng backend xử lý → Cách vá**, kèm phần hỏi-đáp làm rõ những thắc mắc nảy sinh trong lúc làm.

---

## Trạng thái

Chú thích: ✅ Xong · 🔴 Đang làm · ⬜ Chưa làm

| #   | Chủ đề                                | Trạng thái |
| --- | ------------------------------------- | :--------: |
| 01  | SQL injection                         |     ⬜      |
| 02  | Authentication                        |     ⬜      |
| 03  | Path traversal                        |     ⬜      |
| 04  | OS command injection                  |     ⬜      |
| 05  | Business logic vulnerabilities        |     ⬜      |
| 06  | Information disclosure                |     ⬜      |
| 07  | Access control                        |     ⬜      |
| 08  | File upload vulnerabilities           |     ⬜      |
| 09  | SSRF                                  |     ⬜      |
| 10  | [XXE injection](xxe/)                 |     ✅      |
| 11  | [NoSQL injection](nosql-injection/)   |     ✅      |
| 12  | API testing                           |     ⬜      |
| 13  | Cross-site scripting (XSS)            |     ⬜      |
| 14  | CSRF                                  |     ⬜      |
| 15  | CORS                                  |     ⬜      |
| 16  | Clickjacking                          |     ⬜      |
| 17  | DOM-based vulnerabilities             |     ⬜      |
| 18  | WebSockets                            |     ⬜      |
| 19  | Insecure deserialization              |     ⬜      |
| 20  | GraphQL API vulnerabilities           |     ⬜      |
| 21  | Server-side template injection (SSTI) |     ⬜      |
| 22  | Web cache poisoning                   |     ⬜      |
| 23  | HTTP Host header attacks              |     ⬜      |
| 24  | HTTP request smuggling                |     ⬜      |
| 25  | OAuth authentication                  |     ⬜      |
| 26  | JWT attacks                           |     ⬜      |
| 27  | Prototype pollution                   |     ⬜      |

### XXE injection (chi tiết)

| Lab | Mức | Trạng thái |
|-----|-----|:---------:|
| [01 — Exploiting XXE using external entities to retrieve files](xxe/LAB01.md) | Apprentice | ✅ |
| [02 — Exploiting XXE to perform SSRF attacks](xxe/LAB02.md) | Apprentice | ✅ |
| [03 — Blind XXE with out-of-band interaction](xxe/LAB03.md) | Practitioner | ✅ |
| [04 — Blind XXE with out-of-band interaction via XML parameter entities](xxe/LAB04.md) | Practitioner | ✅ |
| [05 — Exploiting blind XXE to exfiltrate data using a malicious external DTD](xxe/LAB05.md) | Practitioner | ✅ |
| [06 — Exploiting blind XXE to retrieve data via error messages](xxe/LAB06.md) | Practitioner | ✅ |
| [07 — Exploiting XXE to retrieve data by repurposing a local DTD](xxe/LAB07.md) | Practitioner | ✅ |
| [08 — Exploiting XInclude to retrieve files](xxe/LAB08.md) | Practitioner | ✅ |
| [09 — Exploiting XXE via image file upload](xxe/LAB09.md) | Practitioner | ✅ |

### NoSQL injection (chi tiết)

| Lab | Mức | Trạng thái |
|-----|-----|:---------:|
| [01 — Detecting NoSQL injection](nosql-injection/LAB01.md) | Apprentice | ✅ |
| [02 — Exploiting NoSQL operator injection to bypass authentication](nosql-injection/LAB02.md) | Apprentice | ✅ |
| [03 — Exploiting NoSQL injection to extract data](nosql-injection/LAB03.md) | Practitioner | ✅ |
| [04 — Exploiting NoSQL operator injection to extract unknown fields](nosql-injection/LAB04.md) | Practitioner | ✅ |

---

## Cách tổ chức

```
portswigger-writeups/
├── README.md          # file này — bảng mục lục
├── template.md        # khung chuẩn, copy ra mỗi khi viết lab mới
├── assets/            # ảnh chụp màn hình dùng chung
├── xxe/               # mỗi chủ đề một thư mục
│   ├── LAB01.md
│   └── ...
└── nosql-injection/
    ├── LAB01.md
    └── ...
```

Thêm chủ đề mới: tạo thư mục theo tên chủ đề, viết mỗi lab thành `LABxx.md` theo khung **Mục tiêu → Recon → Exploit → Mô phỏng backend xử lý → Cách vá**, rồi cập nhật trạng thái ở bảng trên.

## Lưu ý trước khi đẩy lên public

- **Che dữ liệu nhạy cảm** trong ảnh/text: lab ID, `session` cookie, token → thay bằng `<LAB-ID>`, `<SESSION>` (các lab PortSwigger hết hạn nhanh nên session cũ không còn giá trị).
- Cắt mọi dòng lộ danh tính người khác trong ảnh công cụ (ví dụ dòng "licensed to ...").
- **Không đăng** lời giải các kỳ thi có chứng chỉ (BSCP) nếu định thi.

## Quy trình Git cơ bản

```bash
# lần đầu
git clone https://github.com/minhtb254cs/portswigger-writeups.git
cd portswigger-writeups

# mỗi lần viết xong một bài
git add .
git commit -m "nosql: add write-up for lab 02 (auth bypass)"
git push
```
