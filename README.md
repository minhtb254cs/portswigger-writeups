# PortSwigger Web Security Academy — Write-ups

Write-up các lab trên [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs).
Mục tiêu không chỉ là giải được lab, mà hiểu **vì sao lỗ hổng tồn tại**, **vì sao payload hoạt động**, và **cách vá**.

> Mỗi bài viết theo khung trong [`template.md`](template.md): recon → xác nhận → khai thác (3 lớp) → backend giả định → root cause → remediation.

---

## Trạng thái

Chú thích: ✅ Xong · 🔴 Đang làm · ⬜ Chưa làm

| # | Chủ đề | Trạng thái |
|---|--------|:---------:|
| 01 | SQL injection | ⬜ |
| 02 | Authentication | ⬜ |
| 03 | Path traversal | ⬜ |
| 04 | OS command injection | ⬜ |
| 05 | Business logic vulnerabilities | ⬜ |
| 06 | Information disclosure | ⬜ |
| 07 | Access control | ⬜ |
| 08 | File upload vulnerabilities | ⬜ |
| 09 | SSRF | ⬜ |
| 10 | XXE injection | ⬜ |
| 11 | [NoSQL injection](nosql-injection/) | 🔴 |
| 12 | API testing | ⬜ |
| 13 | Cross-site scripting (XSS) | ⬜ |
| 14 | CSRF | ⬜ |
| 15 | CORS | ⬜ |
| 16 | Clickjacking | ⬜ |
| 17 | DOM-based vulnerabilities | ⬜ |
| 18 | WebSockets | ⬜ |
| 19 | Insecure deserialization | ⬜ |
| 20 | GraphQL API vulnerabilities | ⬜ |
| 21 | Server-side template injection (SSTI) | ⬜ |
| 22 | Web cache poisoning | ⬜ |
| 23 | HTTP Host header attacks | ⬜ |
| 24 | HTTP request smuggling | ⬜ |
| 25 | OAuth authentication | ⬜ |
| 26 | JWT attacks | ⬜ |
| 27 | Prototype pollution | ⬜ |

### NoSQL injection (chi tiết)

| Lab | Mức | Trạng thái |
|-----|-----|:---------:|
| [Detecting NoSQL injection](nosql-injection/lab-01-detecting-nosql-injection.md) | Apprentice | ⬜ |
| [Exploiting NoSQL operator injection to bypass authentication](nosql-injection/lab-02-bypass-authentication.md) | Apprentice | ⬜ |
| [Exploiting NoSQL injection to extract data](nosql-injection/lab-03-extract-data.md) | Practitioner | ⬜ |
| [Exploiting NoSQL operator injection to extract unknown fields](nosql-injection/lab-04-extract-unknown-fields.md) | Practitioner | ⬜ |

---

## Cách tổ chức

```
portswigger-writeups/
├── README.md          # file này — bảng mục lục
├── template.md        # khung chuẩn, copy ra mỗi khi viết lab mới
├── assets/            # ảnh chụp màn hình dùng chung
└── nosql-injection/   # mỗi chủ đề một thư mục
    ├── lab-01-....md
    └── ...
```

Thêm chủ đề mới: tạo thư mục theo tên chủ đề, copy `template.md` vào, đổi tên thành `lab-XX-ten-lab.md`, rồi cập nhật trạng thái ở bảng trên.

## Lưu ý trước khi đẩy lên public

- **Che dữ liệu nhạy cảm** trong ảnh/text: lab ID, `session` cookie, token → thay bằng `<LAB-ID>`, `<SESSION>`.
- Cắt mọi dòng lộ danh tính người khác trong ảnh công cụ (ví dụ dòng "licensed to ...").
- **Không đăng** lời giải các kỳ thi có chứng chỉ (BSCP) nếu định thi.

## Quy trình Git cơ bản

```bash
# lần đầu
git clone https://github.com/<username>/portswigger-writeups.git
cd portswigger-writeups

# mỗi lần viết xong một bài
git add .
git commit -m "nosql: add write-up for lab 02 (auth bypass)"
git push
```
