<!--
  TEMPLATE — copy file này ra mỗi khi viết một lab mới.
  Xóa hết các comment <!-- ... --> sau khi điền xong.
  Không bắt buộc đủ mọi mục: lab Apprentice đơn giản có thể bỏ "Biến thể" và "Phòng thủ".
  Ngôn ngữ: viết tiếng Việt hay tiếng Anh tùy bạn; nếu dùng cho CV quốc tế thì cân nhắc tiếng Anh.
-->

# [Tên lab]

| | |
|---|---|
| **Chủ đề** | <!-- NoSQL injection --> |
| **Mức độ** | <!-- Apprentice / Practitioner / Expert --> |
| **Link** | <!-- https://portswigger.net/web-security/... --> |
| **Công cụ** | <!-- Burp Repeater, Intruder, ... --> |

## Mục tiêu

<!-- Diễn đạt lại mục tiêu lab bằng lời của bạn, đừng copy nguyên văn tiếng Anh. -->

## 1. Recon & giả thuyết

<!--
  Bạn đã khám phá ứng dụng thế nào? Chức năng/endpoint nào khả nghi?
  Giả thuyết ban đầu: tham số nào có thể đi vào query, kiểu injection nào?
-->

## 2. Phát hiện & xác nhận lỗ hổng

<!--
  Payload thử nghiệm đầu tiên + phản hồi của server.
  Quan trọng: có CẶP đúng/sai làm mốc để chứng minh mình điều khiển được logic.
  Ví dụ một điều kiện SAI và một điều kiện ĐÚNG, cho thấy phản hồi khác nhau.
-->

```http
<!-- request trích từ Burp, chỉ giữ phần liên quan -->
```

## 3. Khai thác

<!--
  Mỗi bước trình bày 3 lớp:
  - Gửi gì (payload)
  - Query biến thành gì (truy vấn giả định phía server)
  - Vì sao phản hồi khác nhau => kết luận
  Nếu thử sai, ghi lại cả lần sai và lý do — đó là phần giá trị nhất.
-->

### Bước 1: ...

```http

```

**Query giả định:** `...`
**Vì sao chạy:** ...

## 4. Backend giả định

<!--
  Tự viết 5-6 dòng code server CÓ lỗ hổng mà bạn đoán.
  Viết được dòng này nghĩa là bạn thật sự hiểu, không chỉ copy payload.
-->

```javascript

```

## 5. Root cause

<!-- Nguyên nhân gốc: nối chuỗi input? nhận object thay cho string? bật JS phía server? -->

## 6. Remediation

<!--
  Cách vá CỤ THỂ, không viết "validate input".
  Ví dụ: ép kiểu dữ liệu, tắt $where/mapReduce, dùng ODM có schema, phân quyền DB tối thiểu.
  Nêu rõ: cách vá nào chặn được payload của bạn, cách nào không.
-->

- ...

## 7. Bài học

<!-- 1-3 câu: điểm mới học được, biến thể cần nhớ, mẹo công cụ. -->

<!-- ===== CÁC MỤC NÂNG CAO (tùy chọn, chỉ làm cho lab tâm đắc) ===== -->

<!--
## 8. Biến thể khó hơn
  - Nếu server không trả thông báo lỗi khác nhau? => blind time-based
  - Nếu có WAF chặn ký tự đặc biệt / $where?
  - Nếu $regex bị lọc? => dùng $gt/$lt dò nhị phân

## 9. Góc phòng thủ & tác động thực tế
  - Blue team phát hiện vụ này trong log thế nào?
  - Một CVE / bug bounty report thật cùng lớp lỗi (tóm tắt 2-3 câu).

## 10. Tự động hóa
  - Script Python thay cho thao tác tay trên Intruder.
-->
