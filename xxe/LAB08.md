![](../assets/Pasted%20image%2020261121083753.png)
# 1. Mục tiêu
Khai thác tính năng "Check stock" để đọc file /etc/passwd. Điểm khác biệt lớn nhất so với tất cả các lab trước: request lần này **không hề giống XML**. Body gửi lên là dạng `application/x-www-form-urlencoded` (`productId=1&storeId=1`), nhìn qua chẳng có dấu vết gì của XML. Đây chính là khái niệm **hidden attack surface** (bề mặt tấn công ẩn): XXE không chỉ nằm ở những request XML lộ liễu, mà ẩn ở mọi chỗ dữ liệu bị xử lý như XML dù không hiển nhiên.

Bản chất ở đây: app nhận một mẩu dữ liệu từ client (`productId`), rồi **nhúng nó vào một tài liệu XML lớn hơn ở backend** (thường là SOAP request) trước khi đem đi parse. Mình chỉ kiểm soát **một trường giá trị nằm sâu trong thân tài liệu**, không kiểm soát được cả tài liệu.

Hệ quả: XXE kinh điển **tắc**. Vì XXE kinh điển cần khai `<!DOCTYPE ... <!ENTITY ...>>`, mà theo luật XML, `DOCTYPE` bắt buộc phải nằm ở **đầu tài liệu, trước thẻ gốc**. Trường `productId` của mình nằm sâu bên trong → không có cách nào chèn `DOCTYPE` vào đúng chỗ → không khai entity được.

# 2. Recon
Vẫn là chức năng Check Stock quen thuộc. Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request.

```http
POST /product/stock HTTP/2
Host: 0ae8003304a2b07a808c4ef7009c00b2.web-security-academy.net
Cookie: session=cYQKVsIBdeEt9d0MkTT9MMtWyeGKEYV4
Content-Length: 21
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://0ae8003304a2b07a808c4ef7009c00b2.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ae8003304a2b07a808c4ef7009c00b2.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

productId=1
&storeId=1
```

Khác hẳn LAB01–07: `Content-Type` là `application/x-www-form-urlencoded`, body chỉ là cặp key-value. Nhưng vì đề bài gợi ý đây là lab XXE, suy ra server **nhận `productId` rồi tự nhét vào một khung XML ở backend** để xử lý check stock. Mình không thấy XML, nhưng XML vẫn tồn tại — ở phía server. Giá trị `productId` chính là trường duy nhất mình kiểm soát được trong tài liệu XML đó.

# 3. Exploit
Vì không chèn được `DOCTYPE`, ta dùng **XInclude**. XInclude là một phần của chuẩn XML dùng để ghép tài liệu từ các mảnh con. Mấu chốt: nó là một **element bình thường, đặt được ở bất kỳ đâu trong thân tài liệu → không cần `DOCTYPE`**.

Chèn payload vào đúng trường `productId` mình kiểm soát:

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
&storeId=1
```

Giải thích từng phần:
- `xmlns:xi="http://www.w3.org/2001/XInclude"` — khai báo namespace XInclude để parser nhận ra thẻ `xi:include`.
- `href="file:///etc/passwd"` — nguồn cần chèn, vẫn dùng scheme `file://` để đọc file trên server.
- `parse="text"` — chèn nội dung dưới dạng **văn bản thuần**. Nếu để `parse="xml"` thì parser sẽ cố parse `/etc/passwd` như một tài liệu XML → hỏng ngay (file này đâu phải XML).

**Cơ chế hai tầng ghép** (điểm hay nhất của lab này):
- **App ghép (nối chuỗi):** input của mình bị server nối vào khung XML → cả cụm element `xi:include` lọt vào bên trong tài liệu XML server-side.
- **Parser ghép (XInclude processing):** khi parse, parser quét tài liệu, gặp mỗi `xi:include` thì thay nó bằng nội dung mà `href` trỏ tới → nội dung `/etc/passwd` được inline thẳng vào tài liệu, rồi phản chiếu ra response.

![](../assets/Pasted%20image%2020261123095154.png)![](../assets/Pasted%20image%2020261123095211.png)

Nội dung /etc/passwd hiện ra trong response. Khai thác thành công, hoàn thành lab.

> **Mục đích gốc của XInclude là gì?** Vẫn là câu chuyện trust boundary quen thuộc. XInclude sinh ra để **ghép một tài liệu XML từ nhiều mảnh** — sách chia theo chương, chèn code mẫu bằng `parse="text"`, tái dụng boilerplate. So với external entity, nó tiện hơn ở chỗ: không cần DTD, chèn được fragment, lại có cơ chế fallback. Một tính năng tử tế, chỉ hóa thành vũ khí khi bị bật trên dữ liệu không tin cậy. Phòng chống gọn nhất: **tắt xử lý XInclude**.

# 4. Mô phỏng backend xử lý
```java
// [LỖI 1] — server nhận field dạng form, tự nhúng vào khung XML server-side bằng nối chuỗi
String productId = request.getParameter("productId");   // input của attacker
String storeId   = request.getParameter("storeId");
String xml = "<?xml version=\"1.0\"?>"
           + "<stockCheck><productId>" + productId + "</productId>"   // xi:include lọt vào thân
           + "<storeId>" + storeId + "</storeId></stockCheck>";

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setXIncludeAware(true);                              // [LỖI 2] — bật xử lý XInclude
dbf.setExpandEntityReferences(true);
Document doc = dbf.newDocumentBuilder().parse(
        new InputSource(new StringReader(xml)));        // xi:include được thay bằng nội dung /etc/passwd ở đây
```

Hai cái sai cùng lúc: (1) nhét thẳng input chưa kiểm tra vào tài liệu XML bằng nối chuỗi, và (2) bật xử lý XInclude trên tài liệu chứa dữ liệu không tin cậy.

# 5. Cách vá
```java
// Cách 1: tắt XInclude (mặc định đã tắt — đừng bật lên)
dbf.setXIncludeAware(false);

// Cách 2 (gốc rễ): đừng dựng XML bằng nối chuỗi — build cây có kiểm soát để giá trị được escape
Document doc = dbf.newDocumentBuilder().newDocument();
Element root = doc.createElement("stockCheck");
Element pid  = doc.createElement("productId");
pid.setTextContent(productId);                           // giá trị được escape an toàn, không thành markup
root.appendChild(pid);
```

Nguyên tắc: không ghép input của người dùng vào tài liệu XML bằng nối chuỗi; nếu buộc phải, hãy escape/validate chặt (ví dụ `productId` chỉ cho phép số). Tắt hoàn toàn xử lý XInclude nếu ứng dụng không thực sự cần. Và như mọi lab trước, hạn chế tối đa quyền của tiến trình, không để parser đọc được file hệ thống nhạy cảm.
