# TongjiCTF 2022 write up

## Misc

### 签到

根据提示，在网站首页源码中找到注释
```html
<!-- tjctf{GO0D_lUck_h@ve_fun_2022} -->
```
得到 flag 为 `tjctf{GO0D_lUck_h@ve_fun_2022}`。

### 放风

根据题目，得知附件为 GPS 记录。使用 [GPS Visualizer](https://www.gpsvisualizer.com/draw/)，上传 GPS 记录，得到 GPS 图像：

![gps_pic](https://github.com/SiuKam/TongjiCTF-2022-Write-Up/blob/main/gps_pic.png)

得到 flag 为 `tjctf{grld}`。

### basic

根据附件的文件头 `**TI83F*` 得知附件为德州仪器 TI-83 计算器的文件。根据[资料](http://merthsoft.com/linkguide/ti83+/fformat.html)提供的文件格式，`0x3B` 位的值 `05` 表明该文件为 TI-83 中的程序。`0x48-0x87` 位为该程序编码后的内容，可根据[网站](http://merthsoft.com/linkguide/ti83+/tokens.html)提供的 Tokens and Character Codes 逐步转译。但是更简便的方法应该是使用 TI-83 计算器（或者模拟器）直接打开，这里使用模拟器，打开附件程序后如下图所示：

![ti_83_basic](https://github.com/SiuKam/TongjiCTF-2022-Write-Up/blob/main/ti_83_basic.png)

得到 flag 为 `tjctf{hE1L0_Fr0M_7i_8as1C}`。

### 你码红了

扫描给出的图片，得到 `never gonna give you up`。

binwalk 分析，可看到 png 后还有附加文件：

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1080 x 2400, 8-bit/color RGBA, non-interlaced
64            0x40            Zlib compressed data, best compression
6563          0x19A3          Zlib compressed data, default compression
10374         0x2886          Zlib compressed data, best compression
530944        0x81A00         POSIX tar archive (GNU), owner user name: ".shanghai.metro.xcf"
```

将附加的 `xcf` 文件提取出来，使用 GIMP 打开，即可看到隐藏的红码：

![red_qr](https://github.com/SiuKam/TongjiCTF-2022-Write-Up/blob/main/red_qr.png)

解析之后得到字符串 `Bztrcw{WD^kYf}ifM*o2v>ZqZuV^Sdpg){Qnm=c$dK]i*zz><smo1q6uQeNHEe`。根据提示`编码方法变种 safe in source code`，搜索得到 `Z85` 编码方法，解码后得到 flag 为 `tjctf{Sc@n_Y0uR_c0De_u$iNg_tHe_F**k1n6_mETrO_@pp}`。


### Old Typer

根据提示`打字机的节奏很重要`，使用 Wireshark 抓包后将服务器发包时间导出，算得发包间隔（见下图）。

![typer_bar](https://github.com/SiuKam/TongjiCTF-2022-Write-Up/blob/main/typer_bar.png)

可见发包间隔明显分为长、中、短三类，且特征为每两次长间隔中间最多有 6 次中/短间隔，猜测为摩斯电码。将长间隔作为分隔符，中间隔作为 dash，短间隔作为 dot，得到摩斯电码：

>.--  -- ..- .-.-.- ..-. --- ..- -. -.. .-.-.- .. - .-.-.- - .--- -.-. - ..-. -.--. ----- .-.. -.. ..--.- - -.-- .--..-...-- . . ..--.- -. ...-- . -.. ..--.- .-. . --- .. .---- -.--.- .-. .- .-. . .--. .-.. .- -.-. . .-.-.- .--. .- .-. . -. - .... . ... . ... .-.-.- .-- .. - .... .-.-.- -.-. ..- .-. .-.. -.-- . .-.- -... .-. .- -.-. -.- . - ... .-.-.- .- -. -.. .-.-.- .- .-.. .-.. .-.-.- .. -. .-.-.- ..- .--. .--. . .-. .-.-.- -.-. .  ... ..

解码后得到原文：

>WMU.FOUND.IT.TJCTF(0LD_TY#EE_N3ED_REOI1)RAREPLACE.PARENTHESES.WITH.CURLYEÄBRACKETS.AND.ALL.IN.UPPER.CESI

但是由于该方法受网络影响较大，单次尝试无法得到正确 flag，多次尝试后拼凑得到 flag 为 `tjctf{0ld_typ3r_n3ed_reoi1}`。

## Cryto

### XXXX64

根据题目与提示，得知应与 BASE64 编码有关。根据程序中给出的密文 `c = BV2Jf1jnIVa+IVjE7=lnTjelov66` ，联想 BASE64 编码后尾部可能带等号的特性，猜测程序中将 `=` 加密为 `6`，得到 `key = 7`，编写程序解密文：

```python
from base64 import *
from Crypto.Random import random
# from secret import flag

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

codedFlag = 'BV2Jf1jnIVa+IVjE7=lnTjelov66'
key = 7
decodedFlag = ''
for ch in codedFlag:
    codedIndex = alphabet.find(ch)
    for i in range(65):
        if (key * i) % 65 == codedIndex:
            decodedIndex = i
            decodedFlag += alphabet[decodedIndex]
            break

print(decodedFlag)
```

得到原文为 `cDR5X2F0dDNudDFvbl90MF89PQ==` ，BASE64 解码后得到 flag 为 `tjctf{p4y_att3nt1on_t0_==}`。

### GhostFromThePast

根据附件中大量的 A 与 B，猜测使用培根密码使用加密，解密后得到原文：

>THE CTF COMPETITION COVERS A WIDE RANGE OF FIELDS AND HAS A COMPLEX CONTENT AT THE SAME TIME THE DEVELOPMENT OF SECURITY TECHNOLOGY IS GETTING FASTER AND FASTER AND THE DIFFICULTY OF CTF IS GETTING HIGHER AND HIGHER THE THRESHOLD FOR BEGINNERS IS GETTING HIGHER AND HIGHER MOST OF THE ONLINE INFORMATION IS SCATTERED AND TRIVIAL BEGINNERS OFTEN DON T KNOW HOW TO SYSTEMATICALLY LEARN THE KNOWLEDGE OF CTF RELATED FIELDS OFTEN TAKING A LOT OF TIME AND SUFFERING SYNT LBATTNAAVHAVHOHCNGVNBMUNA

得到 `SYNT LBATTNAAVHAVHOHCNGVNBMUNA`，猜测为移位密码，尝试 ROT13 解密得到 `FLAG YONGGANNIUNIUBUPATIAOZHAN`，得到 flag 为 `tjctf{YONGGANNIUNIUBUPATIAOZHAN}`。

## ONIST

### 同济大学猫咪问答

第一问，查去年[新闻](https://news.tongji.edu.cn/info/1003/77905.htm)得到`刘孔阳`。

第二问，依稀记得是 `Gitty RSA`。

第三问，[Cat Training Force](https://github.com/Cat-Training-Force)。

第四问，查看[存档](https://github.com/Cat-Training-Force/Tongji-CTF-2021/blob/master/Reverse/Endless/wp/endless.c)，得到 `247`。

第五问，查看[存档](https://github.com/brant-ruan/TongjiCTF-2017)，得到 `21`。

第六问，`广楼`。

得到 flag 为 `tjctf{0ce1f560a60afffd456895f006fc42ad22157d00105f4d585f5b06170edb7f5e}`。

## Web

### 天狗的旗子

使用 `dirb` 命令扫描网站，得到：

```
---- Scanning URL: http://10.10.175.100:38089/ ----
+ http://10.10.175.100:38089/flag (CODE:200|SIZE:20)                                                       
+ http://10.10.175.100:38089/robots.txt (CODE:200|SIZE:58) 
```

访问 `/flag` 得到假 flag，访问 `/robots.txt`，得到新路径提示 `/feasgsdrgvsefzergvsdfvsvgswgewrf`，访问得到提示 `only localhost can access`。使用 Burp 构建请求头，增加字段 `X-Forwarded-For: localhost`，发送后得到 flag 为 `tjctf{fORW@Rd_Y0ur_f1a6}`。

## IoT

### Something In The Channel 

根据提示，使用 PulseView 按 UART 协议、波特率 115200 对文件中的 D0 与 D1 两个通道进行解码，得到 D0 的内容如下：

>Hello! Do you want to go out with me to see the cats?
Sorry to hear that... Oh last time I forgot to tell you the first part of the flag. It should be `tjctf{I_w4nt_T0_5hAr3_`.
Well, I hope the epidemic will end as soon as possible. See you!

得到 flag 的第一部分 `tjctf{I_w4nt_T0_5hAr3_`。

对 D1 解码出来的内容进行 binwalk 分析，提示存在包含 png 图像的 zip 包：

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
123           0x7B            Zip archive data, at least v2.0 to extract, compressed size: 296327, uncompressed size: 309144, name: 2.png
296572        0x4867C         End of Zip archive, footer length: 22
```

提取得到一张猫图：

![IoT_cat](https://github.com/SiuKam/TongjiCTF-2022-Write-Up/blob/main/IoT_cat.png)

使用 `Stegsolve.jar` 程序对猫图进行分析，在 `Blue plane 0` 通道中发现二维码，解析后得到 flag 的第二部分 `cu7e_C@ts_W17h_y0u}`。拼接得到完整 flag `tjctf{I_w4nt_T0_5hAr3_cu7e_C@ts_W17h_y0u}`。
