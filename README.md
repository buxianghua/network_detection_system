# 基于snort、barnyard2和base的 网络入侵检测系统的部署与应用

目 录

[1、项目分析	4](#_Toc43626113)

[1.1、项目背景	4](#_Toc43626114)

[1.2、需求分析	4](#_Toc43626115)

[1.3、Snort体系分析	4](#_Toc43626116)

[1.4、Snort三种工作模式	5](#_Toc43626117)

[2、概要设计	5](#_Toc43626118)

[2.1、Snort功能介绍	5](#_Toc43626119)

[2.2、入侵检测模块分析	6](#_Toc43626120)

[2.3、Snort工作流程分析	6](#_Toc43626121)

[2.4、ADODB功能分析	7](#_Toc43626122)

[2.5、snort组件分析	7](#_Toc43626123)

[2.4、安装准备	7](#_Toc43626124)

[3、详细设计	8](#_Toc43626125)

[3.1、准备工作	8](#_Toc43626126)

[3.1.1、安装wget	9](#_Toc43626127)

[3.1.2、更新yum源	9](#_Toc43626128)

[3.1.3、安装epel源	10](#_Toc43626129)

[3.1.4、下载安装配置文件	10](#_Toc43626130)

[3.2、安装配置LMAP	10](#_Toc43626131)

[3.2.1、安装LAMP组件	10](#_Toc43626132)

[3.2.2、安装php插件	10](#_Toc43626133)

[3.2.3、安装pear插件	11](#_Toc43626134)

[3.2.4、安装adodb	11](#_Toc43626135)

[3.2.5、安装base	11](#_Toc43626136)

[3.2.6、设置目录权限	11](#_Toc43626137)

[3.2.7、配置mysql	11](#_Toc43626138)

[3.3、配置base	12](#_Toc43626139)

[3.4、安装配置snort	15](#_Toc43626140)

[3.4.1、安装依赖包	15](#_Toc43626141)

[3.4.2、安装libdnet	16](#_Toc43626142)

[3.4.3、安装libcap	16](#_Toc43626143)

[3.4.4、安装DAQ	17](#_Toc43626144)

[3.4.5、安装snort	18](#_Toc43626145)

[3.4.6、配置snort	19](#_Toc43626146)

[3.4.7、配置规则库	20](#_Toc43626147)

[3.5、安装barnyard2	21](#_Toc43626148)

[3.5.1、配置barnyard2	21](#_Toc43626149)

[4、部署测试	22](#_Toc43626150)

[4.1、测试snort	22](#_Toc43626151)

[4.2、测试barnyard2	23](#_Toc43626152)

[4.3、测试IDS	25](#_Toc43626153)

[4.3.1、添加测试规则	25](#_Toc43626154)

[4.3.2、测试运行	25](#_Toc43626155)

[4.3、配置IDS启动脚本	27](#_Toc43626156)

[4.4、启动IDS	28](#_Toc43626157)

[4.5、测试IDS	28](#_Toc43626158)

[4.6、停止IDS服务	34](#_Toc43626159)

[5、项目总结	34](#_Toc43626160)

# 1、项目分析

### 1.1、项目背景

伴随着互联网产业的不迅猛发展，新兴技术层数不穷，互联网通讯技术逐渐成为了各行各业不可替代的基础设施，越来越多的业务都是依靠互联网来得以实现。随着我国科技产业的飞速发展，很多过去无法想象的事物变成了现实，由计算机衍生的人工智能等一系列高新技术，以不可阻挡的势头影响着人们的生活，这一切的一切都离不开互联网的支撑，人们享受网络带来的便捷与畅快的同时，也不得不面对网络入侵者对网络安全所带来的威胁，近些年网络飞速发展的同时，信息安全问题也显得日益突出，人们对隐私保护的意识逐渐增强，因此计算机网络安全问题日益成为了社会各界所关注的热点。拥有一个完备可靠的网络安全攻防系统以是个人、企业乃至国家所不懈追寻的目标。

### 1.2、需求分析

在互联网飞速发展的当下社会，信息安全问题尤为突出，任何试图破坏网络活动正常化的事件都可成为网络安全问题。在网络安全问题产生的早期，人们通常使用的方法就是防火墙，但随着网络攻击技术手段的不断提升，传统的防火墙作为一种被动的防御性网络安全工具，已经不足以防御新型的网络攻击。这种情况下逐渐诞生了网络入侵检测系统，入侵检测系统不仅能够为网络安全提供及时的入侵检测以及采取响应防护手段，还可以正确识别针对计算机网络的恶意行为，并为此做出响应和防护机制。它提供对系统内部攻击和外部攻击以及错误操作的实时防护，能够自主的应对网络攻击，良好的弥补了传统防火墙的不足，有效的完善了网络安全的防护机制，入侵检测及时做一种防御手段，已经成为网络安全体系的重要组成部分。因此掌握网络入侵检测系统的部署与应用以是计算机从业人员不可缺少的知识技能。

### 1.3、Snort体系分析

IDS是计算机的入侵监视系统，它通过实时的监视，对异常的网络行为发出警报。入侵检测系统大致可分为两大类，信息来源一类是基于主机IDS的基于网络的IDS，检测方法一类是针对异常入侵检测和误用的入侵检测。Snort
IDS(入侵检测系统)既是一个强大的网络入侵检测系统。它具有实时数据流量分析和记录IP数据网络数据包的能力，能够进行协议分析，对数据包内容进行识别，检测不同的攻击方式，对攻击进行实时监控和报警。此外，Snort是一个开源的入侵检测系统，具有很好的移植性和可扩展性。Barnyard2作为IDS的前端工具，主要应用是读取sonrt产生的数据并存储到数据库中，同时base的页面变化，来测试应用成果与否。

![](media/e872e134de1e2438609a1d77041eaee7.png)

Snort结构由四大模块组成，分别是：

1.  数据包嗅探模块，负责监听网络数据包，对网络进行分析。

2.  预处理模块，用相应的插件来检查原始的数据包，数据包预处理后传送到检测引擎。

3.  检测模块，是Snort的核心模块；检测引擎根据预先设置的规则检测数据包，一旦发现规则匹配，就通知警报模块。

4.  警报/日志模块，经过检测引擎检测后数据输出。如果出现异常则会发出报警

### 1.4、Snort三种工作模式

1.  侦测模式：snort将在现有的网域内获取数据包，并显示在屏幕上。

2.  数据包记录模式：snort将已截取的数据包存入存储硬盘中。

3.  上线模式：snort可对截取到的数据包做分析的动作，并根据一定的规则来判断是否有网络攻击行为的出现。

# 2、概要设计

### 2.1、Snort功能介绍

Snort拥有三大基本功能：嗅探器，数据包记录和入侵检测。嗅探器模式从网络上读取数据包并作为连续不断的数据流显示在终端。数据包记录器模式是把数据包记录到硬盘上。网络入侵检测模式可配置使snort分析网络数据流以匹配用户定义的一些规则，并根据检测结果采取一定的措施。

### 2.2、入侵检测模块分析

snort是一套开源的网络入侵预防与网络入侵检测软件。使用了以侦测签名与通信协议的侦测方法。数据嗅探是基于Libpcap开发而成，Libpcap是一个跨平台的报文抓取程序。数据嗅探器将网卡获取的数据送入上层预处理组件进行处理。

预处理器介于检测引擎和数据包嗅探器之间，主要功能有包重组、解码协议和异常检测，负责对数据包的进行预先处理。作为入侵检测系统，它能够对网络中数据包片段编排与组装，还原原始的数据内容。因此预处理器对安全威胁的检测和识别非常重要。

检测引擎是Snort的核心部分，其中负责规则处理的规则库是检测引擎的重要组件，规则处理模块主要负责规则的解析和规则检测。检测引擎通过读取规则文件把规则链中，再与数据包进行对比，检测判定是否存在安全威胁，并做出响应的处理，如：警报、记录或者忽略等。针对大流量的数据中心存在系统检测处理数据丢失等情况，这就表示在大规模的网络应用中，对引擎算法的优化和改进，有着相当大的必要。

从本质上说，Snort与tcpdump和snoop一样，都是网络数据包嗅探器。因此，嗅探器模式是Snort工作的基本模式。只要运行Snort时不加载规则，它就可以从网络上读取数据包并连续不断地显示在屏幕上。这时，Snort将显示统计信息。Snort使用Libpcap网络驱动库。在这种模式下，Snort将网卡设置为混在模式，读取并解析共享信道中的网络数据包。在嗅探模式下，Snort也可以将这些信息记录到日志文件中。这些文件随后可以用Snort或者tcpdump查看。这种模式的用户并非很大，因为现在很多可以记录包的工具了。在这种模式下并不需要snort.conf配置文件。
入侵模式需要载入规则库才能工作。在入侵模式下，Snort并不记录所有捕获的包，而是将包与规则对比，仅当包与某个规则匹配的时候，才会记录日志或产生报警。如果包并不与任何一个规则匹配，那么它将会被悄悄丢弃，并不做任何记录。运行Snort的入侵检测模式的时候，通常会在命令行指定一个配置文件。

### 2.3、Snort工作流程分析

Snort在进入工作模式之前，首先要对其进行基础设置，对结构组件进行初始化配置，根据规则文件生成相应的规则链表。通过调用Libpcap提供的数据函数抓取数据包，对数据进行预处理，sonrt调用完了协议的解析函数，对数据包进行分层解析，从数据包中提取有效的检测信息，然后将解析的数据转存。由snort将解析结果和已知的规则进行比较，判断是否存在入侵行为，当相匹配时则判定存在网络安全问题，向管理员发出警报。如果不存在安全问题则直接通过。

Snort，对每个被检测的数据包都定义了如下的三种处理方式alert(发送报警信息)Log(记录该数据包)，Pass(忽略该数据)。这些处理方式其实是具体定义，在检测规则中的，具体的完成是在日志或者报警子系统中。日志子系统允许将嗅探器，收集到的信息，以可读的格式或者tcpdump格式记录下来。

此外，Snort有两种输出方式，即日志和告警，输出结果时，snort会按常规规则或预处理规则直接指定输出类型。

### 2.4、ADODB功能分析

adodb是一种兼容各类数据库应用程序的接口(API)，各种数据库都可以，MySQL、Informix、Oracle，MS
SQL
7、Foxpro、Access，ADO、Sybase、FrontBase、DB2等，不论后端是何种数据库，存取数据的方式都是一致的，adodb作为一种PHP存取数据库的中间函数组件，在本次项目种担负着桥梁的责任。

### 2.5、snort组件分析

barnyard2是一个snort组件，通过与数据库相联系，用于数据的调取与存放。daq、libdnet、libpcap都是snort的安装组件，需要编译后配合snort使用。snortrules-snapshot是snort的规则匹配库，主要功能就是用于数据的比对与识别判断依据。base则是用于前端页面数据的显示。

### 2.4、安装准备

工作环境

| 名称                   | 版本    |
|------------------------|---------|
| VMware Workstation Pro | 15      |
| MobaXterm              | 10.4    |
| Centos                 | 6.7     |
| Mysql                  | 5.7     |
| adodb                  | 5.20.9  |
| barnyard2              | 1.9     |
| base                   | 1.4.5   |
| daq                    | 2.0.5   |
| libdnet                | 1.12    |
| libpcap                | 1.9.0   |
| snort                  | 2.9.9.0 |
| snortrules-snapshot    | 2990    |

# 3、详细设计

本次项目设计是基于centos6.7操作系统，在系统上进行snort、barnyard2以及base的总体搭建，其中snort是主要部分，Barnyard2的作用是读取snort产生的二进制事件文件并存储到MySQL。同时根据base页面的变化，来测试是否成功。

### 3.1、准备工作

安装Centos6.7.iso镜像到虚拟机，配置网络设置确保连接互联网。

![](media/417131e9dc034ef1bd03d1fcb08bb72c.png)

![](media/8005949c703a184e9ffccc92d6cf6579.png)

#### 3.1.1、安装wget

![](media/d17a11bb63583e56247c4b239cad603d.png)

#### 3.1.2、更新yum源

\# wget -O /etc/yum.repos.d/CentOS-Base.repo

http://mirrors.aliyun.com/repo/Centos-6.repo

\# yum clean all

\# yum makecache

![](media/8a9e3585feecffa4a5e3cc5b118d2c65.png)

#### 3.1.3、安装epel源

\#yum install -y epel-release

#### 3.1.4、下载安装配置文件

![](media/e7cc54ed32043e75e748ed6b49d55a52.png)

### 3.2、安装配置LMAP

#### 3.2.1、安装LAMP组件

\# yum install -y httpd mysql-server php php-mysql php-mbstring php-mcrypt
mysql-devel php-gd

![](media/5a5a7f36c4dc5caed492eb718819b098.png)

#### 3.2.2、安装php插件

\#yum install -y mcrypt libmcrypt libmcrypt-devel

![](media/a2fb5fd44a7198a354e1a9b4e715557c.png)

修改vim /etc/php.ini

error_reporting = E_ALL & \~E_NOTICE

#### 3.2.3、安装pear插件

\# yum install -y php-pear

\# pear upgrade pear

\# pear channel-update pear.php.net

\# pear install mail

\# pear install Image_Graph-alpha Image_Canvas-alpha Image_Color Numbers_Roman

\# pear install mail_mime

#### 3.2.4、安装adodb

\# tar -zxvf adodb-5.20.9.tar.gz -C /var/www/html

\# mv /var/www/html/adodb5 /var/www/html/adodb

#### 3.2.5、安装base

\# tar -zxvf base-1.4.5.tar.gz -C /var/www/html/

\# mv /var/www/html/base-1.4.5 /var/www/html/base

#### 3.2.6、设置目录权限

\# chown -R apache:apache /var/www/html

\# chmod 755 /var/www/html/adodb

#### 3.2.7、配置mysql

解压barnyard2（使用文件创建数据库表）

\# tar -zxvf barnyard2-1.9.tar.gz

启动mysql

\# service mysqld start

设置root密码为123456

\# mysqladmin -u root password 123456

![](media/98b6db16cffa35c2500129b03abbf596.png)

\# mysql -uroot -p123456

创建snort的数据库，创建名为snort、密码为123456的数据库用户并赋予名为snort数据库权限。

mysql\>create database snort;

mysql\>grant create,select,update,insert,delete on snort.\* to snort\@localhost
identified by '123456';

![](media/e23228535af095db9cd0714625e2eaa1.png)

退出数据库，导入创建数据库表。

\# mysql -uroot -p123456 -D snort \<
/root/test/barnyard2-1.9/schemas/create_mysql

![](media/f142649fa2035a74aeb0d768427f5c6b.png)

![](media/6e262ba8741d995b5c07e7adbb4160d4.png)

### 3.3、配置base

\# service mysqld start 启动mysql

\# service httpd start 启动apache

\# service iptables stop 关闭iptables

![](media/da7416cbcb7f9cdb9d921b9aa3d55339.png)

用浏览器打开http://192.168.60.180/base

![](media/3984264ff1475f151ca3df6a2d2e398d.png)

点击Continue，进入配置页面，选择显示语言，设置adodb路径。

![](media/ac8e88fb3e0eddd76011e92d80f4e09d.png)

点击下一步，配置数据库。

![](media/f23ec774f35de0b0cc1e723b0393fd69.png)

点击下一步，自行配置用户名和密码，这里我设置为admin:admin

![](media/11abef43090d3df14934927c80abb2bd.png)

点击继续进入，再点击“Create BASE AG”

![](media/aab40741baf370947b90d6bbebf3b6b4.png)

如果显示Successfully created的字样则说明是成功了，点击“step 5”

![](media/38caddc81000cd2172efe8730d0ac92a.png)

如此即说明安装成功。

![](media/aee5cd3c7ebfb4449630b1d0d92b85fd.png)

### 3.4、安装配置snort

#### 3.4.1、安装依赖包

\# yum install –y gcc flex bison zlib libpcap tcpdump gcc-c++ pcre\* zlib\*
libdnet libdnet-devel

![](media/0827697a84924e26a838f08d6fce94ac.png)

#### 3.4.2、安装libdnet

\# tar -zxvf libdnet-1.12.tgz

\# cd libdnet-1.12

对libdnet进行编译到/usr/local目录

\# ./configure && make && make install

![](media/94c3d2db6d3cc394ce4c5c415c3d8c79.png)

#### 3.4.3、安装libcap

\# tar -zxvf libpcap-1.9.0.tar.gz

\# cd libpcap-1.9.0

\# ./configure && make && make install

移动到/usr/local目录下进行编译

![](media/7cef2447bec97eea9482be72d791a461.png)

#### 3.4.4、安装DAQ

\# tar -zxvf daq-2.0.5.tar.gz

\# cd daq-2.0.5

\# ./configure && make && make install

移动到/usr/local目录下进行编译

![](media/b0373efa4e6e4077bf54a0911284bd36.png)

#### 3.4.5、安装snort

\# tar -zxvf snort-2.9.9.0.tar.gz

\# cd snort-2.9.9.0

\# ./configure && make && make install

移动到/usr/local目录下进行编译

![](media/7b9da5e0621972c9139d7835ec375b7b.png)

#### 3.4.6、配置snort

首先创建文件目录

\# mkdir /etc/snort

\# mkdir /var/log/snort

\# mkdir /usr/local/lib/snort_dynamicrules

\# mkdir /etc/snort/rules

\# touch

/etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

\# cd /usr/local/snort-2.9.9.0

\# cp gen-msg.map threshold.conf classification.config reference.config
unicode.map snort.conf /etc/snort

![](media/00549c529a2f655d5f51068a6498931e.png)

编辑配置文件

\# vim /etc/snort/snort.conf

修改路径

var RULE_PATH /etc/snort/rules

var SO_RULE_PATH /etc/snort/so_rules

var PREPROC_RULE_PATH /etc/snort/preproc_rules

var WHITE_LIST_PATH /etc/snort/rules

var BLACK_LIST_PATH /etc/snort/rules

![](media/8705a108d0b38073392b92df21257d5a.png)

设置日志目录

config logdir: /var/log/snort

![](media/cc027a196d1e3e4a20ea0d211d883ce8.png)

配置输出插件

output unified2: filename snortlog, limit 128

![](media/ade8300fbe583c16d6fc094ac0990c54.png)

#### 3.4.7、配置规则库

\# tar -zxvf snortrules-snapshot-2990.tar.gz -C /etc/snort/

\# cp /etc/snort/etc/sid-msg.map /etc/snort/

![](media/7cb9e14bd80c054be5b02ac5e9ce4a72.png)

### 3.5、安装barnyard2

\# mv barnyard2-1.9 /usr/local

\# ./configure --with-mysql --with-mysql-libraries=/usr/lib64/mysql/

\# make && make install

![](media/3381904ee19493358e848c95050b3ba8.png)

#### 3.5.1、配置barnyard2

创建文件目录

\# mkdir /var/log/barnyard2

\# touch /var/log/snort/barnyard2.waldo

\# cp /usr/local/barnyard2-1.9/etc/barnyard2.conf /etc/snort/

![](media/201f55ef4d8a4b1deffe331b58e6e33e.png)

修改配置文件

\# vi /etc/snort/barnyard2.conf

config logdir: /var/log/barnyard2

config logdir:/var/log/barnyard2

config hostname:localhost

config interface:eth0

config waldo_file:/var/log/snort/barnyard.waldo

output database: log, mysql, user=snort password=123456 dbname=snort
host=localhost

![](media/13bd4a10f983c01ca580d18074b12430.png)

![](media/f9d9824102e2d7b26a5ca3efbe77fb9b.png)

![](media/6a5299ba09665fa1052f6ad8c6ff2eab.png)

# 4、部署测试

### 4.1、测试snort

参数注解：

\-T 指定启动模式：测试

>   \-i 指定网络接口：eth0

>   \-c 指定配置文件：/etc/snort/snort.conf

\# snort -T -i eth0 -c /etc/snort/snort.conf

![](media/c4dc144d6797b18dc0107f61cc1993ff.png)

如此则测试成功。

### 4.2、测试barnyard2

参数注解：

>   \-c 指定配置文件：/etc/snort/barnyard2.conf

>   \-d 指定Log目录：/var/log/snort

>   \-f 指定Log文件：snort.log

>   \-w 指定waldo文件：/var/log/snort/barnyard2.waldo

\#barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w
/var/log/snort/barnyard2.waldo

![](media/8ca8ad807664d321abf4835a66eee98e.png)

如此即说明安装成功，ctrl+c终止程序。

![](media/bd95c0ddbe3cefee3caafdd8db7f7fef.png)

### 4.3、测试IDS 

首先确保：httpd开启，iptables关闭，mysql开启。

\# service httpd start

\# service iptables stop

\# service mysqld start

#### 4.3.1、添加测试规则

\#vim /etc/snort/rules/local.rules

添加一条检查ping包的规则

alert icmp any any -\> any any (msg: "IcmP Packet detected";sid:1000001;)

规则解释：

![](media/f88fc1c1aa546dbc524f8cce06528677.png)

![](media/a8e3287a88a569ccd145e6eaac716cc9.png)

#### 4.3.2、测试运行

配置好后，我们依次启动：-D为后台运行

\# barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w
/var/log/snort/barnyard2.waldo -D

\# snort -D -T -i eth0 -c /etc/snort/snort.conf

![](media/6112d33228d7e2e684b91391583321d2.png)

![](media/3b225e5765854bc4bd1fdf9a941698ba.png)

同时我们使用主机ping测试虚拟机。

\# ping 192.168.60.180 -t

当IDS命令执行完毕后，用主机浏览器访问base安全分析引擎页面。

http://192.168.60.180/base

可以看到有检测到IP数据。

![](media/89bca99292117352dc1ac39ea13dbfe9.png)

![](media/5595ba53b8a8df73ac9f29dcae20805a.png)

![](media/745ba540cea314081e7794368c3fe867.png)

### 4.3、配置IDS启动脚本

\# chmod 755 startids.sh

\#!/bin/bash

echo
"\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*正在启动服务\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"

barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w
/var/log/snort/barnyard2.waldo -D

snort -D -c /etc/snort/snort.conf -i eth0

echo
"\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*正在启动完成\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"

![](media/8514f1647aa1fd3a503fe2f72caf22eb.png)

### 4.4、启动IDS

＃ service mysqld start 启动mysql

＃ service httpd start 启动apache

＃ service iptables stop 关闭防火墙

使用脚本启动IDS：

![](media/28e69653162fca62ce22e9a7478a9d01.png)

手动启动IDS：

\#barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w
/var/log/snort/barnyard2.waldo -D

\#snort –D -c /etc/snort/snort.conf -i eth0

### 4.5、测试IDS

使用ping命令向IDS所在IP发送数据包，base页面会出现ICMP警告。

![](media/70fa28e46ba08c6fb778ade8a6fe5017.png)

![](media/e8ded697eec1de4e688147c7b9df6169.png)

可以看到，在连续不断的ping目标IP的情况下，基本安全分析引擎BASE就会源源不断的收到数据包警报数据，我们还可以对某个特定的数据包进行分析和查看。

![](media/fa8c51b45b468d187d4d4b568b012468.png)

接下来对TCP和UDP进行测试，首先添加规则到local.rules中。

\# vim /etc/snort/rules/local.rules

在网站根目录下添加一个自定义网页。

![](media/47d458b18babcfd9b355a9bcc98ac06c.png)

使用另外一个台机器访问此网页。

![](media/4a76d76a0ae3c26d226cc4feefb4b7e8.png)

再打开安全分析引擎BASE主页面，发现TCP和UDP已经有了数据。

![](media/f19973a44fa33b08b19a3ceb88e11f78.png)

下一步跟进数据，可以看到协议类型等信息。

![](media/170c686116484f826a733af7659a442f.png)

![](media/b7d552744b07cf44fca987342f9d9f16.png)

通过IP分析，可以清晰的看到IP间的通讯情况。

![](media/5d342c3ba72d3fcf7a09319e70e030c9.png)

最后我们使用namp对端口进行扫面查看安全引擎的检测情况。

首先对snort进行简单配置。

\# vim /etc/snort/snort.conf

修改此处配置信息

\# preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { high
}

将如下注释去掉

\# include \$PREPROC_RULE_PATH/preprocessor.rules

\# include \$PREPROC_RULE_PATH/decoder.rules

\# include \$PREPROC_RULE_PATH/sensitive-data.rules

![](media/c5a5830c7699882ac29f2c2af6af6627.png)

![](media/57c8c86955527eb6ffb598a11c44735b.png)

首先看到BASE的端口扫描通信区域没有显示。

![](media/141dd6b33eb0d4902756e9a0fe0af5cf.png)

接下来使用使用Kali中的nmap命令对目标IP进行扫描。

![](media/7a5dd7e2e5e9c563b4fa4b76867d6004.png)

同时打开BASE主页面，发现流量监控数据同步显示。

![](media/eb210b966160b1a1bcde7d122ae1bbb3.png)

打开端口扫描通信查看详细信息。

![](media/16de845026cc09ae3e8cb0e7b815dec6.png)

可以看到扫描流量的详细信息。

![](media/af19d1aca61a6f6f8b1474416f458c85.png)

![](media/c82cee221fa503ec02a1b48f32e6e758.png)

![](media/433e2751e701d272d0bd3b91eefd7e3e.png)

自此，snort测试工作成功，可以上线运行。

### 4.6、停止IDS服务

可以使用已经配置好的脚本停止IDS。

![](media/42a56d94bcc0f3cc92f0a46f05b43131.png)

也可以手动停止服务。

killall -9 snort barnyard2

# 5、项目总结

通过对网络安全课程的学习，我学到了很多有关计算机网络安全方面的知识和技能，对网络安全领域有了更深层次的理解。通过完成这个项目，使得我对snort网络入侵检测系统有了一个具体的了解，Snort
IDS(入侵检测系统)是一个强大的网络入侵检测系统。它具有实时数据流量分析和记录网络数据流包的能力。对目标网络从源IP源端口到目的IP和目的端口的整个过程进行整体监控，能够进行协议分析，对网络数据包内容进行搜索和匹配。它能够检测各种不同的网络攻击方式，对异常数据流量实时监控和及时警报。

此外，Snort作为一个开源的入侵检测系统，有着良好的扩展性和可移植性，在对基于snort、barnyard2和base的入侵检测系统的部署于应用的过程中，也不乏出现各种各样的问题，如：PHP插件下载，snort对TCP/UDP等信息的检测配置等问题，通过对报错原因和运行日志的分析，结合借助各种渠道获取的相关知识经验，最终所有问题得以解决，呈现出一个性能良好、稳定可持续运行的网络入侵检测系统。

非常感谢老师能给我这次机会，让我能够独立的完成一个入侵检测系统的部署与应用的过程，以此来结合所学知识让我对之前学到的知识有了更深层次的理解与感悟，对今后的学习与工作有着及其重要的意义。
