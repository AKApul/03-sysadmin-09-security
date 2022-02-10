# 03-sysadmin-09-security

1.
https://disk.yandex.ru/i/Dw4MFQ51nal6qQ

2.
https://disk.yandex.ru/i/hyv-2TxIbhn3XQ

3.
 sudo apt install apache2

sudo a2enmod ssl

sudo systemctl restart apache2

sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt -subj "/C=RU/ST=Moscow/L=Moscow/O=ORGAKA/OU=Org/CN=www.somesite.xyz"

sudo nano /etc/apache2/sites-available/mytestsite.conf

<VirtualHost *:443>
   ServerName www.somesite.xyz
   DocumentRoot /var/www/www.somesite.xyz

   SSLEngine on
   SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
   SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
</VirtualHost>

sudo mkdir /var/www/www.somesite.xyz

sudo nano /var/www/www.somesite.xyz/index.html

\<h1>it worked!\</h1>

sudo a2ensite mytestsite.conf

sudo apache2ctl configtest

sudo systemctl reload apache2


4.


vagrant@vagrant:~/testssl.sh$ ./testssl.sh -U --sneaky https://rwtk.ru/

###########################################################
    testssl.sh       3.1dev from https://testssl.sh/dev/
    (13f0388 2022-02-02 13:34:23 -- )

      This program is free software. Distribution and
             modification under GPLv2 permitted.
      USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

       Please file bugs @ https://testssl.sh/bugs/

###########################################################

 Using "OpenSSL 1.0.2-chacha (1.0.2k-dev)" [~183 ciphers]
 on vagrant:./bin/openssl.Linux.x86_64
 (built: "Jan 18 17:12:17 2019", platform: "linux-x86_64")


Testing all IPv4 addresses (port 443): 90.156.201.21 90.156.201.116 90.156.201.58 90.156.201.98
-----------------------------------------------------------------------------------------------------------------
 Start 2022-02-10 07:47:48        -->> 90.156.201.21:443 (rwtk.ru) <<--

 Further IP addresses:   90.156.201.98 90.156.201.58 90.156.201.116 2a00:15f8:a000:5:1:12:2:c094 2a00:15f8:a000:5:1:13:2:c094 2a00:15f8:a000:5:1:14:2:c094
                         2a00:15f8:a000:5:1:11:2:c094
 rDNS (90.156.201.21):   fe.shared.masterhost.ru.
 Service detected:       HTTP


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           OpenSSL handshake didn't succeed
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
                                           Can be ignored for static pages or if no secrets in the page
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)              Downgrade attack prevention supported (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                           make sure you don't use this certificate elsewhere with SSLv2 enabled services
                                           https://censys.io/ipv4?q=9B3CAE7CA9B38D947D57D2F89F400200C6C4DB0551DCF9E2700210822FB6E6E4 could help you to find out
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no common prime detected
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA ECDHE-RSA-DES-CBC3-SHA
                                                 EDH-RSA-DES-CBC3-SHA AES128-SHA AES256-SHA DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2022-02-10 07:48:54 [  69s] -->> 90.156.201.21:443 (rwtk.ru) <<--

-----------------------------------------------------------------------------------------------------------------
 Start 2022-02-10 07:48:54        -->> 90.156.201.116:443 (rwtk.ru) <<--

 Further IP addresses:   90.156.201.98 90.156.201.58 90.156.201.21 2a00:15f8:a000:5:1:12:2:c094 2a00:15f8:a000:5:1:13:2:c094 2a00:15f8:a000:5:1:14:2:c094
                         2a00:15f8:a000:5:1:11:2:c094
 rDNS (90.156.201.116):  fe.shared.masterhost.ru.
 Service detected:       HTTP


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           OpenSSL handshake didn't succeed
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
                                           Can be ignored for static pages or if no secrets in the page
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)              Downgrade attack prevention supported (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                           make sure you don't use this certificate elsewhere with SSLv2 enabled services
                                           https://censys.io/ipv4?q=9B3CAE7CA9B38D947D57D2F89F400200C6C4DB0551DCF9E2700210822FB6E6E4 could help you to find out
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no common prime detected
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA ECDHE-RSA-DES-CBC3-SHA
                                                 EDH-RSA-DES-CBC3-SHA AES128-SHA AES256-SHA DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2022-02-10 07:49:56 [ 131s] -->> 90.156.201.116:443 (rwtk.ru) <<--

-----------------------------------------------------------------------------------------------------------------
 Start 2022-02-10 07:49:56        -->> 90.156.201.58:443 (rwtk.ru) <<--

 Further IP addresses:   90.156.201.98 90.156.201.116 90.156.201.21 2a00:15f8:a000:5:1:12:2:c094 2a00:15f8:a000:5:1:13:2:c094 2a00:15f8:a000:5:1:14:2:c094
                         2a00:15f8:a000:5:1:11:2:c094
 rDNS (90.156.201.58):   fe.shared.masterhost.ru.
 Service detected:       HTTP


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           OpenSSL handshake didn't succeed
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
                                           Can be ignored for static pages or if no secrets in the page
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)              Downgrade attack prevention supported (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                           make sure you don't use this certificate elsewhere with SSLv2 enabled services
                                           https://censys.io/ipv4?q=9B3CAE7CA9B38D947D57D2F89F400200C6C4DB0551DCF9E2700210822FB6E6E4 could help you to find out
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no common prime detected
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA ECDHE-RSA-DES-CBC3-SHA
                                                 EDH-RSA-DES-CBC3-SHA AES128-SHA AES256-SHA DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2022-02-10 07:51:03 [ 198s] -->> 90.156.201.58:443 (rwtk.ru) <<--

-----------------------------------------------------------------------------------------------------------------
 Start 2022-02-10 07:51:03        -->> 90.156.201.98:443 (rwtk.ru) <<--

 Further IP addresses:   90.156.201.58 90.156.201.116 90.156.201.21 2a00:15f8:a000:5:1:12:2:c094 2a00:15f8:a000:5:1:13:2:c094 2a00:15f8:a000:5:1:14:2:c094
                         2a00:15f8:a000:5:1:11:2:c094
 rDNS (90.156.201.98):   fe.shared.masterhost.ru.
 Service detected:       HTTP


 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
 Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK), no session ticket extension
 ROBOT                                     not vulnerable (OK)
 Secure Renegotiation (RFC 5746)           OpenSSL handshake didn't succeed
 Secure Client-Initiated Renegotiation     not vulnerable (OK)
 CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
 BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
                                           Can be ignored for static pages or if no secrets in the page
 POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
 TLS_FALLBACK_SCSV (RFC 7507)              Downgrade attack prevention supported (OK)
 SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
 FREAK (CVE-2015-0204)                     not vulnerable (OK)
 DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
                                           make sure you don't use this certificate elsewhere with SSLv2 enabled services
                                           https://censys.io/ipv4?q=9B3CAE7CA9B38D947D57D2F89F400200C6C4DB0551DCF9E2700210822FB6E6E4 could help you to find out
 LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no common prime detected
 BEAST (CVE-2011-3389)                     TLS1: ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA ECDHE-RSA-DES-CBC3-SHA
                                                 EDH-RSA-DES-CBC3-SHA AES128-SHA AES256-SHA DES-CBC3-SHA
                                           VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)
 LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
 Winshock (CVE-2014-6321), experimental    not vulnerable (OK)
 RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)


 Done 2022-02-10 07:52:07 [ 262s] -->> 90.156.201.98:443 (rwtk.ru) <<--

-----------------------------------------------------------------------------------------------------------------
Done testing now all IP addresses (on port 443): 90.156.201.21 90.156.201.116 90.156.201.58 90.156.201.98

vagrant@vagrant:~/testssl.sh$


5.


 sudo apt install openssh-server
sudo systemctl start sshd.service
sudo systemctl enable sshd.service
ssh-keygen

vagrant@vagrant:~$ ssh-copy-id vagrant@10.0.2.12

/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/vagrant/.ssh/id_rsa.pub"
The authenticity of host '10.0.2.12 (10.0.2.12)' can't be established.
ECDSA key fingerprint is SHA256:wSHl+h4vAtTT7mbkj2lbGyxWXWTUf6VUliwpncjwLPM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
vagrant@10.0.2.12's password:

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'vagrant@10.0.2.12'"
and check to make sure that only the key(s) you wanted were added.

vagrant@vagrant:~$ ssh 'vagrant@10.0.2.12'

Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 10 Feb 2022 11:53:58 AM UTC

  System load:  0.0               Processes:             114
  Usage of /:   2.5% of 61.31GB   Users logged in:       1
  Memory usage: 22%               IPv4 address for eth0: 10.0.2.15
  Swap usage:   0%                IPv4 address for eth1: 10.0.2.12


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Thu Feb 10 11:29:02 2022 from 10.0.2.2

6.

vagrant@vagrant:~$ cat ~/.ssh/config

Host second

User vagrant

HostName 10.0.2.12

Port 22

IdentityFile /home/vagrant/.ssh/id_rsa2.pub


ssh second

7.
vagrant@vagrant:~$ sudo tcpdump -c 100 -w ~/kkkk.pcap

tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes

100 packets captured

100 packets received by filter

0 packets dropped by kernel

https://disk.yandex.ru/i/Z6N1SRT7RADhcA
