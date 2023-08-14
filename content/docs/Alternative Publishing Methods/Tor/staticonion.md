---
title: "Static Onion"
linkTitle: "Static Onion"
weight: 4
description: >
  Create Onion Service for your Static mirror
---

Required expertise level : **Advanced**

Platform : **Linux / Ubuntu - Debian**

Last tested and confirmed : March 2022

------

{{% pageinfo %}}
This guide will walk you through the process of creating **Onion Service** for you static website.
{{% /pageinfo %}}

{{% alert color="warning" title="Note" %}}
**This guide** focuses on creating a simple Onion service mainly in the context of censorship circumvention, if you are more concerned with the anonymity Tor provides in Onion services you should not depend on this guide alone, reading and understanding **[Tor project documentations](https://2019.www.torproject.org/docs/tor-onion-service.html.en)** will best practice in that case, **as a ensuring full anonymity is an advanced and very details oriented process.**
{{% /alert %}}

-------

- **Install Nginx webserver**

> Run the following commands in your terminal in their respective order

```bash
sudo apt install software-properties-common
sudo add-apt-repository ppa:nginx/stable
sudo apt update && sudo apt install nginx -y
```
![](/img/onion-services/6.png)

Confirm your installation by entering `nginx -v`, the output should look similar to this

- **Install Tor client**

{{% alert color="warning" title="Note" %}}
**If Tor Project Website and Tor communications are blocked in your country,** probably the official **[software repositories](https://deb.torproject.org/torproject.org)** are also blocked, in which case you should skip adding them and install Tor directly from **your distribution's repositories.**
{{% /alert %}}

> Add in the following lines in `/etc/apt/sources.list`

```
deb https://deb.torproject.org/torproject.org stretch main
deb-src https://deb.torproject.org/torproject.org stretch main
```

> Run the following commands in your terminal in their respective order

```bash
curl https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt update && apt install tor deb.torproject.org-keyring
sudo apt update && sudo apt install tor
```

 > Run the following commands to start Tor daemon

```bash
sudo systemctl start tor
sudo systemctl enable tor
```

> Confirm Tor is running without issues

```bash
sudo systemctl status tor
tor --version
```
![](/img/onion-services/7.png)

- **Configure Tor client**

> **Open** Tor config file at `/etc/tor/torrc` with your favorite editor

`vim /etc/tor/torrc`

> **Uncomment** the following lines by removing the `#`, and optionally, replace the directory name in `/var/lib/tor/hidden_service/` with different name, specially if you are planning on hosting multiple Onion Services on the same server. i.e. `/var/lib/tor/myfirstonion/`

- **Before:**

```bash
 72 #HiddenServiceDir /var/lib/tor/hidden_service/
 73 #HiddenServicePort 80 127.0.0.1:80
```
- **After**:

```bash
HiddenServiceDir /var/lib/tor/myfirstonion/
HiddenServicePort 80 127.0.0.1:80
```
> Restart Tor service

`sudo systemctl restart tor`

> Confirm your Onion Service related files were generated at `/var/lib/tor/myfirstonion/`

```bash
cd /var/lib/tor/myfirstonion/ && ls
```
You should find two files generated at this directory

1- `hostname` **contains your Onion Service address**

2- `private_key` **Private key used for encryption. Don't edit or share this file under any circumstances**

![](/img/onion-services/8.png)

- **Configure Nginx Webserver**

**It's very important to read Nginx documentations and follow the [best practices](https://riseup.net/en/security/network-security/tor/onionservices-best-practices) when configuring your Onion Service**

But essentially, you can get your Onion Service up & running by adding this simple config file to your `/etc/nginx/sites-enabled`

```nginx
server {
    listen 127.0.0.1:80;
    server_name [onion-address]; #replace with your generated onion address, you can get that by executing : `cat /var/lib/[yourservicename]/hostname`
    root /var/www/html/mystaticmirror; #replace with your mirror's files directory, and make sure the webserver user has access permissions to it.
    client_max_body_size 99M;
    port_in_redirect off;
    charset utf-8;
    index index.html;
location / {
    autoindex off;
}
}
```

- **Testing your setup**

![](/img/onion-services/9.png)

Make sure Both Nginx and Tor client are restarted and running succesfully, then head to your Tor Browser and test your new Onion address.

- **[Optional] - announcing your new mirror for Tor browser users**

{{< alert >}}
[**Onion-Location**](https://community.torproject.org/onion-services/advanced/onion-location/) is a new feature implemented in Tor Browser.

It essentially allows you to **announce your Onion mirror** for Tor Browser users when they access your original website, through adding an **HTTP Header** using your webserver, or adding specific **HTML `<meta>`** to your `index.html` page.
{{< /alert >}}

**HTTP Header**

- Apache

```apache
<VirtualHost *:443>
       ServerName <your-website.tld>
       DocumentRoot /path/to/htdocs

       Header set Onion-Location "http://your-onion-address.onion%{REQUEST_URI}s"

       SSLEngine on
       SSLCertificateFile "/path/to/www.example.com.cert"
       SSLCertificateKeyFile "/path/to/www.example.com.key"
     </VirtualHost>
```

- Nginx

```nginx
add_header Onion-Location http://<your-onion-address>.onion$request_uri;
```

**HTML `<meta>`**

```html
<meta http-equiv="onion-location" content="http://<your-onion-service-address>.onion" />
```

{{< alert >}}
**When** everything is well configured and working, visitors of your original Clearnet website using Tor browser, should be notified about the availability of the Onion mirror and it's address.
{{< /alert >}}

![](/img/onion-services/10.png)