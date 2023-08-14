---
title: "Encrypted SNI"
linkTitle: "ESNI"
weight: 5
description: >
  Encrypted Server Name Indication
_build:
 list: false
 render: false
---

Required expertise level : **Advanced**

Platform : **Any**

-----
{{% alert color="warning" title="Note" %}}
Encrypted Server Name Indication (ESNI), Now, [Encrypted Client Hello (ECH)](https://www.ietf.org/archive/id/draft-ietf-tls-esni-10.txt), is still undergoing a lot of changes and developments, and will probably see more changes before it reaches a production ready state, it's important to note that it's **not yet production ready.**

The purpose of this guide was to introduce the new technology and a proof of concept "based on our testing" of the potential benefit of ESNI in the context of censorship circumvention. **This guide is no longer valid and will be removed in the next update**.

Both Cloudflare and Mozilla announced they are working on a compatible server and client implementation of the latest draft of ECH, we will keep following the updates and will test any new implementations as it's being introduced, and present our findings in the future.

**References**
-  [TLS Encrypted Client Hello (draft-ietf-tls-esni-10) - IETF](https://www.ietf.org/archive/id/draft-ietf-tls-esni-10.txt)
-  [Encrypted Client Hello: the future of ESNI in Firefox - Mozilla](https://blog.mozilla.org/security/2021/01/07/encrypted-client-hello-the-future-of-esni-in-firefox/)
-  [Good-bye ESNI, hello ECH! - CloudFlare](https://blog.cloudflare.com/encrypted-client-hello/)
{{% /alert %}}

### What is Server Name Indication (SNI)?

**Server Name Indication (SNI) is an extension to the Transport Layer Security (TLS) network encrypted protocol.**

{{% alert %}}
**Essentially,** SNI's purpose is to send the requested domain name to the webserver in the form of plain/text HTTP header, so the server will send back the appropriate response to initiate the encrypted connection.
{{% /alert %}}

**SNI was originally [standardized in 2003](https://tools.ietf.org/html/rfc3546),** it's wide implementation is a big part of today's Internet infrastructure, mainly because it allowed hosting multiple websites with different domain names on the same webserver.

Since then, the SNI header is a main target in any Deep Packet Inspection (DPI) operations, to preliminarily detect traffic to specific host before blocking.  [read more about SNI and the issues it presents](https://blog.cloudflare.com/encrypted-sni/)

### What is Encrypted SNI and how can it help?

{{% alert %}}
[Encrypted SNI (ESNI)](https://tools.ietf.org/html/draft-ietf-tls-esni-06) is a new suggested extension, it uses [**asymmetric encryption keys**](https://en.wikipedia.org/wiki/Public-key_cryptography) to encrypt the SNI header, the server publishes the public key `well-known` DNS record and the client fetches the key using DNS.

Current implementations of ESNI requires DNS over HTTPS (DoH) in order to work.
{{% /alert %}}

{{% alert color="warning" title="Note" %}}
Encrypted SNI is still not standardized, which means that it's still in early development stages and might undergo a lot of changes on it's way to be a widely implemented standard
{{% /alert %}}

----

### How to test Encrypted SNI?

Some projects are trying to test for the best implementation of ESNI, or how to integrate it with major software stacks i.e. [Nginx](https://github.com/sftcd/nginx), and [OpenSSL](https://github.com/sftcd/openssl/tree/master/esnistuff).

**If you are interested in a deeper technical understanding of ESNI you can check out these projects**

- [Developing ESNI for OpenSSL (DEfO)](https://defo.ie/)
- [Noctilucent](https://github.com/SixGenInc/Noctilucent)

-----
{{% alert %}}
In this guide, we will use the most stable and tested implementation which comes with CloudFlare and Mozilla Firefox
{{% /alert %}}

### Server Side


**Currently,** the only stable and tested server side implementation of ESNI is [CloudFlare](https://blog.cloudflare.com/esni/).

All you have to do is to enable **TLS 1.3**

**Log in** to your **CloudFlare account,** select your **domain name**, go to > `SSL/TLS` options, choose > `Edge Certificates`, and make sure > `TLS 1.3` is enabled.


![](/img/esni/1.png)

### Client Side

Mozilla Firefox latest releases are shipped with TLSv1.3 and ESNI extension support, yet, it doesn't come enabled by default for now.

**To enable ESNI support in Mozilla Firefox**

- Make Firefox is updated to latest release

![](/img/esni/2.png)

- Enable DNS over HTTPS (DoH) in `Preferences` > `Network Settings` > `Enable DNS over HTTPS`

![](/img/esni/3.png)

{{% alert title="Note" %}}
CloudFlare DoH resolver **might be blocked** in your country. **[Check here](https://1.1.1.1/help).**

If that's the case, you can try changing `Next DNS`, or choose `Custom` and test the public resolver - with DoH support -  from **[this list](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Public+Resolvers).**
{{% /alert %}}

- Enable ESNI extension support
  - Open a **new tab** and type the address `about:config`
  - **Click** `Accept the Risk and Continue`
  - **Search** for `network.security.esni.enabled`
  - **Click** on the value to change it from `False` to `True`
- **Restart** your browser and test your settings [here](https://www.cloudflare.com/ssl/encrypted-sni/)

![](/img/esni/4.png)

![](/img/esni/5.png)

{{% alert title="Test your website" %}}
 by adding visiting this address in your browser `https://[yourdomain.com]/cdn-cgi/trace` i.e. `https://www.cloudflare.com/cdn-cgi/trace`

 You should get these **values:**

```
tls=TLSv1.3
sni=encrypted
```

 {{% /alert %}}

 ----

### Resources and readings

- CloudFlare : [Encrypt that SNI: Firefox edition](https://blog.cloudflare.com/encrypt-that-sni-firefox-edition/)
- CloudFlare : [Encrypt it or lose it: how encrypted SNI works](https://blog.cloudflare.com/encrypted-sni/)
- IETF : [Transport Layer Security (TLS) Extensions](https://tools.ietf.org/html/rfc3546)
- IETF : [TLS Encrypted Client Hello - draft-ietf-tls-esni-07](https://tools.ietf.org/html/draft-ietf-tls-esni-07)
- Chromium Support Status :  [Issue 908132](https://bugs.chromium.org/p/chromium/issues/detail?id=908132)
- [Developing ESNI for OpenSSL (DEfO)](https://defo.ie/)
- Mozilla : [Encrypted SNI Comes to Firefox Nightly - October 18, 2018](https://blog.mozilla.org/security/2018/10/18/encrypted-sni-comes-to-firefox-nightly/)
- If you want to test ESNI further, or develop something for it - [Noctilucent](https://github.com/SixGenInc/Noctilucent)
- For better understanding of [DNS over HTTPS (DoH)](https://www.cloudflare.com/learning/dns/dns-over-tls/) and other [DNS privacy related materials](https://dnsprivacy.org/wiki/)