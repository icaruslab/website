
---

title: "Dynamic Mirroring"
linkTitle: "Dynamic Mirroring"
weight: 8
date: 2017-01-04
description: >
  What is dynamic mirroring?
---

### What is dynamic-mirroring

> **There are multiple ways of mirroring a dynamic website.**

**One of these ways will be** creating a reverse-proxy server which acts as a middle box between the client and the origin server which hosts the website.

The server in the middle will get the required URL from the client and contact the origin server to fetch the content and serve it to the user.

In this method the **reverse-proxy server** will be reachable through a domain-name which isn’t blocked, this method is relatively easy to implement, but it can be easily blocked by blocking the domain name or the IP address of the proxy server.

**Another method will be** hosting a full copy of the original blocked website on the server and keeping it synchronized with the original server.

This method needs certain access privileges to the origin server and it holds the same disadvantages of the first method. In many cases you can just keep changing the mirror server’s domain name and IP address whenever it gets blocked, but that can be inefficient in terms of both financial costs and usability.

**In our documentations**, we will try to introduce different methods of dynamic mirroring, either by creating a proxy service hosted on **[Google App Engine](https://cloud.google.com/appengine)** using **[Decoy](/docs/dynamic-mirroring/decoy/)**, or creating Onion service mirror on Tor network using **[EOTK - The Enterprise Onion Toolkit](https://github.com/alecmuffett/eotk)**.