---
title: "Intro to Tor"
linkTitle: "Intro to Tor"
weight: 2
description: >
  Introduction to Tor network
---

Required expertise level : **Beginner / Intermediate**

Platform : **Gnu/Linux | macOS | MS Windows | Android | BSD**

Last tested and confirmed : March 2022

-----

{{% pageinfo %}}
**This guide is an updated version of this [article](https://www.madamasr.com/en/2019/12/25/feature/politics/beating-the-block-mada-masr-launches-tor-mirror/), published by MadaMasr - An Egyptian independent media organization - in the context of releasing their own Onion mirror.**
{{% /pageinfo %}}

## What is Tor?

{{< youtube id="JWII85UlzKw" autoplay="false" >}}

{{< alert title="Tor" >}}
 is the acronym for the original project that produced The Onion Router protocol, which protects the identity of internet users. It’s one of several technologies that have become widely used to roam the web freely and securely.
{{< /alert >}}

**The project began in the mid-1990s** and has gone through several phases. It is now administered by a not-for-profit organization, supervised by a community of its users and developers.

All Tor software is developed under **open-source licenses** and is publicly available for anyone to view and collaborate in improving.

## How does Tor work?

**Let’s imagine the journey of a data packet between a user and a server** (i.e. a website), both connected to the internet. With a regular connection, the data packet moves from the user’s device through the local router and then to the servers of the Internet Server Provider (ISP). If the ISP’s servers allow the packet to pass, it will reach its destination, hassle-free.

**_But what if you don’t want anyone to access your data packet, its destination or its content? Or to be able to block its journey?_**

{{< alert title="Onion routing" >}}
allows your packet to take a different, more secure route to reach its final destination.

Your Tor client will choose a group of random nodes for the packet to move through until it reaches its final destination. It will then generate a set of keys on your computer, which are used to encrypt the data packet as many times as the number of nodes it will pass through in its journey before reaching the final exit node.
{{< /alert >}}

![](/img/onion-services/5.png)

**The encryption protocol** allows each node the packet is passing through to decrypt just one layer of the encryption to get information about the next node the packet will pass through.

The aim of the onion routing protocol is for your packet to pass through a series of random nodes before reaching its final destination, **with each node only receiving information about the nodes that directly proceed and follow it.**

None of the nodes — _except for the last one_ — can access information about the data packet’s final destination or see what’s inside it. **The final exit node decrypts the final layer and directs the packet to its intended destination on the internet.**

## Who runs Tor?

{{< alert title="The organization" >}}
 operates several machines that serve as nodes on its network. Volunteers run thousands more nodes — all under the community’s supervision — to ensure data security.
{{< /alert >}}

**Anyone can volunteer** to host a node in the network given that they have the necessary technical capabilities and internet speed.

Neither the community nor the organization **has the right or the ability to interfere with the encryption protocol because the encryption keys of each user are stored on their respective devices.**

{{% alert color="warning" %}}
**Data packets are therefore completely encrypted within the Tor network.**
{{% /alert %}}

## What’s the difference between using Tor and using a Virtual Private Network (VPN)?

>VPN is the name given to different protocols and mechanisms that route the connection of one or more machines to a virtual network through which they can access the internet.

**To do so,** the VPN client creates an encrypted connection to the server of the virtual private network, which acts like a tunnel transferring data from the machine to the server before it reaches the internet. When the data gets to its final destination, it appears as if it were sent from the server of the virtual network.

VPN theoretically helps protect users’ anonymity as it hides their geographical locations and identities from the servers at the receiving end. Yet while VPN provides some privacy besides enabling users to access blocked websites, it doesn’t provide watertight protection.

Network admins can collect users’ data after decrypting them. Data can also be manipulated if users connect to websites and services that don’t use secure protocols, such as HTTPS.

**It’s also not advisable to use free VPN services**, as many such services make money by collecting and selling user data. Others inadvertently transfer adware and, sometimes, malware from unprotected websites while browsing.

These are the main differences between using the Tor network and VPN services. Whether paid or free, VPN providers generally seek profit, and there isn’t a practical method to verify their user data security policies. Tor, on the other hand, is subject to clear transparency rules and the supervision of both developers and users.

**Additionally,** it’s easy to block access to VPN service providers, either through tracking their respective routing protocols or intercepting connections. Authorities can also directly block VPN servers and websites, as is the case with some countries.

## What’s the difference between Onion Services and the normal web - [Clearnet](https://en.wikipedia.org/wiki/Clearnet_(networking))?

**We’ve explained how Tor network operates by describing the journey of a data packet through the nodes** until it reaches the exit node and then its destination on the internet.

**But what if the packet never leaves Tor network?**

**Onion services** are used to grant access to servers operating completely within the Tor network that are only accessible using the onion routing protocol. These services can be accessed through randomly generated addresses (most of the time) ending with the special-use top-level domain suffix “.onion” (as opposed to the more common .com or .org).

**What this technique provides** is a routing protocol between the user and the server so that neither has any information about the other.

{{< alert >}}
Under optimum conditions in which all preferences are properly set by both parties, it is not possible to trace the server operating on Tor network, nor can the website’s admin collect any data that would reveal a user’s identity — barring, of course, a mistake or voluntary release of such information.
{{< /alert >}}

## Tor Browser

{{< alert >}}
You can reach Tor Browser and download the installer for your respective operating system using the following links
{{< /alert >}}

- [Tor Project website](https://www.torproject.org/download/)       **If Internet censorship is in place in your country, there is a fairly chance this website is _blocked_**

- [**Tor Project repository on GitHub**](https://github.com/TheTorProject/gettorbrowser/releases/tag/torbrowser-release)

- [**The Internet Archive**](https://archive.org/details/@gettor)

- [**Google Drive**](https://drive.google.com/open?id=13CADQTsCwrGsIID09YQbNz2DfRMUoxUU)


**Other mirrors**

- https://tor.eff.org/

- https://tor.calyxinstitute.org/

- https://tor.ccc.de/
- We host an **expermintal mirror for Tor Browser binary files on IPFS,** you can reach it on [ipfs.io/ipns/tor-ipfs.fightcensorship.tech](https://ipfs.io/ipns/tor-ipfs.fightcensorship.tech)

**Tor Project** also provides another method to download its browser. **Just send an email to gettor@torproject.org** including the name of your operating system (Windows, OSX, Linux). You will receive a message containing links to download the browser via Google Drive and Dropbox, which aren’t blocked.

----

**Tor Browser for Android is also available on the [Google Play Store](https://play.google.com/store/apps/details?id=org.torproject.torbrowser
)**

{{< alert >}}
You can also use Tor network’s proxy app [**Orbot**](https://play.google.com/store/apps/details?id=org.torproject.android), which provides a similar service to VPNs. Orbot redirects the data from all the apps on your phone to go through Tor network. This can help override blocks placed on apps such as Signal and Wire, among others.
{{< /alert >}}


![Orbot VPN mode](/img/onion-services/3.gif)

{{< alert >}}
**There isn’t an official version** of Tor Browser for iPhone and iPad users because of the restrictions Apple places on apps. However, every now and then, independent developers come up with alternative browsers to access Tor network such as [**OnionBrowser**](https://onionbrowser.com/).

**These browsers, however, don’t ensure the anonymity of users accessing content outside the Tor network.**
{{< /alert >}}

## When Tor is blocked, activate bridges


{{< youtube id="DkEqWGF3cvg" autoplay="false" >}}

{{< alert >}}
Connection to Tor network usually gets restricted through blocking or jamming entry nodes because the addresses of most VPNs, as well as the protocols of nodes and relays, are openly available on the internet.
{{< /alert >}}

**What makes fully blocking Tor network such a difficult task is that there are many ways to connect to it. One such way is by using bridges.**

**In a nutshell,** bridges are servers run by volunteers whose addresses aren’t usually published openly. Bridges work as an intermediary between users and Tor network and help bypass blocks while hiding the connection from any party trying to analyze the network’s data.

### Activating Bridges

**Tor browser on Android phones**

![](/img/onion-services/1.gif)

**Tor’s Android client, Orbot**

![](/img/onion-services/2.gif)

**Tor browser on Desktop devices**

![](/img/onion-services/4.gif)

### Websites that can be accessed through .onion services

- [**BBC**](https://www.bbcweb3hytmzhn5d532owbu6oqadra5z3ar726vq5kgwwn6aucdccrad.onion/)

- [**The New York Times**](https://www.nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion/)

- [**ProtonMail**](https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/)

- [**Facebook**](https://www.facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion/)

- [**Twitter**](https://twitter3e4tixl4xyajtrzo62zg5vztmjuricljdp2c5kshju4avyoid.onion/)

- [**MadaMasr**](https://madakrogilagsapkmoe2iwjbmuva27t73opugag6kjsgrqxzywpbksad.onion)

- [**Masaar**](https://masarnh55evghtxwgbq5dg5xssdxhm43wgyy4f5uxwejzyfuuepliuad.onion)