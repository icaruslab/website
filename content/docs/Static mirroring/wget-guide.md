---
title: "Wget"
linkTitle: "Wget"
weight: 5
description: >
  Use [Wget](https://www.gnu.org/software/wget/) to create a static clone of a website
---

Required expertise level : **Beginner / Intermediate**

Platform : **Gnu/Linux | macOS | MS Windows | Android | BSD**

Last tested and confirmed : January 2022

-----

{{< alert >}}
**Wget** is a cli-based software that retrieves web content, it supports HTTP, HTTPS, and FTP protocols.
{{< /alert >}}
**One of Wget’s features** is the ability to scan and index the entirety of a website and download a fully functional static clone of the original website.

The static clone can be later refreshed and updated with new content published to the original website.
While there are different ways of performing this task using Wget, you may get different results depending on your original website properties, including the CMS being used, the web server configurations, any kind of DDoS protection and online asset's protection e.g. images and videos.

----

### Install Wget

**MS Windows**

- [Chocolatey](https://chocolatey.org/install) package manager for MS Windows

    `choco install wget`

**Gnu/Linux**

{{< alert color="success" title="Note" >}}As Wget is a Gnu developed software, it’s available in most distributions main repositories, the installation process should be as simple as using your distribution’s package manager.{{< /alert >}}

> Examples

  - `apt install wget`

  - `dnf install wget`

  - `pacman -S wget`

**macOS**

- Install using [Homebrew](https://brew.sh/) package manager

    `brew install wget`

- Install using [Macports](https://www.macports.org/install.php)

    `port install wget`

----

### Pulling the website to your local machine

{{< alert color="success" title="Note" >}}We will be using some basic parameters for Wget which should work for the majority of websites, but you may need to refer to the [manual pages of Wget](https://www.gnu.org/software/wget/manual/wget.html) in case of needing to do some tweaks or solve an issue with the resulting mirror.{{< /alert >}}

`wget --mirror --convert-links --adjust-extension --page-requisites http://example.org`

##### Parameters and options description

`--mirror`

Turn on options suitable for mirroring.  This option turns on recursion and time-stamping, sets infinite recursion depth and keeps FTP directory listings.

-`-convert-links`

After the download is complete, convert the links in the document to make them suitable for local viewing.  This affects not only the visible hyperlinks, but any part of the document that links to external content, such as embedded images, links to style sheets, hyperlinks to non-HTML content, etc.

`--adjust-extension`

If some link points to `//foo.com/bar.cgi?xyz` with `--adjust-extension` asserted and its local destination is intended to be .`/foo.com/bar.cgi?xyz.css`, then the link would be converted to `//foo.com/bar.cgi?xyz.css`. Note that only the filename part has been modified. The rest of the URL has been left untouched, including the net path `("//")` which would otherwise be processed by Wget and converted to the effective scheme `(ie. "http://")`.

`--page-requisites`

This option causes Wget to download all the files that are necessary to properly display a given HTML page.  This includes such things as inlined images, sounds, and referenced stylesheets.

----

{{< alert title="Tip" >}}[Wget2](https://gitlab.com/gnuwget/wget2) is currently being developed, while it’s not stable yet but it’s a full rewrite of the original Wget and meant to replace it in the near future. Wget2 comes with many new features such as HTTP/2.0 support and multi-threaded download which can make the process of pulling large websites way faster.{{< /alert >}}

{{< alert color="warning" title="Note" >}}For websites operating behind Cloudflare, this process can be identified as malicious behaviour as many simultaneous requests are coming from one IP address in short intervals, this can result in partial downloads or failing to download some assets such as inline images and CSS files.{{< /alert >}}

**This can be solved** by either **whitelisting your IP address on Cloudflare** and disable assets protection features during the crawling process, or configure the origin server to **allow direct access** on a different domain/sub-domain with [basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) enabled, you can then add `--http-user=[HTTP-USER]` `--http-passwd=[HTTP-PASSWORD]` parameters to your Wget command to authenticate.
