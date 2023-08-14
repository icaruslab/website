---
title: "HTTrack"
linkTitle: "HTTrack"
weight: 6
description: >
  Use [HTTrack](https://www.httrack.com/) to create a static clone of a website
---

Required expertise level : **Beginner / Intermediate**

Platform : **Gnu/Linux | macOS | MS Windows | Android | BSD**

Last tested and confirmed : January 2022

-----

{{< alert >}}
**HTTrack** is a free software developed for the specific purpose of downloading fully functional offline copies of any website.
>It has many advantages over Wget, and offers a graphical user interface. While it’s not being updated since 2017, it proofed to be efficient in most use cases in our testing scenarios.
{{< /alert >}}

### Install HTTrack

**Windows**

- [Chocolatey](https://chocolatey.org/install) package manager for MS Windows

    `choco install httrack`

- Or you can download the installation file [here](https://www.httrack.com/page/2/en/index.html)

**Gnu/Linux**

{{< alert >}}Since HTTrack is available in most major distributions main repositories, you can use your package manager to directly install the compiled version.{{< /alert >}}

>Example

- `apt install httrack`
- `dnf install httrack`
- `pacman -S httrack`

{{< alert >}}In this [page](https://www.httrack.com/page/2/en/index.html) you can find instructions on downloading and building HTTrack from source.{{< /alert >}}

{{% alert title="Note" %}}Also, a version with a graphical user interface exists for Gnu/Linux but still in beta, you can find the source [here](https://sourceforge.net/projects/httraqt/){{% /alert %}}

**macOS**

- Using Homebrew package manager

    `brew install httrack`

- Using Macports

    `sudo port install httrack`

----

### Pulling the website to your local machine

```bash
httrack --mirror --robots=0 --stay-on-same-domain --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0"  --keep-links=0 --path example.org --quiet https://example.org/ -* +example.org/*
```

##### Parameters and options description


`--mirror`

Mirror websites

`--robots=0`

Follow robots.txt and meta  robots  tags  (0=never,1=sometimes,*  2=always,  3=always  (even strict rules)) (--robots[=N])

`--stay-on-same-domain`

Stay on the same principal domain

`--user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0"`

User-agent field sent in HTTP headers

`--keep-links=0`

keep  original  links  (e.g.  http://www.adr/link)  (`--keep-links=0` *relative link, `--keep-links` absolute links, `--keep-links=4` original links, `--keep-links=3` absolute URI links, `--keep-links=5` transparent proxy link)

`--path example.org`

Path for mirror/logfiles+cache (`--path` mirror[,path cache and logfiles])

`--quiet`

no questions - quiet mode

`https://example.org/ -*`

Replace example.org with the website you want to mirror

`+example.org/*`

HTTrack will crawl and scan the whole website, renders every and save it locally to your machine in an offline browsable form. The suggested combination of arguments will convert the inline URLs to relative links which can be hosted virtually anywhere.

`httrack --continue`

In case of intercepted or uncompleted download process HTTrack will use the cache to resume the download process and make sure it won’t include re-downloading the same unchanged assets.

`httrack --update`

----


>Here we need to consider a very important note about how HTTrack functions.

**Normally** there will be a cached version of all downloaded assets saved in a directory under the main project’s directory named hts-cache, the cache will be used in every update presumably to avoid having to crawl and download the whole website with every update, which can be a very time-consuming process especially with big websites.

**However**, in our testing with different websites of different sizes and structures, the real-life scenario turned to be different from what the software documentations provides.

{{< alert >}}_For example_ with a big WordPress website running relatively recent version of Nginx web server and operating behind a Cloudflare proxy, the cache never helped to reduce the update times needed to refresh the static copy with new published content and HTTrack was almost crawling all over the website with every update.{{< /alert >}}

This can be connected with many elements, among them will that HTTrack is a relatively old software which didn’t receive any updates since 2017 therefore it’s support for the most recent changes in the web structure and technologies isn’t the best.

**One other element** _which will cause great impact and change of behavior in any tools doing the same functionality,_ will be dealing with different configuration and installations of Web servers, CMS, and security measurements.

**We encourage** you to dig deeper in HTTrack documentation to find options and arguments which can help to find the best suited configuration for your setup.

{{% alert title="Note" %}}When using HTTrack _- and almost any website downloader -,_ while you are using Cloudflare proxy and DDoS protection for your website, it’s highly important to set a `user-agent` in the arguments and make sure the chosen `user-agent` isn’t blocked in the security settings in your web server and Cloudflare.{{% /alert %}}

{{% alert title="Note" %}}**With big websites**, many security settings and tools might identify the constant crawling and multiple hits in short time intervals as malicious behavior and block or throttle your IP address's connection to the website.

**In that case** you should revise your security settings and find the maximum allowed connections then you can use arguments like `--max-rate=N`, `--connection-per-second=N`, `--max-pause=N` to limit HTTrack traffic hitting your website to the maximum allowed numbers.

Also, you should consider whitelisting your IP address in your security settings if the option exists.{{% /alert %}}
