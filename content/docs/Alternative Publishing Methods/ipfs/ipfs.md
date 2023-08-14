---
title: "Interplanetary File System"
linkTitle: "IPFS"
weight: 4
description: >
  A peer-to-peer hypermedia protocol
---

Required expertise level : **Intermediate**

Platform : **Gnu/Linux | macOS | MS Windows | Android | BSD**

Last tested and confirmed : March 2022

-----

{{% alert title="Interplanetary File System - IPFS "%}}
**is A peer-to-peer hypermedia protocol** which is being introduced as the future successor of HTTP.

**Being built on the peer-to-peer data exchange system,** IPFS is practically difficult to block at least by current censorship techniques and standards, making it worth testing.
{{% /alert %}}

**While it's basically built as a data storage and distribution protocol,** makes the way it functions different than most current day web hosting and cloud functions today, where in most cases, websites are basically web applications which processes and renders on a server then send the resulted web pages to the user.

**In IPFS case,** there are no server nor processing capabilities, which mean that it's only capable of serving static or semi-static web pages, essentially anything which depends on client-side rendering and processing.
in this scenario, the browser gets to do most of job and IPFS just delivers raw files.

{{< alert >}}
To learn about **the difference between static and dynamic websites**, refer the [**Getting Started**](/docs/getting-started/#what-is-the-difference-between-static-and-dynamic-websites) section in the documentations.
{{< /alert >}}

----

## Installing IPFS

- **MS Windows**
  - Install the CLI tool using **[Chocolatey](https://chocolatey.org/packages/ipfs)** windows package manager `choco install ipfs`
  - Install the Desktop app (GUI) **[Chocolatey](https://chocolatey.org/packages/ipfs-desktop)** `choco install ipfs-desktop`
  - Or download the installation file directly from [IPFS website](https://ipfs.io/#install)


- **Gnu/Linux**
  - Download and run the installation script for the Command Line Interface - CLI - tool from [IPFS website](https://docs.ipfs.io/how-to/command-line-quick-start/#install-ipfs)
  - Download and run the installation package for the Graphical User Interface - GUI - desktop app from [GitHub](https://github.com/ipfs-shipyard/ipfs-desktop#install)

- **macOS**
  - Install using **[Homebrew](https://docs.brew.sh/Installation)** package manager. `brew install ipfs`
  - Download the Desktop app from [GitHub](https://github.com/ipfs-shipyard/ipfs-desktop#install)

![](/img/ipfs/1.png)IPFS Desktop app

----

## Adding your static mirror to IPFS

{{< alert >}}
**Adding your static mirror to IPFS** is a very simple process but there are some configuration which should be considered to make sure your website will be easily accessible.
{{< /alert >}}

- **After following [IPFS guides](https://docs.ipfs.io/how-to/command-line-quick-start/#initialize-the-repository) on how to get the application on your machine running, confirm**

```bash
❯ ipfs --version
ipfs version 0.6.0
```

- Using your termianl, go to your static mirror directory.
- Run `ipfs add -Q  --recursive --progress mystaticmirror `

![](/img/ipfs/2.png)

{{% alert title="IPFS will" %}}
start adding your files to it's [Datastore](https://docs.ipfs.io/concepts/glossary/#datastore), and creating a unique [hash](https://docs.ipfs.io/concepts/hashing/#hashes-are-important) for every file, the hash of the root directory will be the final output, this will be the address of your mirror on IPFS network.
{{% /alert %}}

- Now, we can try to access our mirror using IPFS and the hash of the root directory.

![](/img/ipfs/3.png)

**There are two ways of accessing files on IPFS**


- **Using a gateway**
  - IPFS Gateway  - [ipfs.io](https://ipfs.io)
  - CloudFlare Gateway - [cloudflare-ipfs.com](cloudflare-ipfs.com)
  - Pinata Gateway  - [gateway.pinata.cloud](https://gateway.pinata.cloud)

{{< alert >}}
There are several online gateways that provides a bridge between normal web and data stored on IPFS, you can do that by going to the gateway in your browser while appending **`/ipfs/QmYn4A9jzkXob1iUPuwjpqxaMkrwE54ywvJUv2cE1s4egE`** to the URL.
{{< /alert >}}

- **using the local client (peer-to-peer)**

{{< alert >}}
This is the method IPFS should be functioning essentially.

**You need to have IPFS installed on your machine for this method to work.**
{{< /alert >}}

- Install [**IPFS Companion**](https://github.com/ipfs-shipyard/ipfs-companion) browser extension and make sur IPFS is running on you machine.
- **When you enable the extension,** it detects if your local IPFS daemon is running in the background and automatically rewrites any IPFS URL that contains a valid hash to be fetched using your local IPFS installation.

![](/img/ipfs/4.png)

----

### Updating a website on IPFS


{{% alert title="Every time"%}}
 you update your static mirror with new content, you will need to add the new version to IPFS again.
{{% /alert %}}

**As we mentioned earlier,** IPFS depends on a hashing system to keep track of files, and since every file will create a unique hash, that means the final - root directory - hash will be different every time.

This situation **presents a usability issue,** as you will need somehow to share the new calculated hash with your audience every time you update your website, in order for them to be able to reach the most recent version of your website on IPFS.

#### Enters the Interplanetary Name System [(IPNS)](https://docs.ipfs.io/concepts/ipns/)

{{% alert title="IPNS"%}}
provides a solution similar to the regular web Domain Name System (DNS).
{{% /alert %}}

Using a locally generated key on your machine, IPNS will create a static hash, which will be published to the [Distributed hash table (DHT)](https://en.wikipedia.org/wiki/Distributed_hash_table), this key can be linked to another hash and store it as value.

Think about it (IPNS) as a domain name generator, it gives you a random hash, and register it in a table and store the most recent hash of your files as a value, IPFS users will just need the static IPNS hash to access your website.

- Generate a new IPFS key

`ipfs key gen --type=rsa --size=2048 mystaticsite`

![](/img/ipfs/5.png)The output will be your new IPNS address

- Publish your IPNS address and link it with your mirror's most recent hash.

`ipfs name publish --key=mystaticsite [replace with your files most recent hash]`

![](/img/ipfs/6.png)The output will confirmation for the linking between the IPNS address and the IPFS hash

- We can confirm that your new IPNS address is alive either by accessing it using a gateway i.e. | **`ipfs.io/ipns/[put your IPNS hash here]`** |, or **enable IPFS Companion browser extension** to be redirected automatically to your local gateway

![](/img/ipfs/7.png)

{{% alert title="Note"%}}
If you are adding large files/directories to IPFS.

it might be a good idea to add `--nocopy` parameter in the first step:

`ipfs add -Q  --recursive --nocopy --progress mystaticmirror `

this will tell IPFS not to make a full copy of every file in it's datastore and will just create the hashes and use the original files, **which will save disk space.**
{{% /alert %}}