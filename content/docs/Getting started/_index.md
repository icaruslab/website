---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  Things you need to know before getting started
---

## Introduction and methodology

### What is the difference between Static and Dynamic websites

**Dynamic Websites** can be identified as Websites written in scripting languages which need to be processed on the server before sending the final outcome (Web Pages) to the user/browser.

Some examples of these languages would be PHP, Server-side Javascript, ASP etc.
Typically, most of the modern day widely used Content management systems such as WordPress and Drupal, use PHP as a backend language, which means they need a fully operational server in order to work.

**A static website** would be consisting of HTML and CSS and some client-side JavaScript variations, libraries, and frameworks, which could be served as it is to the browser which can process and render the required web pages from the code and display the final outcome to the user without the need for any server-side processing.


### Why would you need to convert your website to a static one

> **The main advantage static websites holds is the ability to be stored on and served from virtually any kind of online storage platform.**

In these guides we will be going through the process of converting your dynamic website to a static one, or more accurately “creating a static mirror of your dynamic website”, the reason behind that will that we will be using some circumvention techniques which depends on and utilizes technologies which doesn’t the capability of server-side processing, therefore, it won’t be able to serve any web pages written in languages depends on this capability.
One other main advantages would be security, speed, and overall performance. As static websites don't have to run on servers and all code runs and renders locally at the user's browser, that limits the attack surface significantly.

### What if you don’t want to abandon your CMS and fully migrate to a new stack

**It’s possible** to keep your current setup as it is if you are using a CMS such as WordPress or Drupal.
In which case we will go through the process of generating and maintaining a static mirror of your website. Throughout these guides, we will display different methods of achieving this task, with every method we will


### What is dynamic-mirroring

> **You can mirror a dynamic website in different ways without needing to generate a static clone of it.**

**One of these ways will be** creating a reverse-proxy server which acts as a middle box between the client and the origin server which hosts the website, the server in the middle will get the required URL from the client and contact the origin server to fetch the content and serve it to the user. In this method the reverse-proxy server will be reachable through a domain-name which isn’t blocked, this method is relatively easy to implement, but it’s easily blocked by blocking the domain name or the IP address of the proxy server.

**Another method will be** hosting a full copy of the original blocked website on the server and keeping it synchronized with the original server, this method needs certain access privileges to the origin server and it holds the same disadvantages of the first method. In many cases you can just keep changing the mirror server’s domain name and IP address whenever it gets blocked, but that can be inefficient in terms of both financial costs and usability.


{{< alert color="success" >}}**In our guides we will be introducing** a way of creating and maintaining a dynamic-mirror to any blocked website, the mirror will be hosted on Google Cloud Platform’s App Engine, and will be utilizing the ability to serve the website through a subdomain under *.appspot.com domain.{{< /alert >}}

### What is the level of technical expertise required in order to be able to implement the documented solutions

**Every published solution** will be labeled according to the level of technical knowledge required for it's implementation. Guides will be labeled in three different levels based on the required level of technical expertise you need to acquire/learn to be able to implement or develop the solution <span style="color:red"> **(Beginner - Intermediate - Advanced)** </span>
