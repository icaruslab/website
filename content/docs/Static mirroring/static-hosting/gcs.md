---
title: "Hosting on Google Cloud Storage"
linkTitle: "Google CS"
weight: 9
description: >
  A guide on hosting a static website on Google Cloud Storage.
---
Required expertise level : **Intermediate**

Platform : **Any**

Last tested and confirmed : January 2022

-----

{{< alert >}}
>**Google Cloud Storage** is **object storage service** similar to Amazon S3, and it provides the ability to serve static web pages as well.
{{< /alert >}}

The **main** advantage of using Google Cloud Storage to host our static mirror is the ability to serve a fully functional **"static"** web pages directly using Google Cloud Platform URLs which usually looks like this: `https://storage.googleapis.com/[bucketname]`

-----

## Configure static site hosting on Google Cloud Storage

### Creating GCS bucket, and setting permissions

- **First,** you need to create an account on __[Google Cloud Platform](https://cloud.google.com/)__, you will need to create a Google account for this.

{{% alert title="Note" %}}
 **While it's possible to use a pre-existing Google account for this step, it's better to create a new one just for this purpose**.
 {{% /alert %}}

![](/img/hosting-gcs/1.png)

- Log in to **[Google Cloud Console](https://console.cloud.google.com/)** using your newly created account.

![](/img/hosting-gcs/2.png)

- Here, you'll need to open **Storage** from the side bar to access [**Google Cloud Storage**](https://console.cloud.google.com/storage) settings page.

![](/img/hosting-gcs/3.png)Create a new bucket here

![](/img/hosting-gcs/4.png)Buck name

- First step will be choosing your bucket name, **bucket names should be unique and you'll use it to access your static website later**.

![](/img/hosting-gcs/5.png)Region settings

- Unless you know what you are doing, there is no need to change anything here.

![](/img/hosting-gcs/6.png)Storage Class

- In most cases it should be **Standard**.

![](/img/hosting-gcs/7.png)Access control

- We will be handling permissions and access control configurations later on, so we'll leave it unchanged for now.

![](/img/hosting-gcs/8.png)Encryption

- As this bucket will be publicly available, we don't need to change anything with Encryption settings.

{{< alert >}}
**Now, we can go proceed to the new bucket settings page.**
{{< /alert >}}

![](/img/hosting-gcs/9.png)

-----

### Upload the static website

{{< alert >}}
**While you can upload your static website using the web interface, it's preferred to do that using Google Cloud SDK, specially if you are planning on updating your mirror with new content frequently.**
{{< /alert >}}

#### [Install Google Cloud SDK Command Line Interface](https://cloud.google.com/sdk/install)

**Installing Google Cloud SDK** is pretty straight forward process. Simply, follow the instructions related to your operating system in this [**guide**](https://cloud.google.com/sdk/install) and you will be good to go.

### Upload using Google Cloud SDK CLI

- After installing Google Cloud Sdk, you will need to authorize the local client to connect to you Google Cloud account, you can do that by opening your terminal and entering `gcloud init`

![](/img/hosting-gcs/10.png)

- After **Successfully logging in to your account**, you will be asked to select the project you want to use, if you didn't create a new project you can do that now using the local CLI.

![](/img/hosting-gcs/11.png)

{{< alert >}}
**Now, you can use your local CLI to upload the static mirror to the newly created bucket.**
{{< /alert >}}

- Using your terminal, change directory to the static mirror files location, and enter `gsutil rsync -R [local-dir] gs://[bucketname]`

{{% alert color="warning" title="Note" %}}
**Replace `[local-dir]` with the static mirror directory name and `[bucketname]` with the bucket name.**
{{% /alert %}}

![](/img/hosting-gcs/12.png)Uploading files

- Now if you go to your bucket settings page, you will notice the static mirror files are uploaded.

![](/img/hosting-gcs/13.png)

- Final step will be **setting public permissions** to the files so the static mirror will be accessible to public internet, you can do that using the local CLI by entering `gsutil iam ch allUsers:objectViewer gs://[bucketname]`

{{% alert color="warning" title="Note" %}}
**Replace `[bucketname]` with your bucket name.**
{{% /alert %}}

Now you can access your static mirror using this URL scheme `https://storage.googleapis.com/[bucketname]/index.html`

{{% alert color="warning" title="Note" %}}
**Replace `[bucketname]` with your bucket name.**
{{% /alert %}}

![](/img/hosting-gcs/14.png)

{{< alert title="Updating the static mirror" >}}
**Updating your static mirror with new content** will be as simple as going to the mirror's local directory on your terminal and executing `gsutil rsync -R [local-dir] gs://[bucketname]` every time.
{{< /alert >}}