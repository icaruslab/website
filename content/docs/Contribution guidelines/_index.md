---
title: "Contribution Guidelines"
linkTitle: "Contribution Guidelines"
weight: 10
description: >
  How to contribute to the docs
---

{{% pageinfo %}}
This project is hoping to create a knowledge repository of accumulated experience in the fight for a free and open Internet. All our documentations, guides, code, and research are published under [GNU General Public License (GPLv3)](https://www.gnu.org/licenses/quick-guide-gplv3.html)

We welcome and appreciate any contributions, suggestions, and critique.
{{% /pageinfo %}}

We use [Hugo](https://gohugo.io/) to format and generate our website, the
[Docsy](https://github.com/google/docsy) theme for styling and site structure,
and [GitHub](https://www.github.com/) to deploy and host the site.


[Hugo](https://gohugo.io/) is an open-source static site generator that provides us with templates,
content management in a standard directory structure, and a website generation
engine. You write the pages in Markdown (or HTML if you want), and Hugo wraps them up into a website.

{{< alert >}}
**This Project and all it's related materials are hosted on [GitHub](https://github.com/icaruslab).**

We use GitHub pull requests to receive contributions and submissions,  Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.
{{< /alert >}}

## Creating an issue

If you've found a problem in the docs, but you're not sure how to fix it yourself, please create an issue in the [Documentations repo](https://github.com/icaruslab/docs/issues). You can also create an issue about a specific page by clicking the **Create Issue** button in the top right hand corner of the page.

## Useful resources

* [Docsy user guide](https://www.docsy.dev/docs/): All about Docsy Hugo theme, including how it manages navigation, look and feel, and multi-language support.
* [Hugo documentation](https://gohugo.io/documentation/): Comprehensive reference for Hugo.
* [Github Hello World!](https://guides.github.com/activities/hello-world/): A basic introduction to GitHub concepts and workflow.


## Updating a single page

If you've just spotted something you'd like to change while using the docs, Docsy has a shortcut for you:

1- Click **Edit this page** in the top right hand corner of the page.
2- If you don't already have an up to date fork of the project repo, you are prompted to get one - click **Fork this repository and propose changes** or **Update your Fork** to get an up to date version of the project to edit. The appropriate page in your fork is displayed in edit mode.

## Previewing your changes locally

If you want to run your own local Hugo server to preview your changes as you work:

1- Follow the instructions here [Getting started](https://gohugo.io/getting-started/quick-start/) to install Hugo and any other tools you need. You'll need at least **Hugo version 0.45** (we recommend using the most recent available version), and it must be the **extended** version, which supports SCSS.

2- Fork the [project website repository](https://github.com/icaruslab/docs) repo into your own project, clone it to your local machine

```bash
git clone [your fork address]
```

3- Run `hugo server` in the site root directory.

>By default your site will be available at http://localhost:1313/. Now that you're serving your site locally, Hugo will watch for changes to the content and automatically refresh your site.

4- Continue with the usual [GitHub workflow](https://guides.github.com/activities/hello-world/) to edit files, commit them, push the changes up to your fork, and create a pull request.

## Localization

We hope our documentations will be accessible to as many people as possible, if you find it useful and willing to localize it to unavailable language, or have suggestions to improve an existing translation, we welcome and appreciate your efforts, we use [GitHub workflow](https://guides.github.com/activities/hello-world/).

After forking the website repository to your own project/account

- Create a directory under `content` i.e. `content/ar`
- Add the new language under `[languages]` in `config.toml`

### Example of the required values

```toml
[languages.en]
		title = "Icarus Project"
		description = "Testign and documenting Internet censorship circumvention techniques"
		languageName ="English"
		languagedirection = "ltr"
		contentDir = "content/en"
    weight = 1
    time_format_default = "02.01.2006"
		time_format_blog = "02.01.2006"
```
- Follow [Docsy's guide](https://www.docsy.dev/docs/language/#internationalization-bundles) on how to translate the theme's UI strings (text for buttons etc.)
- Submit your changes in a pull request

### available Languages

- [ ] Arabic (coming soon!)

- [x] English