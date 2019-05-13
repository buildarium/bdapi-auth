# bdapi-auth

> Buildarium Auth Backend

![Version](https://img.shields.io/badge/version-1.0.3-black.svg?longCache=true&style=flat-square)
[![Docker Cloud](https://img.shields.io/docker/cloud/build/buildarium/bdapi-auth.svg)](https://cloud.docker.com/u/buildarium/repository/docker/buildarium/bdapi-auth)
<!-- [![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m781258374-4099c727e3e333d16b40f870.svg?style=flat-square)](https://status.indie.casa) -->
<!-- [![Deployment](https://img.shields.io/badge/deployment-gcloud-1B9CE2.svg?longCache=true&style=flat-square)](http://cloud.google.com/) -->

[![Slack Channel](https://img.shields.io/badge/chat-on%20slack-%233D133D.svg?longCache=true&style=flat-square)](https://buildarium.slack.com/app_redirect?channel=bdapi)
[![Email](https://img.shields.io/badge/email-buck-blue.svg?longCache=true&style=flat-square)](mailto:buck@buildarium.com)
![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)

![Screenshot](https://i.imgur.com/QixTAZW.png)

---

## Table of Contents

- [bdapi-auth](#bdapi-auth)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Clone](#clone)
    - [Setup](#setup)
      - [Helpful Commands](#helpful-commands)
  - [Features](#features)
  - [Documentation](#documentation)
    - [Updating Remote PostgreSQL Database](#updating-remote-postgresql-database)
  - [Tests](#tests)
    - [Running unit tests](#running-unit-tests)
    - [Linting](#linting)
  - [Contributing](#contributing)
    - [Step 1](#step-1)
    - [Step 2](#step-2)
    - [Step 3](#step-3)
  - [Deployment](#deployment)
    - [Development Ecosystem](#development-ecosystem)
    - [Testing Ecosystem](#testing-ecosystem)
    - [Staging Ecosystem](#staging-ecosystem)
    - [Production Ecosystem](#production-ecosystem)
  - [Team](#team)
  - [FAQ](#faq)
  - [Support](#support)
  - [License](#license)

---

## Installation

### Clone

- Clone this repo to your local machine using `git@github.com:buildarium/bdapi-auth.git`

### Setup

[Install Docker](https://docs.docker.com/install/)

#### Helpful Commands

From here, you probably want to check out a branch other than `master`:

> View branches on the remote

```shell
$ git branch -v -a
```

> Checkout a branch (will copy to local if only on remote)

```shell
$ git checkout [BRANCH]
```

---

## Features

- Register account
- Login/recieve a generated "Authorization Token" that expires in 30 days
- Confirm email
- Forgot password
- Email notifications via SendGrid

## Documentation

*WIP*
<!-- Found [here](https://icapi-network-dot-indiecasa-core.appspot.com/docs) -->

### Updating Remote PostgreSQL Database

Generate a migration: `dotnet ef migrations add initial`

Get SQL script: `dotnet ef migrations script`

## Tests

### Running unit tests

*WIP*
<!-- > Execute the unit tests via [Karma](https://karma-runner.github.io)

```shell
$ make test
``` -->

### Linting

*WIP*
<!-- > Run linting tools as per the [Angular Style Guide](https://angular.io/guide/styleguide)

```shell
$ make lint
``` -->

---

## Contributing

> To get started...

Use the [Git Flow](https://nvie.com/posts/a-successful-git-branching-model/) branching model and [SemVer](https://semver.org/) for versioning.

### Step 1

- 👯 Clone this repo to your local machine

- 🔎 Ensure sure you have a local copy of the `develop` branch

```shell
$ git branch -a
* master
  remotes/origin/HEAD
  remotes/origin/master
  remotes/origin/develop
  ...
$ git checkout develop
Branch develop set up to track remote branch experimental from origin.
Switched to a new branch 'develop'
$ git branch
* develop
  master
```

- 🌱 Create a feature branch off the `develop` branch

```shell
$ git checkout -b myfeature develop
Switched to a new branch "myfeature"
```

### Step 2

- **HACK AWAY!** 🔨🔨🔨
- 📦 Deployments are automatic to the  [Testing Ecosystem](#deployment) whenever a commit is pushed

### Step 3

- 🏷 Decide the proper version number as per [SemVer](https://semver.org/) and edit `package.json`
    - Given a version number `MAJOR.MINOR.PATCH`, increment the:
        - `MAJOR` version when you make incompatible API changes
        - `MINOR` version when you add functionality in a backwards-compatible manner, and
        - `PATCH` version when you make backwards-compatible bug fixes.

`package.json`:

```json
{
  ...
  "version": "MAJOR.MINOR.PATCH",
  ...
}
```

-  👨‍🍳 Prepare the `develop` branch to be merged into and ensure it's up-to-date

```shell
$ git checkout develop
Switched to branch 'develop'
$ git pull
```

- 🔀 Merge your feature branch into `develop`

```shell
$ git merge --no-ff myfeature
Updating ea1b82a..05e9557
(Summary of changes)
$ git branch -d myfeature
Deleted branch myfeature (was 05e9557).
$ git push origin develop
```

> *The `--no-ff` flag causes the merge to always create a new commit object, even if the merge could be performed with a fast-forward. This avoids losing information about the historical existence of a feature branch and groups together all commits that together added the feature*

## Deployment

### Development Ecosystem

When developing locally, simply use:

```shell
$ docker-compose up
```

This will start build all necessary Docker images and start up any Docker container(s) necessary to run.

**Additionally, `docker-compose.yml` will automatically expose local ports for testing, and will mount the local code into the Docker container for hot reloads.**

*All you need to do is write code and test (hot reloading is enabled). You can view the running container at `http://localhost:5205`.*

### Testing Ecosystem

Commits submitted to the `develop` branch will automatically be built into a Docker image and pushed to the Docker container registry.

From there, we have a Digital Ocean droplet running [Watchtower](https://github.com/v2tec/watchtower), which will automatically pull new images from the Docker container registry and swap them out.

To ensure successful deployment to the Testing Ecosystem:

- Ensure the Dockerfile still builds a usable image

*You can view the running container at `http://test.buildarium.com:5205`.*

### Staging Ecosystem

Deployment to Staging is triggered manually with containers built from the  `release-*` branch.

To prepare for the Staging Ecosystem, it is a good idea to:

- All unit, integration, and e2e tests are passing
- Ensure new features are properly covered by appropriate tests
- Provide proper documentation for new features in the official docs
- Ensure new code abides by the style guide

### Production Ecosystem

Deployment to Production is triggered manually from the container registered from the `master` branch upon proper QA testing and when the time is right.

Don't fuck up.

---

## Team

| [**Buck Tower**](https://bucktower.net) | [**Michael Wlodawsky**](https://github.com/wlodawskymichael) |
| :---: | :---: |
| [![Buck Tower](https://avatars1.githubusercontent.com/u/1170938?v=3&s=200)](https://bucktower.net)| [![Michael Wlodawsky](https://avatars1.githubusercontent.com/u/27742630?v=3&s=200)](https://github.com/wlodawskymichael)|
| [`github.com/bucktower`](https://github.com/bucktower) | [`github.com/wlodawskymichael`](https://github.com/wlodawskymichael) |

---

## FAQ

- **How do I do *specifically* so and so placeholder?**
  - No problem! Just do this.

## Support

Reach out at one of the following places!

- Join the Slack channel [`#bdapi`](https://buildarium.slack.com/app_redirect?channel=bdapi)
- Email [`buck@buildarium.com`](mailto:buck@buildarium.com)

---

## License

- **[MIT](https://choosealicense.com/licenses/mit/)**
- Copyright 2019 © [Buildarium](https://buildarium.com).
