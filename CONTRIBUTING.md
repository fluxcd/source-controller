# Contributing

Source Controller is [Apache 2.0 licensed](LICENSE) and accepts contributions
via GitHub pull requests. This document outlines some of the conventions on
to make it easier to get your contribution accepted.

We gratefully welcome improvements to issues and documentation as well as to
code.

## Certificate of Origin

By contributing to this project you agree to the Developer Certificate of
Origin (DCO). This document was created by the Linux Kernel community and is a
simple statement that you, as a contributor, have the legal right to make the
contribution. No action from you is required, but it's a good idea to see the
[DCO](DCO) file for details before you start contributing code to Source
Controller.

## Communications

The project uses Slack: To join the conversation, simply join the
[CNCF](https://slack.cncf.io/) Slack workspace and use the
[#flux](https://cloud-native.slack.com/messages/flux/) channel.

The developers use a mailing list to discuss development as well.
Simply subscribe to [flux-dev on cncf.io](https://lists.cncf.io/g/cncf-flux-dev)
to join the conversation (this will also add an invitation to your
Google calendar for our [Flux
meeting](https://docs.google.com/document/d/1l_M0om0qUEN_NNiGgpqJ2tvsF2iioHkaARDeh6b70B0/edit#)).

### Installing required dependencies

The dependency [libgit2](https://libgit2.org/) needs to be installed to be able to run
Source Controller or its test-suite locally (not in a container).

**macOS**
```
brew install libgit2
```

**Arch Linux**
```
pacman -S libgit2
```

**Building from source**

1. Ensure [`cmake`](https://cmake.org) is available on your system.
1. Download and unarchive [the right `libgit2` version](https://github.com/libgit2/git2go#which-go-version-to-use)
   for our current `git2go` dependency:

   ```console
   $ LIBGIT2_VER=1.1.0
   $ curl -L https://github.com/libgit2/libgit2/releases/download/v$LIBGIT2_VER/libgit2-$LIBGIT2_VER.tar.gz -o /tmp/libgit2.tar.gz
   $ tar -xvf /tmp/libgit2.tar.gz -C /tmp/libgit2-$LIBGIT2_VER
   ```
1. Build and install the library on your system:

   ```console
   $ mkdir /tmp/libgit2-$LIBGIT2_VER/build && cd /tmp/libgit2-$LIBGIT2_VER/build
   $ cmake .. -DCMAKE_INSTALL_PREFIX=/usr
   $ sudo cmake --build . --target install
   ```

### How to run the test suite

You can run the unit tests by simply doing

```bash
make test
```

## Acceptance policy

These things will make a PR more likely to be accepted:

- a well-described requirement
- tests for new code
- tests for old code!
- new code and tests follow the conventions in old code and tests
- a good commit message (see below)
- all code must abide [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- names should abide [What's in a name](https://talks.golang.org/2014/names.slide#1)
- code must build on both Linux and Darwin, via plain `go build`
- code should have appropriate test coverage and tests should be written
  to work with `go test`

In general, we will merge a PR once one maintainer has endorsed it.
For substantial changes, more people may become involved, and you might
get asked to resubmit the PR or divide the changes into more than one PR.

### Format of the Commit Message

For Source Controller we prefer the following rules for good commit messages:

- Limit the subject to 50 characters and write as the continuation
  of the sentence "If applied, this commit will ..."
- Explain what and why in the body, if more than a trivial change;
  wrap it at 72 characters.

The [following article](https://chris.beams.io/posts/git-commit/#seven-rules)
has some more helpful advice on documenting your work.
