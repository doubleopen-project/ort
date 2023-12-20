# About

This is a package manager plugin for the [OSS Review Toolkit][ORT] to analyze [Yocto] projects managed by [BitBake]. It
supersedes the combination of the [meta-doubleopen] and [do-convert] projects by relying on upstream [SBOM] generation
in [SPDX] format, and converting that to an ORT analyzer result file.

# Usage

As a prerequisite, ensure that the `bitbake` tool is installed on your Linux system and that its executable is in your
`PATH` environment. Then copy the JAR file built by this project to the "plugin" directory of your ORT installation and
run the ORT analyzer on a directory containing a Yocto project with `*.bb` files.

[ORT]: https://github.com/oss-review-toolkit/ort
[BitBake]: https://docs.yoctoproject.org/bitbake.html
[Yocto]: https://www.yoctoproject.org/
[meta-doubleopen]: https://github.com/doubleopen-project/meta-doubleopen
[do-convert]: https://github.com/doubleopen-project/do-convert
[SBOM]: https://docs.yoctoproject.org/dev/dev-manual/sbom.html
[SPDX]: https://spdx.dev/
