# Bitcoin Utils in Crystal

## Genesis

This started with a port of [James D'Angelo's Python scripts](https://github.com/wobine/blackboard101) to [crystal-lang](https://crystal-lang.org).

Functionality:
 - generate public key
 - sign data
 - verify signature

 The basic unit tests in [spec/bitcoinutil_spec.cr](./spec/bitcoinutil_spec.cr) can be run using `crystal spec`.  The "generates public key JD" and "signs and verifies JD" checks expected values given parameters in JD's code.

## Contributors

- [packetzero](https://github.com/packetzero) Alex M - creator, maintainer
