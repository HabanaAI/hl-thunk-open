# Overall Package Version

This version number is set in the top level CMakeLists.txt:

```sh
set(PACKAGE_VERSION "11")
````

For upstream releases this is a single integer showing the release
ordering. We do not attempt to encode any 'ABI' information in this version.

Branched stabled releases can append an additional counter eg `11.2`.