Elatests
========
## How to use
Before using elatests, make sure that the libraries needed by the elatests are in the paths which the executable file can link with.

Elatests must be run with a configuration file which you can specify with the -c option. If you run elatests without specifying a configuration file, it will use tests.conf in the following paths in order: '.', '../etc/carrier', '/usr/local/etc/carrier', '/etc/carrier'. However, the last two paths will be neglected on Windows.

Elatests will start successfully if either you specify a configuration file or the tests.conf is found in any of those paths mentioned before. Otherwise, it will fail to start.

You can also use --cases or --robot option when starts elatests. If either of them is provided, only one of them will be started. If neither of them is provided, both the cases and the robot will be started.

For example, you can use the following commands to start elatests on Macintosh:
```shell
$cd CMAKE_INSTALL_PREFIX/bin
$DYLD_LIBRARY_PATH=../lib ./elatests [--cases | --robot] [-c CONFIG]
```

or the following commands on Linux:
```shell
$cd CMAKE_INSTALL_PREFIX/bin
$LD_LIBRARY_PATH=../lib ./elatests [--cases | --robot] [-c CONFIG]
```

or the following commands on Windows:
```shell
>cd CMAKE_INSTALL_PREFIX/bin
>elatests.exe [--cases | --robot] [-c CONFIG]
```

Remember to replace the CMAKE_INSTALL_PREFIX with the value you set when you build Carrier.
