08/19/2019 Li Fenxiang lifenxiang@elastos.org

**version 5.4.0**, main changes to previous version:

```markdown
- Introduce "include" directive in config file to import content of other config files. 
- API changes in sending/receiving messages.
```

08/05/2019 Li Fenxiang lifenxiang@elastos.org

**version 5.3.4**, main changes to previous version:

```markdown
- Make compiling options take effect in global scope.
- Improve the initialization procedure of dstore on Hive SDK.
```

05/29/2019 Chen Yu chenyu@gmail.com

**version 5.3.3**, main changes to previous version:

```markdown
- Update dependency libcrystal to v1.0.5.
```

05/14/2019 Chen Yu chenyu@gmail.com

**version 5.3.2**, main changes to previous version:

```markdown
- Update CI scripts for configuring android ndk for different arches;
- Fix crash issue for using C++ libraries on android armeabi-v7a platform;
- Correct reference count of using carrier instance;
- Change back to use static libraries on Android platform to resolve crash issue.
```
05/06/2019 Chen Yu chenyu@gmail.com

**version 5.3.1**, main changes to previous version:

```markdown
- Update CI to upgrade sphinx version for building API docs;
- Update dependency hive to release-v0.1.1;
- Support offline message sending/receiving;
- Add special test case to verify offline message;
- Resize the hash table size to fit best performance;
- Add bulkmsg command into elashell app.
```
04/10/2019 Tang Zhilong stiartsly@gmail.com

**version 5.2.4**, main changes to previous version:

```markdown
- Export only static libraries for iOS, and static/dynamic libraries for other platforms;
- Update dependency cygwin to 3.0.6-1 for windows platform;
- Update dependency libcrystal to v1.0.4.
```

03/18/2019 Tang Zhilong stiartsly@gmail.com

**version 5.2.3**, main changes to previous version:

```markdown
- Fix ios cross-compilation issue for some macos environment;
- Fix issue for calling open_portforwarding and close_portforwarding in stream without PORTFORWARDING option;
- Update dependency cygwin libraries need on Windows platforms;
- Fix issue of implementing ela_get_version().
```

03/02/2019 Tang Zhilong stiartsly@gmail.com

**version 5.2.2**, main changes to previous version:

```markdown
- Update checksum SHA256 of depedency libcrystal and it's download address;
- Update License to be GPLv3 with regards to c-toxcore project.
```

01/25/2019 Tang Zhilong <stiartsly@gmail.com>
**Version 5.2.1**, main changes to previous version: 

	- Refactored origin scripts-based build system to CMake-based build system;
	- Support Carrier SDK implementation on Windows platform (x86/x64);
	- Support carrier group without central administration, and group peers should be required connected 		to carrier network;
	- Support file transfer between two peers with pull-driven and resume from break-point enabled.
	- Support for session to have it's own cookie or bundle data;
	- Enlarge the data capacity when using API of sending invitation request/reply with data;
	- Refactored error codes and added APIs to get error description from error number;
	- Add testsuite to verify feature of group and file transfer;
	- Add app demo "elafile" demonstrate how we use APIs of file transfers;
	- Add command tool "elaerr" to check what error description to specific carrier errno number;
	- Upgrade underlying dependency project - toxcore.
	- Optimizations and bugfixes to origin carrier/session/stream;
	- Support CI for all platforms (Linux/Macos/Windows/Android/iOS)

08/14/2018 Tang Zhilong <stiartsly@gmail.com>
**Version 5.1**, main changes listed:

	- Carrier: peer to peer message framework.
	- Session: peer to peer session framework (Oriented to stream of transferring data)

