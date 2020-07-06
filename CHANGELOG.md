07/06/2020 Meng Xiaokun mengxiaokun@trinity-tech.io

**version 5.6.2**, main changes to previous version:

```markdown
- Update libsodium to 1.0.18.
- Fix crash issue when online message send timeout.
```

06/18/2020 Meng Xiaokun mengxiaokun@trinity-tech.io

**version 5.6.1**, main changes to previous version:

```markdown
- Support to disabling offline message.
- Resolve internal memory leakage issues.
- Fix curl dependencies.
- update libressl to v2.9.2.
- Update Dockerfile to ubuntu:18.04 and correct docs variable reference.
- update flatcc to 0.6.0.
- Fix connector destroy bug.
- Support pre-defined secret key.
- fix send_friend_message side issue.
- Improving express node access order.
- Fix ios static library install issue.
- Fix receipt thread sync issue.
```


05/27/2020 Meng Xiaokun mengxiaokun@trinity-tech.io

**version 5.6.0**, main changes to previous version:

```markdown
- Add bulkmsg receipt testcases.
- Remove copilation error for windows platform.
- Add express node config.
- Add speed meter for express ndoe.
- Update libcurl and enable ssl for express server.
- Add friend receipt testcases and several bugfixes..
- Improving implementation of offmsg/offreq/offreceipt callbacks.
- Improving configure express nodes and removing original hive bootstrap configuration.
- improving func 'on_friend_message_receipt' and remove useless internal functions.
- Improve generate_msgid and dht_friend_message functions.
- Improve implementation of common func 'send_friend_message_internal' and internal called functions.
- Improve implementation of receipt acknoledges.
- convert receipt list to hashtable and bugfixes.
- combin send message and send receipt message.
- Add express, post/pull/delete offline message, request/onrequest friend.
```


04/26/2020 Meng Xiaokun mengxiaokun@trinity-tech.io

**version 5.5.1**, main changes to previous version:

```markdown
- Support with carrier extension especially used for webrtc
- Improve implementation of bulk message sending/receiving
- Support feature of sending/receiving big data block (1K~5M)
- Turn off to run elatets in travis CI and circle CI
- fix group info store issue when killed by system.
- Update reference location of dependency CUnit release package
- This is a combination of 2 commits.
- Try to leave all groups before start to test ela_get_groups APIs because of group persistence
```

03/23/2019 Li Fenxiang lifenxiang@trinity-tech.io

**version 5.5.0**, main changes to previous version:

```markdown
- Correct default port value for IPFS node service.
- Fix cmake typo.
- Update cygwin.
- Allow ela_get_groups() to be called in the whole lifecycle of carrier due to introduction of persistent group.
```

10/22/2019 Li Fenxiang lifenxiang@elastos.org

**version 5.4.2**, main changes to previous version:

```markdown
- Introduce persistent group. Messages generated during offline time are not delivered once online again.
- Add to support notification of friend request with different greeting message.
```

09/19/2019 Li Fenxiang lifenxiang@elastos.org

**version 5.4.1**, main changes to previous version:

```markdown
- Offline messaging change to use Solo dstore implementation other than to use Hive SDK.
- Fix typo in root CMakeLists.txt of toxcore.
```

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

