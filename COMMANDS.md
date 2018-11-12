help - Display available commands list.<br>
clear - Clear log and output view in shell.<br>
clear [ log | out ] - Clear log or output view in shell.

address - Display own address.
nodeid - Display own node ID.
userid - Display own user ID.
me - Display own user ID, name, description, gender, phone, email and region.
me set [name | description | gender | phone | email | region] [Value] - Set own user details individually.
nospam - Display current nospam value.
nospam [Value] - Change nospam value to enforce address change.
presence - Display self presence.
presence [none | away | busy] - Change own presence.

fadd [Address] [Message] - Add new friend.
faccept [User ID] - Accept friend request.
fremove [User ID] - Remove friend.
friends - List all friends.
friend [User ID] - Display friend details.
label [User ID] [Name] - Add label to friend.
msg  [User ID] [Message] -  Send message to a friend.
invite [User ID] - Invite friend.
ireply [User ID] [confirm message | refuse reason] - Confirm or refuse invitation with a message.

gnew - Create new group.
gleave [Group ID] - Leave group.
ginvite [Group ID] [User ID] - Invite user to group.
gjoin [User ID] cookie - Group invitation from user with cookies.
gmsg [Group ID] [Message] - Send message to group.
gtitle [Group ID] - Display title of group.
gtitle [Group ID] [Title] - Set title of group.
gpeers [Group ID] - Display list of participants in group.
glist - Display list of joined group.

sinit - Initialize session.
snew  [User ID] - Start new session with user.
sadd [plain | reliable | multiplexing | portforwarding] - Add session properties.
sremove [Session ID] - Leave session.
srequest bundle - Bundle and start session
sreply [ok] - Accept session request.
sreply refuse [Reason] - Refuse session request with reason as a message.
swrite [Stream ID] [String] - Send data to stream.
sbulkwrite [Stream ID] [Packet size] [Packet count] -  Send bulk data to stream.
sbulkrecv [ start | end ] - Start or end receiving in bulk.
scadd [Stream] - Add stream channel.
sinfo [ID] - Display stream information.
scclose [Stream] channel - Close stream channel.
scwrite [Stream] channel [String] - Write to stream channel.
scpend [Stream] channel - Display pending stream channels.
scresume [Stream] channel - Resume stream.
sclose - Close session.
spfsvcadd [Name] [tcp|udp] [Host] [Port] - Add service to session.
spfsvcremove [Name] - Remove service from session.
spfopen [Stream] [Service] [tcp|udp] [Host] [Port] - Open portforwarding.
spfclose [Stream] [PF ID] - Close portforwarding.
scleanup - Cleanup session.
kill - Stop carrier.
