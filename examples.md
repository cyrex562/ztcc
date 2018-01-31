```
curl -X POST --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" -d '{"authorized": "true", "ipAssignments": ["10.8.10.4"]}' http://localhost:9993/controller/network/5433b56615c0f45c/member/5433b56615
```

5433b56615c0f45c

```
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c/member/5433b56615
```

```
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c/member/
```

```
curl -X POST --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" -d '{"authorized": "true", "ipAssignments": ["10.8.10.5"]}' http://localhost:9993/controller/network/5433b56615c0f45c/member/4a49696d9b
```

"4a49696d9b"
```
curl -X POST --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" -d '{ "routes": [{"target": "10.8.10.0/24", "via": null}]}' http://localhost:9993/controller/network/5433b56615c0f45c
```

4ebbd51be0

```
curl -X POST --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" -d '{"ipAssignments": []}' http://localhost:9993/controller/network/5433b56615c0f45c/member/4ebbd51be0
```
```
curl -X POST --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" -d '{"ipAssignments": []}' http://localhost:9993/controller/network/5433b56615c0f45c/member/4a49696d9b
```

# network list
```
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network
```

# network info
```
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c
```

```json
{ "capabilities": [], 
  "v6AssignMode": { "zt": "false", 
                    "rfc4193": "false", 
                    "6plane": "false"}, 
  "routes": [{"via": "null", "target": "10.8.10.0/24"}], 
  "ipAssignmentPools": [{"ipRangeStart": "10.8.10.1", "ipRangeEnd": "10.8.10.254"}], 
  "totalMemberCount": 0, 
  "activeMemberCount": 2, 
  "private": "true", 
  "authorizedMemberCount": 5, 
  "revision": 4, 
  "clock": 1517417650557, 
  "v4AssignMode": {"zt": "true"}, 
  "rules": [{"or": "false", "type": "ACTION_ACCEPT", "not": "false"}], 
  "tags": [], 
  "id": "5433b56615c0f45c", 
  "multicastLimit": 32, 
  "authTokens": [], 
  "enableBroadcast": "true", 
  "nwid": "5433b56615c0f45c", 
  "objtype": "network", 
  "creationTime": 1516719152759, 
  "lastModified": 1516802744897, 
  "name": "parrylabs test network"
  }

```

# member list
```commandline
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c/member
```

# member get
```commandline
curl -X GET --header "X-ZT1-Auth: k17yjpeky7b38qxg5pxua2fk" http://localhost:9993/controller/network/5433b56615c0f45c/member/4a49696d9b
```


# update network name
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --name network_2

```

# change network privacy
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --private
```

```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --not-private
```

# enable broadcast
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --enable_broadcast
```

# disable broadcast
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --disable_broadcast
```

# enable v4 address assignment
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --enable_v4_assign
```

# disable v4 address assignment
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --disable_v4_assign
```

# add ip pool
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --ip_pool_add 10.99.99.1:10.99.99.254
```

# delete ip pool
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --ip_pool_del 10.99.99.1:10.99.99.254
```

# set ip pool
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --ip_pool_set 10.8.10.1:10.8.10.254
```

# add internal route
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --route_add 10.99.97.0/24
```

# delete internal route
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --route_del 10.99.97.0/24
```

# set internal routes
```commandline
network update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --route_del 10.8.10.0/24
```

# add external route
# delete external route

# list members of a network
```commandline
member list --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c
```

# get info on network member
```commandline
member get --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0
```

```json
{
 "authHistory": [
  {
    "a": "true", 
    "by": "api", 
    "ct": "null",
     "ts": 1516803695668, 
     "c": "null"
  }
  ], 
  "id": "4ebbd51be0", 
  "revision": 2, 
  "nwid": "5433b56615c0f45c", 
  "lastAuthorizedTime": 1516803695668, 
  "tags": [], 
  "lastRequestMetaData": "v=7\nvend=1\npv=9\nmajv=1\nminv=2\nrevv=4\nmr=400\nmc=80\nmcr=40\nmt=80\nf=0\nrevr=1", 
  "ipAssignments": [
  "10.8.10.188"
  ], 
  "creationTime": 1516725275018, 
  "identity": "4ebbd51be0:0:fec053c979e89cd45e27a8dd7f0d089243608c0901ab7fb122d52ba971906721901a42e752b01e30c2fc29616a79a68a5369b27f194b5a37d69a23e49ee25cdd",
  "recentLog": [
      {
        "authBy": "memberIsAuthorized", 
        "auth": "true", 
        "fromAddr": "10.2.1.56/9993", 
        "vProto": 9, 
        "vRev": 4, 
        "vMajor": 1, 
        "ts": 1516893143023, 
        "vMinor": 2
      }, 
      {
        "authBy": "memberIsAuthorized", 
        "auth": "true", 
        "fromAddr": "10.2.1.56/9993", 
        "vProto": 9, 
        "vRev": 4, 
        "vMajor": 1, 
        "ts": 1516893080100, 
        "vMinor": 2}
  ], 
  "address": "4ebbd51be0", 
  "noAutoAssignIps": "false", 
  "clock": 1517424463858, 
  "capabilities": [], 
  "lastModified": 1516893143023, 
  "authorized": "true", 
  "lastDeauthorizedTime": 0, 
  "objtype": "member", 
  "activeBridge": "false"
  }
```

# de-authorize a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --not_authorized
```

# authorize a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --authorized
```

# enable active bridging for a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --enable_active_bridging
```

# disable active bridging for a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --disable_active_bridging
```

# assign a managed ip to a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --ip_add 10.99.98.91
```

# delete a member's managed ip
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --ip_add 10.99.98.91
```

# set the list of assigned managed ips for a member
```commandline
member update --auth_token k17yjpeky7b38qxg5pxua2fk --network 5433b56615c0f45c --member 4ebbd51be0 --ip_set 10.99.98.91
```



