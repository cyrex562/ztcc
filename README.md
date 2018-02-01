# ZTCC: ZeroTier Console Command-line tool
ztcc provides a wrapper around the ZeroTier REST API for controlling a self-hosted ZeroTier controller. The intent of ztcc is to provide a command-line tool in the style of OpenStack's tools that enables straightforward interaction of the ZeroTier REST API from the command line.

## Getting Started

### Prerequisites
The up to date list of prerequisites for running the python can be found in requirements.txt. Running ztcc requires access to a functioning install of of ZeroTier, generally on the same host.

### Installing
1. Install ZeroTier on the host see: https://www.zerotier.com/download.shtml for more information.
2. Clone this repository
3. Install any prerequisites from requirements.txt

## Running the tests
1. Create a YAML file with sample data
2. run `pytest test_ztcc.py`

## Deployment
ztcc can read things like the auth token other values as environment variables:
* `ZTCC_PORT`: the port to contact the ZeroTier controller on, default is 9993.
* `ZTCC_HOST`: the hostname/ip address to contact the ZeroTier controller at, default is `localhost`.
* `ZTCC_AUTH_TOKEN`: the Auth Token used to authenticate with the controller. For security sake, do not hard code this in a launch or service script, use it for sessions only.
* `ZTCC_NET`: The Network ID of the network you wish to get information on or modify. 
* `ZTCC_CONTROLLER`: The Member ID of the instance of ZeroTier acting as a controller. 
NOTE: Environment variables take precedence over command line parameters.

## Commands

### List Networks Hosted by the Controller
```commandline
network list --auth_token AUTH_TOKEN 
```

### Get Information for a Network
```commandline
network get --auth_token AUTH_TOKEN --network NETWORK_ID
```

### Create a Network
```commandline
network create --auth_token AUTH_TOKEN --controller CONTROLLER_ID
```

### Delete a Network
```commandline
network delete --auth_token AUTH_TOKEN --network NETWORK_ID
```

### Set the Network's Name
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --name NETWORK_NAME
```

### Change the Network's Privacy
#### Private
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --private
```

#### Not Private
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --not-private
```

### Enable Ethernet Broadcast
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --enable_broadcast
```

### Disable Ethernet Broadcast
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --disable_broadcast
```

### Enable IPV4 Address Assignment
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --enable_v4_assign
```

### Disable IPV4 Address Assignment
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --disable_v4_assign
```

### Add One or More IP Address Pools
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --ip_pool_add POOL_START_IP:POOL_END_IP
```

### Delete One or More IP Address Pools
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --ip_pool_del POOL_START_IP:POOL_END_IP
```

### Add One or More Internal Routes
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --route_add NETWORK_IP/MASK_BITS
```

### Delete One or More Internal Routes
```commandline
network update --auth_token AUTH_TOKEN --network NETWORK_ID  --route_del NETWORK_IP/MASK_BITS
```

### Add One or More External Routes
### Delete One or More External Routes

### Get a List of Network Members
```commandline
member list --auth_token AUTH_TOKEN --network NETWORK_ID
```

### Get Info for a Network Member
```commandline
member get --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID
```

### De-Authorize a Network Member
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --not_authorized
```

### Authorize a Network Member
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --authorized
```

### Enable Active Bridging for a Network Member
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --enable_active_bridging
```

### Disable Active Bridging for a Network Member
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --disable_active_bridging
```

### Assign One or More Managed IPs to a Network Member
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --ip_add MANAGED_IP
```

### Delete One or More Network Member's Managed IPs 
```commandline
member update --auth_token AUTH_TOKEN --network NETWORK_ID  --member MEMBER_ID --ip_del MANAGED_IP
```

## Built With
* [ZeroTier](https://www.zerotier.com): The target application 
* [Requests](http://docs.python-requests.org/en/master/)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2): Excellent github README template 

## License
This project is licensed under the xxx license - see the LICENSE.MD file for details

## Contributing
Submit pull requests or issues to this github page.

## Versioning
ztcc uses semantic versioning. For release versions, check the tags in this repository.

## Authors
* Josh Madden - Initial work - [cyrex562](https://github.com/cyrex562)





