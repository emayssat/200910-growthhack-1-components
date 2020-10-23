# Growth-hack: Close-up view of the IAM service's components

In this demo, we will use the command line to deploy and interact with the individual components of our IAM service.
We will learn
* How to start the IAM service
* How to attest an agent, extend the trust domain, using the one-time token method
* How to create a workload profile
* How to match the profile, obtain a certificate, generate a JWT to assert a workload identity

## High level architecture

During the growth hack presentation, we discussed the architecture of our IAM service.

![spiffe_architecture](./.images/640/spiffe_architecture.png)

In this demo, we will deploy our IAM service and interact with individual components, including
1. a server process at the core of our IAM service
2. an agent process responsible for workload attestation
3. an ephemeral workload, simulated with the command line

All of the above will be executed in a pre-configured development environment, a pre-built container.
The architecture diagram for this demo looks as follow.

![spiffe_cli_workload](./.images/640/spiffe_cli_workload.png)

Let's get started!

## Development environment

The first step is to build and deploy the pre-configured development environment

```bash
docker build -t paasteurizers/spire-dev:v1 .
# Sending build context to Docker daemon  116.3MB
# Step 1/5 : FROM spire-dev:latest
#  ---> ec7333adc957
# Step 2/5 : RUN apt-get install -y curl vim
#  ---> Using cache
#  ---> b6e77b656f29
# Step 3/5 : WORKDIR /root/spire
#  ---> Using cache
#  ---> c6261345b20f
# Step 4/5 : ENTRYPOINT ["/bin/sleep"]
#  ---> Using cache
#  ---> cf419f42d111
# Step 5/5 : CMD ["infinity"]
#  ---> Using cache
#  ---> 485e3cbf8abe
# Successfully built 485e3cbf8abe
# Successfully tagged paasteurizers/spire-dev:v1

docker run --detach --rm --name paasteurizers-spire-dev --volume `pwd`:/root/spire paasteurizers/spire-dev:v1
# 96ec58b679a06fc7c65a843fb116318f41f2bffaa417bfe8c40a43de0307b95b
```

Once the container is running, exec into it

```bash
docker exec -it paasteurizers-spire-dev  /bin/bash
# root@96ec58b679a0:~/spire#
```

You have successfully logged on our demo environment

## Start the IAM service

### First let's start the identity server

Let's first look at the configuration of the server 

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

cat etc/server/server.conf
# server {
#     bind_address = "127.0.0.1"         <== running on localhost at port 8081
#     bind_port = "8081"
#     registration_uds_path = "/tmp/spire-registration.sock"
#     trust_domain = "paasteurizers.iam"      <== trust domain
#     data_dir = "./.data"
#     log_level = "DEBUG"
#     upstream_bundle = true
#     default_svid_ttl = "1h"       <== Time to live for the SPIFFE Verifiable Identity Document
#     ca_subject = {
#         country = ["US"],
#         organization = ["SPIFFE"],
#         common_name = "",
#     }
# }
# 
# plugins {
#     DataStore "sql" {
#         plugin_data {
#             database_type = "sqlite3"      <== Where all the identities in the trust domain are saved (aka domain state)
#             connection_string = "./.data/datastore.sqlite3"
#         }
#     }
# 
#     NodeAttestor "join_token" {     <== This server can attest agents using tokens
#         plugin_data {
#         }
#     }
# 
#     NodeResolver "noop" {
#         plugin_data {}
#     }
# 
#     KeyManager "memory" {
#         plugin_data = {}
#     }
# 
#     UpstreamCA "disk" {          <== Keep this information very secure!
#         plugin_data {
#             key_file_path = "./etc/server/dummy_upstream_ca.key"
#             cert_file_path = "./etc/server/dummy_upstream_ca.crt"
#         }
#     }
# }
```

Now let's start the identity service as a background process

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

./bin/spire-server run --config ./etc/server/server.conf &
[1] 24
root@4de1a3cc2473:~/spire# WARN[0000] Current umask 0022 is too permissive; setting umask 0027.
# INFO[0000] data directory: "./.data"
# INFO[0000] Opening SQL database                          db_type=sqlite3 subsystem_name=built-in_plugin.sql
# INFO[0000] Initializing database.                        subsystem_name=built-in_plugin.sql
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=sql plugin_services="[]" plugin_type=DataStore subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=join_token plugin_services="[]" plugin_type=NodeAttestor subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=noop plugin_services="[]" plugin_type=NodeResolver subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=memory plugin_services="[]" plugin_type=KeyManager subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=disk plugin_services="[]" plugin_type=UpstreamCA subsystem_name=catalog
# INFO[0000] plugins started
# DEBU[0000] Loading journal                               path=.data/journal.pem subsystem_name=ca_manager
# INFO[0000] Journal loaded                                jwt_keys=0 subsystem_name=ca_manager x509_cas=0
# DEBU[0000] Preparing X509 CA                             slot=A subsystem_name=ca_manager
# INFO[0000] X509 CA prepared                              expiration="2020-09-10T19:16:50Z" issued_at="2020-09-09T19:16:50Z" self_signed=false slot=A subsystem_name=ca_manager upstream_bundle=true
# INFO[0000] X509 CA activated                             expiration="2020-09-10T19:16:50Z" issued_at="2020-09-09T19:16:50Z" slot=A subsystem_name=ca_manager
# DEBU[0000] Successfully rotated X.509 CA                 subsystem_name=ca_manager trust_domain_id="spiffe://paasteurizers.iam" ttl=86399.8593326
# DEBU[0000] Preparing JWT key                             slot=A subsystem_name=ca_manager
# INFO[0000] JWT key prepared                              expiration="2020-09-10T19:16:50Z" issued_at="2020-09-09T19:16:50Z" slot=A subsystem_name=ca_manager
# INFO[0000] JWT key activated                             expiration="2020-09-10T19:16:50Z" issued_at="2020-09-09T19:16:50Z" slot=A subsystem_name=ca_manager
# DEBU[0000] Rotating server SVID                          subsystem_name=svid_rotator
# DEBU[0000] Signed X509 SVID                              expiration="2020-09-09T20:16:50Z" spiffe_id="spiffe://paasteurizers.iam/spire/server" subsystem_name=ca
# 2020/09/09 19:16:50 [DEBUG] Starting checker name=server
# DEBU[0000] Initializing API endpoints                    subsystem_name=endpoints
# INFO[0000] Starting TCP server                           address="127.0.0.1:8081" subsystem_name=endpoints
# INFO[0000] Starting UDS server                           address=/tmp/spire-registration.sock subsystem_name=endpoints
```

By starting the server, we just started the identity service.
But the trust domain does not include any node at this point.
To change that, to expand our trust domain, we need to add one or more agent.
In this particular demo, we will add one agent that will run in the same container.

### Now let's start the identity agent

The purpose of the identity agent is to profile workloads and if recognized to give them their proper identity.
The agent is stateless, if ever restarted, the required information would be pulled from the identity service, where the state is saved.

But before an identity agent can join the trust domain, it needs to be authenticated or attested by the service.
The identity server has been configured to attest agents based on one-time token.
The agent also needs to be configured to support that method.

Before we start the agent, let's quickly look at its configuration

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

cat ./etc/agent/agent.conf
# agent {
#     data_dir = "./.data"
#     log_level = "DEBUG"
#     server_address = "127.0.0.1"    <== Where to find the identity server
#     server_port = "8081"
#     socket_path ="/tmp/agent.sock"
#     trust_bundle_path = "./etc/agent/dummy_root_ca.crt"
#     trust_domain = "paasteurizers.iam"    <== Trust domain the agent is part of
# }
# 
# plugins {
#     NodeAttestor "join_token" {     <== The agent is in agreement with the IAM service
#         plugin_data {               ... It is expected to be authenticated using a one-time token
#         }
#     }
#     KeyManager "disk" {
#         plugin_data {
#             directory = "./.data"
#         }
#     }
#     WorkloadAttestor "k8s" {        <== The agent is configured to identify workloads on Kubernetes
#         plugin_data {                   This plugin is not required for the demo, but we just want to show it already exists
#             kubelet_read_only_port = "10255"
#         }
#     }
#     WorkloadAttestor "docker" {     <== Another agent plugin. Workload running in (regular) docker can be attested as well
#         plugin_data {                   We won't be using this workload attestation method either in this demo.
#         }                               It is just for show!
#     }
#     WorkloadAttestor "unix" {       <== A third agent plugin, which we will use to get a certificate or JWT
#         plugin_data {                   Communication between the agent and the workload is done using a unix socket
#         }
#     }
# }
```

Now that we have looked at the agent configuration, let's start it and go through the attestation process.
We mush first get a one-time token and use that token to have the identity service attest the agent.

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

./bin/spire-server token generate -spiffeID spiffe://paasteurizers.iam/agent1
# Token: 5a576d55-c592-45ea-804e-bf5ed8178cc2
```

Now let's start the agent process, feed it the above token, so it admitted in the trust domain with the Id of spiffe://paasteurizers.iam/agent1
For the purpose of the demo, we will start the process in the background.

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

./bin/spire-agent run -config ./etc/agent/agent.conf -joinToken 5a576d55-c592-45ea-804e-bf5ed8178cc2 &
[2] 54
root@4de1a3cc2473:~/spire# WARN[0000] Current umask 0022 is too permissive; setting umask 0027.
# INFO[0000] Starting agent with data directory: "./.data"
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=join_token plugin_services="[]" plugin_type=NodeAttestor subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=disk plugin_services="[]" plugin_type=KeyManager subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=k8s plugin_services="[]" plugin_type=WorkloadAttestor subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=unix plugin_services="[]" plugin_type=WorkloadAttestor subsystem_name=catalog
# INFO[0000] Plugin loaded.                                built-in_plugin=true plugin_name=docker plugin_services="[]" plugin_type=WorkloadAttestor subsystem_name=catalog
# DEBU[0000] No pre-existing agent SVID found. Will perform node attestation  path=.data/agent_svid.der subsystem_name=attestor
# DEBU[0391] Signing CSR for Agent SVID                    agent_id="spiffe://paasteurizers.iam/spire/agent/join_token/7ff1d539-ea33-4725-a15f-eac1aa4a3e32" attestor=join_token method=node_api spiffe_id="spiffe://paasteurizers.iam/spire/agent/join_token/7ff1d539-ea33-4725-a15f-eac1aa4a3e32" subsystem_name=node_api
# DEBU[0391] Signed X509 SVID                              expiration="2020-09-09T20:23:21Z" spiffe_id="spiffe://paasteurizers.iam/spire/agent/join_token/7ff1d539-ea33-4725-a15f-eac1aa4a3e32" subsystem_name=ca
# DEBU[0391] could not find node resolver                  attestor=join_token subsystem_name=node_api
# INFO[0391] Node attestation request completed            address="127.0.0.1:55476" attestor=join_token method=node_api spiffe_id="spiffe://paasteurizers.iam/spire/agent/join_token/7ff1d539-ea33-4725-a15f-eac1aa4a3e32" subsystem_name=node_api
# DEBU[0000] Entry created                                 entry=0a03ce13-a007-482f-8a00-c985b41bb420 selectors_added=1 spiffe_id="spiffe://paasteurizers.iam/agent1" subsystem_name=cache_manager
# DEBU[0000] Updating SVIDs in cache                       expiring_svids=0 subsystem_name=manager
# INFO[0000] Renewing X509-SVID                            spiffe_id="spiffe://paasteurizers.iam/agent1" subsystem_name=manager
# DEBU[0391] Signing SVID                                  address="127.0.0.1:55478" caller_id="spiffe://paasteurizers.iam/spire/agent/join_token/7ff1d539-ea33-4725-a15f-eac1aa4a3e32" spiffe_id="spiffe://paasteurizers.iam/agent1" subsystem_name=node_api
# DEBU[0391] Signed X509 SVID                              expiration="2020-09-09T20:23:21Z" spiffe_id="spiffe://paasteurizers.iam/agent1" subsystem_name=ca
# DEBU[0000] Entry updated                                 entry=0a03ce13-a007-482f-8a00-c985b41bb420 spiffe_id="spiffe://paasteurizers.iam/agent1" subsystem_name=cache_manager svid_updated=true
# 2020/09/09 19:23:21 [DEBUG] Starting checker name=agent
# INFO[0000] Starting workload API                         subsystem_name=endpoints
```

## Workload API

At this point the identity service is available for any workload that can query the agent.
In this demo, our workload will be a Unix process.
Note that workloads can be of many different types.

Before the workload can get an identity, we need first to create a workload profile. 
As we mentioned earlier, the agent needs to attest workloads before giving them identities.
This attestation is done through 'fingerprinting' or profiling.

For the purpose of the demo, our service will give an identity to any process that is running on the same host as our agent 'spiffe://paasteurizers.iam/agent1' with the Unix user-id 1000.
In practice, the profiling could be even more specific. For example, we could profile based on the path or the sha256 of the process's binary. But let's keep it simple for this demo!

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

./bin/spire-server entry create -parentID spiffe://paasteurizers.iam/agent1 -spiffeID spiffe://paasteurizers.iam/workload -selector unix:uid:1000
# Entry ID      : c5216360-1546-4f65-9a52-b7424ccba5cd
# SPIFFE ID     : spiffe://paasteurizers.iam/workload
# Parent ID     : spiffe://paasteurizers.iam/agent1
# TTL           : 3600
# Selector      : unix:uid:1000
```

Note that the above command is sent not to the agent, but to the server. 
If generic enough, the creation of the profiles could be done by administrators of the identity service. But profiles could also be automatically created through infrastructure web-hooks.
In any case, the server is responsible for managing and maintaining the state of the identity service.

At this time, the identity exists, but it is not being used by any workload.
Let's change that!

Based on the above profiling, we need to run our workload as the user-id 1000.

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

useradd -u 1000 workload
su -c "./bin/spire-agent api fetch x509 " workload 
# SPIFFE ID:		spiffe://paasteurizers.iam/workload
# SVID Valid After:	2020-09-09 19:24:40 +0000 UTC
# SVID Valid Until:	2020-09-09 20:24:50 +0000 UTC
# Intermediate #1 Valid After:	2020-09-09 19:16:40 +0000 UTC
# Intermediate #1 Valid Until:	2020-09-10 19:16:50 +0000 UTC
# CA #1 Valid After:	2018-05-13 19:33:47 +0000 UTC
# CA #1 Valid Until:	2023-05-12 19:33:47 +0000 UTC
```

For security reasons, the above command stores the generated secrets (SVID, bundle, and private key) in memory.
If you want to see the generated certificate (SVID), or even the bundle and private key,  use the following command instead

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

su -c "./bin/spire-agent api fetch x509 --write ./tmp" workload
# Writing SVID #0 to file tmp/svid.0.pem.
# Writing key #0 to file tmp/svid.0.key.
# Writing bundle #0 to file tmp/bundle.0.pem.

ls ./tmp
# bundle.0.pem  svid.0.key  svid.0.pem
```

Now let's introspect the content of the SVID certificate

```bash
# COMMANDS ARE EXECUTED IN THE CONTAINER

openssl x509 -in ./tmp/svid.0.pem -text -noout
# Certificate:
#     Data:
#         Version: 3 (0x2)
#         Serial Number:
#             1b:e1:75:3a:57:c7:3a:aa:b1:e8:ef:f2:37:3b:01:6c
#     Signature Algorithm: ecdsa-with-SHA384
#         Issuer: C=US, O=SPIFFE
#         Validity
#             Not Before: Sep  9 19:24:40 2020 GMT              <== TTL of certificate is 1h (as configured)
#             Not After : Sep  9 20:24:50 2020 GMT
#         Subject: C=US, O=SPIRE
#         Subject Public Key Info:
#             Public Key Algorithm: id-ecPublicKey
#                 Public-Key: (256 bit)
#                 pub:
#                     04:a9:23:e2:a0:dc:25:25:63:9b:9f:ea:6a:38:9d:
#                     3f:5c:3c:96:45:76:de:d4:c9:3c:b8:45:f0:cc:3c:
#                     70:de:3e:8d:d5:a0:ef:d2:7c:7f:c3:db:62:10:8f:
#                     da:1e:7c:7e:e7:1d:68:09:1d:54:7e:9d:2a:4f:1d:
#                     29:a8:77:53:65
#                 ASN1 OID: prime256v1
#                 NIST CURVE: P-256
#         X509v3 extensions:
#             X509v3 Key Usage: critical
#                 Digital Signature, Key Encipherment, Key Agreement
#             X509v3 Extended Key Usage:
#                 TLS Web Server Authentication, TLS Web Client Authentication
#             X509v3 Basic Constraints: critical
#                 CA:FALSE
#             X509v3 Subject Key Identifier:
#                 18:DE:5F:EA:2B:AC:E3:E8:07:DA:7D:02:2E:A3:30:A9:AC:E9:14:A0
#             X509v3 Authority Key Identifier:
#                 keyid:C5:68:B9:FC:47:2C:76:9A:FF:F2:0C:F4:7D:8C:57:E1:A4:B0:79:A4
# 
#             X509v3 Subject Alternative Name:
#                 URI:spiffe://paasteurizers.iam/workload        <== SPIFFE ID of the workload
#     Signature Algorithm: ecdsa-with-SHA384
#          30:66:02:31:00:8b:08:a2:5c:0e:05:e3:fc:07:19:09:13:4f:
#          06:c7:1e:35:06:d3:af:9e:ae:cb:d9:86:e4:7b:b6:a8:e5:34:
#          3b:8d:1c:6f:1d:c8:c9:68:1c:e2:01:dc:57:6a:26:1a:a1:02:
#          31:00:cb:c2:1d:e5:37:c9:52:c6:9c:b9:7c:43:0e:9a:4e:3f:
#          f6:b7:23:24:fb:8a:9b:e3:8f:1b:40:8c:3a:13:a5:a8:11:cd:
```

Alternatively (or both), instead of a certificate, we could fetch a JWT token.

Note that JWTs and certificates can be used together or independently.
The JWT is often passed in HTTP headers and can be introspected at the application layer by let's say an API gateway such as Gloo Enterprise used by EAG.
While a certificate is validated at the time TCP connections are established. Therefore certificates are validated at the transport layer.

In any case, let's look at how to generate a JWT for a workload with the same profile.

```
# COMMANDS ARE EXECUTED IN THE CONTAINER

su -c "./bin/spire-agent api fetch jwt --audience Mobile" workload 
# token(spiffe://paasteurizers.iam/workload):
# 	eyJhbGciOiJFUzI1NiIsImtpZCI6InJRWXNsek13TDNYZXRMaWViZFBVdnNWWWFQTGw1ZW1iIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiTW9iaWxlIl0sImV4cCI6MTU5OTY4MTU0NiwiaWF0IjoxNTk5NjgxMjQ2LCJzdWIiOiJzcGlmZmU6Ly9wYWFzdGV1cml6ZXJzLmlhbS93b3JrbG9hZCJ9.mywENuNDA0pX7S59SnT3u2GpQagMLK_xuLwk-FgiozgnqRNYyvw-1CtfMmo44bhiNHIb9DXCBZcylRqag8REcg
# bundle(spiffe://paasteurizers.iam):
# 	{
#     "keys": [
#         {
#             "use": "jwt-svid",
#             "kty": "EC",
#             "kid": "rQYslzMwL3XetLiebdPUvsVYaPLl5emb",
#             "crv": "P-256",
#             "x": "Pi7j0NSemOfo6fW2jtAyU7DGyM7lmWUIMg9MdfV_Dh8",
#             "y": "ENeqzNqB0Kvf3GoEgrx2ubihwpxyKZMHYlXepfQquG0"
#         }
#     ]
# }
```

If we take the JWT generated above and decode it, we see

![jwt_io_tokenclaim](./.images/640/jwt_io_token_claim.png)

## Conclusion

In this demo, we showed

1. How to bootstrap the identity service, including
  * What is the demo environment and how it related to the IAM service architecture
  * How to bring up our demo environment using one of our container images
  * How to configure and start an identity server at the core of the IAM service
  * How to configure, attest, and start an identity agent to expend the trust domain

2. How a workload should interact with the IAM service to get an identity, including
  * How workload profiles are created and where they are stored
  * How to fetch an x509 certificate
  * How to fetch a JWT token
  * When a JWT should be used in place of a certificate
  * When both JWT and certificate can be used to assert an identity
  
Enjoy! 
