# webauth ssh-cert
Demo/Design for webauth using  for ssh certs using the ssh agent.

The motivation is on having SSO for CLI utilities without the need of generating identity/authentication tokens that can be reused by misbehaving servers. The other goal is to reduce the number of cli operations needed by clients. 

Right now it is a work in progress and no implications of its security are given.


The VO of the procol is as Follows:

![foo](docs/ssh-cert-challenge-sequesnce-v0.png)

Objectives:
1. Avoid use of password
2. Use of an already contained ephemeral credential
3. Prevention of Replay attacks
4. When using certificates no need to for external dependencies for checking auth (use the sshCA as trust anchor)
5. Prevention of revealing of secrets from either the server or the client.

### FAQ:
#### Why not SSL certificates?
Many server services are found behind TLS terminating load balancers.
#### Have you looked auth webauth protocol?
Yes the handshake is very inspired by that prococol. However one of the issues we wanted to avoid is the requirement of establishing long term keys between the client and each of the servers.
