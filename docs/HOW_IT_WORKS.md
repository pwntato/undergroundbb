# How it works

This is the plain-language version of how UndergroundBB keeps your messages private, and where that stops. It needs no background in cryptography. When you want the precise version, each section points to the matching part of [DESIGN.md](DESIGN.md) (how it is built) and [THREAT_MODEL.md](THREAT_MODEL.md) (what an attacker can and cannot do).

## The short version

- Everything you write in a group is **locked in your browser** before it is sent. The server stores locked data and never holds the key that opens it.
- Your **password never leaves your browser**, not even in a scrambled form.
- Each group has **one shared key**. Every member holds a copy, locked so that only they can open it.
- The server still knows **who is in which groups and on which days they post**. It cannot read what they said.
- Removing someone **stops them reading new messages**. It cannot make them forget old ones.
- Someone who **runs the server** could change the website's code to steal your password. That is true of every encrypted app that runs in a browser, and it is the biggest limit here.

## What the server can and cannot see

| The server can see | The server cannot see |
| --- | --- |
| Your username | Your password |
| That you are a member of a group, and your role in it | Your private keys, or the group's key |
| The names and descriptions of **public** groups | A **private** group's name and description |
| The day each post or comment was written, and who wrote it | The title and text of any post or comment |
| Your profile bio, if you write one (every signed-in user can read it) | |
| The day you last logged in | |
| Invites and direct-message requests still waiting, and who they are for | |
| Your notifications: who interacted with you, in which group, on what day | |
| That a given person reacted to a given post (not when) | Which emoji the reaction was |
| How many groups, members and posts there are, and how long each message is | The exact time of any message |
| That a post was deleted, and on what day | What a deleted post said |

This is the main list, not every detail: [What is not protected](THREAT_MODEL.md#what-is-not-protected) is the complete accounting.

A copy of the whole database therefore shows the social graph (who is in which groups, and who messages whom) and day-level activity, but no message content. Direct messages are groups of two, so who talks to whom is visible in the same way. See [What is not protected](THREAT_MODEL.md#what-is-not-protected).

## Your keys and your password

You have two key pairs. One **signs** things (it proves a message or a login came from you). The other **receives** group keys (it lets people send you a group's key privately).

```
   your password
        |
        |  slowed down on purpose (Argon2id), in your browser
        v
   an unlocking key  ----opens---->  [ your two private keys ]
                                        stored on the server,
                                        but locked
```

The server stores your private keys **locked** under a key made from your password. Without the password it holds nothing it can open. If you type the wrong password, unlocking simply fails, so there is no separate password check on the server.

### Logging in without sending your password

1. Your browser asks the server for a login challenge: a random number, and your locked keys.
2. Your browser unlocks the keys with your password and **signs** the number.
3. The server checks the signature against your public key. Each random number works once, so a captured login cannot be replayed.

The server learns only that someone holding your private key was there. This is also why there is **no device setup**: any browser can log in with your username and password, download the same locked keys, and unlock them. See [Login](DESIGN.md#login) and [Multi-device](DESIGN.md#multi-device).

### The recovery code

At signup you get a **recovery code**. It unlocks a second locked copy of your private keys, so you can get back in if you forget your password. Two things follow from that:

- **It is a second full password.** Anyone with the code can open your keys. Store it as carefully as the password.
- **There is no reset.** If you lose both the password and the code, nothing on the server can bring your account back. That is by design.

Changing your password, or recovering with the code, always gives you a **new** recovery code and cancels the old one, so a leaked code does not outlive the event that made you change things. See [Recovery](DESIGN.md#recovery) and [the threat model](THREAT_MODEL.md#the-recovery-code).

## Groups and the group key

Each group has one **group key**. It locks every post, comment and reaction, and for a private group it also locks the group's name and description.

```
                     group key
                         |
        +----------------+----------------+
        |                |                |
   locked for        locked for       locked for
     Alice              Bob             Carol
 (only Alice's     (only Bob's      (only Carol's
  key opens it)     key opens it)    key opens it)
```

Every member holds their own locked copy. The server holds only the locked copies, so it cannot open any of them.

Two more protections sit on top of the locking:

- **Posts and comments are signed.** Your browser signs what you write with your signing key. Other members' browsers check the signature, so one member cannot post as another, and the server cannot forge a message.
- **Each message is tied to its place.** A locked message is bound to the group, thread and slot it was written in. If someone with access to the database copied it into a different thread, it would fail to open instead of appearing in the wrong place.

Posts are plain text only. The app never treats a post as formatting or loads anything from it, and there are no attachments. See [The cryptographic core](DESIGN.md#the-cryptographic-core).

## Getting someone into a group: invites

An invite has to get the group key to the new person **without the server being able to slip in a key of its own**. If the server could do that, it could quietly become a member. So it works like this:

```
 Inviter                          Server                          New person
    |                                |                                 |
    |-- create invite -------------->|                                 |
    |   (signed by the inviter)      |                                 |
    |                                                                  |
    |== link, with a secret after the "#" (never sent to any server) =>|
    |                                |                                 |
    |                                |<-- accept: signs their own keys,|
    |                                |    proves they hold the link ---|
    |                                                                  |
    |   (later, next time the inviter logs in)                         |
    |<-- fetch the acceptance -------|                                 |
    |   check the proof, then lock the group key to the                |
    |   keys the new person signed                                     |
    |-- locked group key ----------->|----- delivered ---------------->|
```

What makes this safe:

- The new person **signs their own keys**, and proves they hold the actual link by using the secret after the `#`. Browsers never send that part of a link to a server, so the server cannot fake the proof.
- The inviter's browser only locks the group key to the keys the new person signed.
- The page shows the inviter's **fingerprint**, a long number that identifies their keys. Comparing it over a call you trust catches a swapped link.

The group key can only be handed over by the **inviter's** browser, so it arrives **the next time the inviter logs in**. That is why a new member sometimes waits. If the inviter changes their keys (see below) before that, the invite stops working and needs to be made again. See [Invites: the signed handshake](DESIGN.md#invites--the-signed-handshake).

## Trusting keys

The first time your browser sees someone's keys, it **remembers** them (this is called pinning, or trust on first use). It keeps that record signed with your own key, so a server cannot quietly edit it.

If a person's keys later change, your browser **stops and asks** instead of carrying on. A key change is rare, and the thing it protects is something you do all the time, so the app prefers friction to a warning you would click through. There are two honest reasons keys change: the person rotated them on purpose (after a lost laptop, say), or someone is interfering. To tell which, use **Check fingerprint** and compare the number with the person on a call you know is them. Do not send it in a message.

Because pins follow you between devices, a new device inherits what an old one verified instead of starting from nothing. See [Key pinning and verification](DESIGN.md#key-pinning-and-verification).

## Roles

| Role | Can invite | Can remove members and change roles |
| --- | --- | --- |
| Admin | Yes | Yes |
| Ambassador | Yes | No |
| Member | No | No |

Every role change is **signed by the admin who made it**, and your browser can walk the chain of signatures back to the person who created the group. A server cannot invent an admin, because it cannot produce the signature.

That protects against a **dishonest server**. It does not protect against a **dishonest member**: anyone holding the group key can write to the group, and an ambassador can invite anyone they like. Roles keep a group organised among people who already trust each other. They are not a wall. See [Roles and the chain of trust](DESIGN.md#roles-and-the-chain-of-trust) and [limitation 2](THREAT_MODEL.md#2-roles-are-not-a-cryptographic-boundary).

## Removing someone

A removed member **still has the group key they were given and everything they already read**. Nothing can take that back. What a group can do is stop them reading what comes next. A group picks one of two ways when it is created:

- **Rotating.** Removing a member makes a **new group key**, locked separately for everyone who remains. The removed person's old key opens only the past. These groups are capped (1,000 members by default, set by whoever runs the deployment) because every removal means re-locking the key for everyone.
- **Open.** Removal only changes who the server will serve. It does not make a new key, so a removed member who kept a copy of the data could still read later posts. In exchange there is no member cap. Public groups are always Open. A Rotating group can be converted to Open, once, and never back.

Making a new key takes a moment, and new posts use the old key until it finishes. If the browser doing the work stops partway, that window stays open until someone resumes it. Removal is a boundary that closes shortly after, not instantly.

Old keys are kept, each one locked inside the next newer key. That is why current members can still read history after a rotation, while a removed member, who holds nothing newer, cannot reach the new key. See [Revocation mode](DESIGN.md#revocation-mode), [Key generations](DESIGN.md#key-generations) and [limitation 3](THREAT_MODEL.md#3-removal-cannot-undo-access).

## Messages expire

Every group has an expiry, **30 days** by default. After that, posts, and the comments and reactions under them, are deleted. The server also stops serving an expired item right away, even if the database has not removed it yet.

Expiry is the most useful protection at any group size: a message that no longer exists cannot be read by someone who steals the database later, or by a member who was removed. A deployment may allow groups to turn it off. A group that does keeps everything for good, and gives up that protection. See [Message expiration](DESIGN.md#message-expiration).

## What this does not protect against

- **The person running the server can change the website's code.** The code that locks and unlocks your messages is delivered by the server. A dishonest or hacked operator could ship a version that sends them your password. Integrity checks make this harder to do quietly, but they cannot stop an operator who controls the site. If that is part of your threat model, you need an app installed from a binary you have checked yourself, and this is not that. See [limitation 1](THREAT_MODEL.md#1-a-malicious-operator-can-serve-malicious-javascript).
- **A stolen database shows who is in which groups.** Names, memberships and day-level activity are not hidden. Message content is.
- **Removal does not un-see.** See above.
- **A stolen device, or a weak or reused password, is still a stolen account.** The locked keys are only as strong as the password that locks them.
- **A lost password and recovery code mean a lost account.** Nobody can reset it.
- **Members can copy what they read.** The app cannot stop a screenshot or a paste.

The complete list is in the [threat model](THREAT_MODEL.md). It is worth reading before you trust this with anything serious.

## Where to go next

- To use the app, read the [user guide](USER_GUIDE.md).
- To run your own copy, read the [self-hosting guide](SELF_HOSTING.md).
- To see how it is built, read [DESIGN.md](DESIGN.md).
