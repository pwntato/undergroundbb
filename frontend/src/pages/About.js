import React from "react";
import { Container, Link, Typography, Box } from "@mui/material";

const About = () => {
  return (
    <Container maxWidth="md">
      <Box
        sx={{
          mt: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Typography component="h1" variant="h4" sx={{ mb: 4 }}>
          About UndergroundBB
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Mission
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          UndergroundBB is a place where people can communicate with each other
          and know their conversations are safe. <br />
          <br />
          All posts (and comments) are encrypted and users can only join groups
          if invited by already trusted group users. It is impossible to see
          group posts or comments using information stored server side. <br />
          <br />
          It is a place where people can share their thoughts and organize,
          whether that be activism or unionization.
          <br />
          <br />
          Finally, and maybe most importantly, UndergroundBB is not run for
          profit. It is a place for the people, by the people.
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          See the code
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          UndergroundBB is open source! Check it out:&nbsp;
          <a
            href="https://github.com/pwntato/undergroundbb"
            target="_blank"
            rel="noopener noreferrer"
          >
            UndergroundBB
          </a>
          . You can even run your own instance so no one can access the database
          except you!
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          How it works
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          <h2>Building Trust Through Invitations</h2>
          <ul>
            <li>
              <strong>Creating Groups:</strong> Anyone can start a group and
              becomes the Admin, the top role in the group. Admins can invite
              others, adjust roles, and manage group settings.
            </li>
            <li>
              <strong>Joining a Group:</strong> New users join as Members after
              being invited by an Admin or a trusted user with an Ambassador
              role. Members can view and post content within the group.
            </li>
            <li>
              <strong>Ambassadors:</strong> Admins can promote trusted Members
              to Ambassadors, who can then invite new Members. Unlike Admins,
              Ambassadors cannot change group settings or manage roles, but they
              play a key role in growing the group by extending invitations.
              This creates a "chain of trust," where only trusted users can
              bring others into the group.
            </li>
          </ul>

          <h2>Ensuring Security with Encryption</h2>
          <p>
            UndergroundBB uses advanced technology to keep your data safe,
            including your personal account details, group messages, and shared
            content:
          </p>
          <ul>
            <li>
              Your account and private information are protected with strong
              encryption, so only you can access them.
            </li>
            <li>
              Group content, like posts and comments, is locked with a secure
              key that only group members can use.
            </li>
            <li>
              Even if someone tries to break in, the layers of security make it
              nearly impossible for them to access your data.
            </li>
          </ul>

          <h2>Keeping Posts and Comments Secure</h2>
          <ul>
            <li>
              Each time a user interacts with the group, their private key is
              unlocked briefly and securely using a session token. This process
              ensures the user can access encrypted group content without
              compromising security. This key is used to access the group’s
              encrypted content, like posts and comments.
            </li>
            <li>
              All group content is encrypted using the group key, so only
              members of the group can view or share it.
            </li>
          </ul>

          <h2>Why It Matters</h2>
          <p>This layered security ensures that:</p>
          <ul>
            <li>Only trusted users can join groups and access content.</li>
            <li>
              Your private information stays private, even if someone else gets
              access to the servers, because all sensitive data is encrypted and
              can only be unlocked with your unique keys.
            </li>
            <li>
              Group content is protected from outsiders, providing a safe and
              secure environment for sharing.
            </li>
          </ul>
        </Typography>
      </Box>

      <Box>
        <Typography component="p">
          <Link
            href="https://github.com/pwntato/undergroundbb"
            target="_blank"
            rel="noopener noreferrer"
          >
            UndergroundBB
          </Link>
          {" by "}
          <Link
            href="https://www.linkedin.com/in/jimmy-hendrix-11a9931/"
            target="_blank"
            rel="noopener noreferrer"
          >
            James Hendrix
          </Link>
          {" is licensed under "}
          <Link
            href="https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1"
            target="_blank"
            rel="noopener noreferrer"
          >
            Creative Commons Attribution-NonCommercial-ShareAlike 4.0
            International
            <Box component="span" sx={{ display: "inline-block", ml: 1 }}>
              <img
                src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1"
                alt=""
                style={{ height: 22, verticalAlign: "text-bottom" }}
              />
              <img
                src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1"
                alt=""
                style={{
                  height: 22,
                  marginLeft: 3,
                  verticalAlign: "text-bottom",
                }}
              />
              <img
                src="https://mirrors.creativecommons.org/presskit/icons/nc.svg?ref=chooser-v1"
                alt=""
                style={{
                  height: 22,
                  marginLeft: 3,
                  verticalAlign: "text-bottom",
                }}
              />
              <img
                src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1"
                alt=""
                style={{
                  height: 22,
                  marginLeft: 3,
                  verticalAlign: "text-bottom",
                }}
              />
            </Box>
          </Link>
        </Typography>
      </Box>
    </Container>
  );
};

export default About;
