import React from "react";
import { Container, Link, Typography, Box, List, ListItem, ListItemText } from "@mui/material";

const About = () => {
  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 4, mb: 4 }}>
        <Typography variant="h4" sx={{ mb: 4 }}>
          About UndergroundBB
        </Typography>
        
        <Typography variant="h5" sx={{ mb: 2 }}>
          Our Mission
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          UndergroundBB is a place where people can communicate with each other
          and know their conversations are safe.
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          All posts (and comments) are encrypted and users can only join groups
          if invited by already trusted group users. It is impossible to see
          group posts or comments using information stored server side.
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          It is a place where people can share their thoughts and organize,
          whether that be activism or unionization.
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Finally, and maybe most importantly, UndergroundBB is not run for
          profit. It is a place for the people, by the people.
        </Typography>

        <Typography variant="h5" sx={{ mb: 2 }}>
          See the code
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          UndergroundBB is open source! Check it out:&nbsp;
          <Link
            href="https://github.com/pwntato/undergroundbb"
            target="_blank"
            rel="noopener noreferrer"
          >
            UndergroundBB
          </Link>
          . You can even run your own instance so no one can access the database
          except you!
        </Typography>

        <Typography variant="h5" sx={{ mb: 2 }}>
          How it works
        </Typography>

        <Typography variant="h6" sx={{ mb: 2 }}>
          Building Trust Through Invitations
        </Typography>
        <List sx={{ width: '100%', mb: 4, pl: 0 }}>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              primary={<Typography variant="subtitle1">Creating Groups</Typography>}
              secondary={<Typography variant="body1">Anyone can start a group and becomes the Admin, the top role in the group. Admins can invite others, adjust roles, and manage group settings.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              primary={<Typography variant="subtitle1">Joining a Group</Typography>}
              secondary={<Typography variant="body1">New users join as Members after being invited by an Admin or a trusted user with an Ambassador role. Members can view and post content within the group.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              primary={<Typography variant="subtitle1">Ambassadors</Typography>}
              secondary={<Typography variant="body1">Admins can promote trusted Members to Ambassadors, who can then invite new Members. Unlike Admins, Ambassadors cannot change group settings or manage roles, but they play a key role in growing the group by extending invitations. This creates a 'chain of trust,' where only trusted users can bring others into the group.</Typography>}
            />
          </ListItem>
        </List>

        <Typography variant="h6" sx={{ mb: 2 }}>
          Ensuring Security with Encryption
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          UndergroundBB uses advanced technology to keep your data safe,
          including your personal account details, group messages, and shared
          content:
        </Typography>
        <List sx={{ width: '100%', mb: 4, pl: 0 }}>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Your account and private information are protected with strong encryption, so only you can access them.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Group content, like posts and comments, is locked with a secure key that only group members can use.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Even if someone tries to break in, the layers of security make it nearly impossible for them to access your data.</Typography>}
            />
          </ListItem>
        </List>

        <Typography variant="h6" sx={{ mb: 2 }}>
          Keeping Posts and Comments Secure
        </Typography>
        <List sx={{ width: '100%', mb: 4, pl: 0 }}>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Each time a user interacts with the group, their private key is unlocked briefly and securely using their password or a session token. This process ensures the user can access encrypted group content without compromising security. This key is used to access the group's encrypted content, like posts and comments.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">All group content is encrypted using the group key, so only members of the group can view or share it.</Typography>}
            />
          </ListItem>
        </List>

        <Typography variant="h6" sx={{ mb: 2 }}>
          Why It Matters
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          This layered security ensures that:
        </Typography>
        <List sx={{ width: '100%', mb: 4, pl: 0 }}>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Only trusted users can join groups and access content.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Your private information stays private, even if someone else gets access to the servers, because all sensitive data is encrypted and can only be unlocked with your unique keys.</Typography>}
            />
          </ListItem>
          <ListItem sx={{ pl: 0 }}>
            <ListItemText
              secondary={<Typography variant="body1">Group content is protected from outsiders, providing a safe and secure environment for sharing.</Typography>}
            />
          </ListItem>
        </List>
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
