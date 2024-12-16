### UndergroundBB

UndergroundBB is a place where people can communicate with each other and know their conversations are safe. All post titles and bodies are fully encrypted such that it requires one of the group's user's password, which aren't stored, even in hash form, on the server end. New users can only be added to a group by users already in the group with a role of Ambassador or Admin, thus providing a chain of trust. The weakest link in the chain is user passwords, so it is recommended to use strong passwords.

## Setup the development environment

1. Clone the repo: `git clone git@github.com:pwntato/undergroundbb.git`
1. Change into the project directory: `cd undergroundbb`
1. Create `.env` file
   1. Copy the sample file: `cp .env.sample .env`
   1. Fill out the missing values in`.env`, anything alphanumeric should be fine for development, but choose strong secrets for production deploys
1. Install the backend modules
   1. Go to the backend folder: `cd backend`
   1. Install the modules: `npm install`
1. Install the frontend
   1. Go to the frontend folder: `cd ../frontend`
   1. Install the modules: `npm install`
1. Return to root: `cd ..`
1. Clean out any previous installs: `docker-compose down -v`
1. Create the docker containers: `docker-compose build --no-cache`
1. Start the docker containers: `docker-compose up` (might need to run twice)
1. Make sure the smoke tests pass
   1. Go to the frontend folder: `cd frontend`
   1. Run the Playwright tests: `npm run test:e2e`
