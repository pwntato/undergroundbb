#! /usr/bin/env bash
echo "POSTGRES_USER=${POSTGRES_USER}"
npm run migrate
#npm start
npm run start:dev
