#! /usr/bin/env bash
echo "POSTGRES_USER=${POSTGRES_USER}"
echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
npm run migrate
#npm start
npm run start:dev
