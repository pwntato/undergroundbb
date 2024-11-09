FROM node:18

WORKDIR /app

COPY package*.json ./
RUN npm install
RUN npm audit fix --force

COPY . .

CMD ["./entrypoint.sh"]
