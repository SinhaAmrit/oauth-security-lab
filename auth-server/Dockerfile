FROM node:18-alpine

WORKDIR /app

COPY package.json .
RUN npm install --production

COPY src/ ./src/

# DB lives in /tmp (ephemeral — seeded fresh on each start, fine for a lab)
EXPOSE 3001

CMD ["node", "src/server.js"]
