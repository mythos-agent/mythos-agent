FROM node:latest

ARG DATABASE_PASSWORD=mysecretpassword123

WORKDIR /app
ADD . .
RUN npm install

EXPOSE 22
EXPOSE 3000

ENV API_KEY=sk-prod-1234567890abcdef

CMD ["node", "server.js"]
