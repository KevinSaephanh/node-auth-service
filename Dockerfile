FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
COPY ./src /app/src

RUN npm install
COPY . .
EXPOSE 8000

CMD ["npm", "start"]