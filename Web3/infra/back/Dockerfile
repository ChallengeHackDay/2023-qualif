FROM node:16-alpine
WORKDIR /app
COPY package.json .
COPY package-lock.json .
RUN npm install
ENV HARDHAT_CONFIG ./dist/hardhat.config.js
COPY tsconfig.json .
COPY hardhat.config.ts .
COPY contracts contracts
COPY src src
RUN npm run build
EXPOSE 8080
CMD ["npm", "start"]