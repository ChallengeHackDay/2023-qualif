FROM nginx:alpine
WORKDIR /app
RUN apk add --update npm
COPY package.json .
COPY package-lock.json .
RUN npm install
COPY . .
RUN mv default.conf /etc/nginx/conf.d/default.conf
RUN npm run build
RUN cp -r /app/dist/* /usr/share/nginx/html
EXPOSE 80