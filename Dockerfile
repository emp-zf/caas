FROM node:22-alpine

ARG XRAY_VERSION=25.12.8
ENV XRAY_VERSION=${XRAY_VERSION}

RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN npm run build

EXPOSE 8080
CMD ["npm", "start"]
