FROM node:20-alpine

WORKDIR /app

# bycrpt requires native compilation toolchain on Alpine
RUN apk add --no-cache python3 make g++

# Copy manifests first to leverage Docker layer caching for nom install
COPY package*.json ./
RUN npm install --omit=dev

COPY seed.js ./

CMD ["node", "seed.js"]