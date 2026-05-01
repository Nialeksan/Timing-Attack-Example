FROM node:20-alpine

WORKDIR /app

# bcrypt requires native compilation toolchain on Alpine
RUN apk add --no-cache python3 make g++

# Copy manifests first to leverage Docker layer caching
COPY package*.json ./
RUN npm install

# Source is bind-mounted via docker-compose at runtime, but copy it here too so the image is runnable standalone
COPY src ./src

EXPOSE 3000

CMD [ "npm", "run", "dev" ]