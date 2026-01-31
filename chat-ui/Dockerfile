# Build stage
FROM node:24-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
ARG VITE_API_BASE_URL
ARG VITE_AUTH_URL

ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_AUTH_URL=$VITE_AUTH_URL

RUN npm run build

# Runtime stage
FROM node:24-alpine

WORKDIR /app

COPY --from=build /app/dist ./dist
COPY --from=build /app/server.js ./
COPY --from=build /app/package*.json ./

RUN npm install --only=production

EXPOSE 8080

CMD ["node", "server.js"]
