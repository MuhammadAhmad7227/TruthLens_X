FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build
FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/.next/standalone ./
USER node
EXPOSE 3000
CMD ["node","server.js"]
