# --- Build stage: install deps and compile TypeScript ---
FROM node:24-slim AS build

WORKDIR /app

# Dependency layer — only invalidated when package*.json change.
COPY package.json package-lock.json ./
RUN npm ci

# Project layer — compile src to dist.
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Prune to production dependencies only.
RUN npm prune --omit=dev

# --- Runtime stage: node + production node_modules + dist ---
FROM node:24-slim

WORKDIR /app

ENV NODE_ENV=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

EXPOSE 3000
USER node
CMD ["node", "dist/server.js"]
