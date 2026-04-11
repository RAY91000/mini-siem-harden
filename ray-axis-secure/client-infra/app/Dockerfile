FROM node:20-alpine

# Utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copier les dépendances en premier (cache Docker)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copier le code
COPY server.js .

# Permissions
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
