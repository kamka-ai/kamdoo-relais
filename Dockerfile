# Relais des notifications de Kamdoo : Node seul, sans dépendance.
FROM node:22-alpine
WORKDIR /app
# curl : le contrôle de santé de Coolify l'appelle dans le conteneur (sans lui, il passe sans rien vérifier).
RUN apk add --no-cache curl
COPY serveur.mjs .
USER node
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/sante || exit 1
CMD ["node", "serveur.mjs"]
