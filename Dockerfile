FROM node:22-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production=false
COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

FROM node:22-slim

LABEL org.opencontainers.image.title="sphinx-agent"
LABEL org.opencontainers.image.description="AI security agent — open-source Mythos for everyone"
LABEL org.opencontainers.image.source="https://github.com/sphinx-agent/sphinx-agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install optional security tools
RUN pip3 install --break-system-packages semgrep checkov 2>/dev/null || true
RUN npm install -g gitleaks 2>/dev/null || true

WORKDIR /app
COPY --from=builder /app/dist dist/
COPY --from=builder /app/node_modules node_modules/
COPY package.json ./

# Create non-root user
RUN groupadd -r sphinx && useradd -r -g sphinx sphinx
USER sphinx

ENV NODE_ENV=production

EXPOSE 4041

ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["serve", "--host", "0.0.0.0", "--port", "4041"]
