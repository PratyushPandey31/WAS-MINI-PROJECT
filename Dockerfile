# =====================================================================
# Dockerfile: Virtualization and Container Security best practices.
# Implements:
#   1. Minimal OS footprint using Alpine Linux (reduces attack surface)
#   2. Least privilege principle running as non-root user (node)
#   3. Proper caching of dependency layers
# =====================================================================

# Step 1: Use minimal base image containing Node.js environment
FROM node:18-alpine AS base

# Step 2: Set working directory inside container
WORKDIR /usr/src/app

# Step 3: Copy packages definitions first to utilize caching layer
COPY package*.json ./

# Step 4: Install production dependencies only (avoid devDependencies)
# npm ci is faster and guarantees reproducible builds
RUN npm ci --only=production

# Step 5: Copy application source files
COPY . .

# Step 6: Apply security permissions. 
# Give write access for SQLite database folder to the non-root 'node' user
RUN mkdir -p data && chown -R node:node /usr/src/app

# Step 7: Enforce non-root execution context (least privilege)
# Prevents container breakout vulnerabilities from gaining host root access
USER node

# Step 8: Expose server port (internal documentation for network mapping)
EXPOSE 3000

# Step 9: Start authentication service container
CMD ["node", "server/index.js"]
