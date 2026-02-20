FROM nginx:alpine

LABEL org.opencontainers.image.source=https://github.com/sauravbhattacharya001/gif-captcha
LABEL org.opencontainers.image.description="GIF CAPTCHA Case Study — static site"
LABEL org.opencontainers.image.licenses=MIT

# Remove default nginx content
RUN rm -rf /usr/share/nginx/html/*

# Add security headers configuration
COPY nginx-security.conf /etc/nginx/conf.d/security.conf

# Copy all static site files
COPY *.html /usr/share/nginx/html/

# Create non-root user and fix permissions
RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /usr/share/nginx/html \
    && chown -R appuser:appgroup /var/cache/nginx \
    && chown -R appuser:appgroup /var/log/nginx \
    && touch /var/run/nginx.pid \
    && chown appuser:appgroup /var/run/nginx.pid \
    && chmod -R 755 /etc/nginx/conf.d

USER appuser

# Nginx runs on port 80 by default
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost/ || exit 1
