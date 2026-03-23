FROM nginx:alpine

LABEL org.opencontainers.image.source=https://github.com/sauravbhattacharya001/gif-captcha
LABEL org.opencontainers.image.description="GIF CAPTCHA Case Study — interactive demo & analysis site"
LABEL org.opencontainers.image.licenses=MIT

# Remove default nginx content
RUN rm -rf /usr/share/nginx/html/*

# Add security headers configuration
COPY nginx-security.conf /etc/nginx/conf.d/security.conf

# Reconfigure nginx to listen on 8080 (non-root can't bind <1024)
RUN sed -i 's/listen\s*80;/listen 8080;/g' /etc/nginx/conf.d/default.conf \
    && sed -i 's/listen\s*\[::\]:80;/listen [::]:8080;/g' /etc/nginx/conf.d/default.conf

# Copy all site assets (HTML pages, CSS, JS, and library modules)
COPY *.html /usr/share/nginx/html/
COPY shared.css shared.js /usr/share/nginx/html/
COPY src/ /usr/share/nginx/html/src/

# Create non-root user and fix permissions
RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /usr/share/nginx/html \
    && chown -R appuser:appgroup /var/cache/nginx \
    && chown -R appuser:appgroup /var/log/nginx \
    && touch /var/run/nginx.pid \
    && chown appuser:appgroup /var/run/nginx.pid \
    && chmod -R 755 /etc/nginx/conf.d

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost:8080/ || exit 1
