FROM nginx:alpine

LABEL org.opencontainers.image.source=https://github.com/sauravbhattacharya001/gif-captcha
LABEL org.opencontainers.image.description="GIF CAPTCHA Case Study — static site"
LABEL org.opencontainers.image.licenses=MIT

# Remove default nginx content
RUN rm -rf /usr/share/nginx/html/*

# Copy the static site
COPY index.html /usr/share/nginx/html/

# Nginx runs on port 80 by default
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost/ || exit 1
