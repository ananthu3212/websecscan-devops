FROM node:19-alpine AS build

WORKDIR /app

# Copy package.json and install dependencies
COPY package.json ./
RUN npm install

# Copy source code and build the app
COPY . ./

# 🔥 REMOVE HTTPS=true - Build with HTTP only
RUN npm run build

# Stage 2: Serve the application using a lightweight Nginx image
FROM nginx:alpine

# Copy the built files from the build stage to the Nginx public directory
COPY --from=build /app/dist /usr/share/nginx/html

# Copy the nginx configuration file
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 for the web server
EXPOSE 80

# Nginx serves the files by default, so no CMD is needed
CMD ["nginx", "-g", "daemon off;"]