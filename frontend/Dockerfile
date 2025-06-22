FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --silent

# Copy source code
COPY . .

# Create build directory
RUN mkdir -p build

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]