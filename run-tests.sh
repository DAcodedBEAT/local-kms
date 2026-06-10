#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}================================${NC}"
echo -e "${YELLOW}Local KMS Functional Tests${NC}"
echo -e "${YELLOW}================================${NC}"
echo ""

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: docker-compose is not installed${NC}"
    exit 1
fi

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    exit 1
fi

# Run tests
echo -e "${YELLOW}Starting KMS and test containers...${NC}"
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit --remove-orphans

TEST_EXIT_CODE=$?

# Cleanup
echo ""
echo -e "${YELLOW}Cleaning up containers...${NC}"
docker-compose -f docker-compose.test.yml down --remove-orphans

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}All tests passed!${NC}"
    echo -e "${GREEN}================================${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}================================${NC}"
    echo -e "${RED}Tests failed!${NC}"
    echo -e "${RED}================================${NC}"
    exit 1
fi
